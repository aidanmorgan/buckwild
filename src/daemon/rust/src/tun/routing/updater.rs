use anyhow::{Context, Result};
use buckwild_common::types::time::Timestamp;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, mpsc};
use tokio::time::interval;
use tracing::{debug, error, info, instrument, warn};

use super::rules::{RoutingRule, RoutingRules};

/// Routing update event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RoutingUpdateEvent {
    AddRule { rule_id: String, rule: RoutingRule },
    RemoveRule { rule_id: String },
    UpdateRule { rule_id: String, rule: RoutingRule },
    BatchUpdate { rules: HashMap<String, RoutingRule> },
    ClearAll,
}

/// Update operation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateResult {
    pub success: bool,
    pub applied_rules: Vec<String>,
    pub failed_rules: Vec<String>,
    pub rollback_performed: bool,
    pub error_message: Option<String>,
}

/// Update statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct UpdateStatistics {
    pub total_updates: u64,
    pub successful_updates: u64,
    pub failed_updates: u64,
    pub rollbacks_performed: u64,
    pub average_update_time_ms: f64,
    pub last_update_time: Option<Timestamp>,
}

/// Real-time routing table updater
pub struct RoutingUpdater {
    routing_rules: Arc<RoutingRules>,
    update_queue: mpsc::UnboundedSender<RoutingUpdateEvent>,
    update_receiver: Option<mpsc::UnboundedReceiver<RoutingUpdateEvent>>,
    backup_rules: Arc<RwLock<HashMap<String, RoutingRule>>>,
    statistics: Arc<RwLock<UpdateStatistics>>,
    batch_timeout: Duration,
    max_batch_size: usize,
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl RoutingUpdater {
    /// Create a new routing updater
    #[instrument]
    pub fn new(
        routing_rules: Arc<RoutingRules>,
        batch_timeout: Duration,
        max_batch_size: usize,
    ) -> Self {
        info!(
            "Creating routing updater with batch timeout: {:?}, max batch size: {}",
            batch_timeout, max_batch_size
        );

        let (update_sender, update_receiver) = mpsc::unbounded_channel();

        RoutingUpdater {
            routing_rules,
            update_queue: update_sender,
            update_receiver: Some(update_receiver),
            backup_rules: Arc::new(RwLock::new(HashMap::new())),
            statistics: Arc::new(RwLock::new(UpdateStatistics::default())),
            batch_timeout,
            max_batch_size,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Start the routing updater
    #[instrument(skip(self))]
    pub async fn start(&mut self) -> Result<()> {
        if self.running.load(std::sync::atomic::Ordering::Acquire) {
            warn!("Routing updater already running");
            return Ok(());
        }

        info!("Starting routing updater");
        self.running
            .store(true, std::sync::atomic::Ordering::Release);

        // Take the receiver
        let mut update_receiver = self
            .update_receiver
            .take()
            .context("Update receiver already taken")?;

        // Start update processing task
        let routing_rules = Arc::clone(&self.routing_rules);
        let backup_rules = Arc::clone(&self.backup_rules);
        let statistics = Arc::clone(&self.statistics);
        let running = Arc::clone(&self.running);
        let batch_timeout = self.batch_timeout;
        let max_batch_size = self.max_batch_size;

        tokio::spawn(async move {
            let mut pending_updates = Vec::new();
            let mut batch_timer = interval(batch_timeout);
            batch_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            while running.load(std::sync::atomic::Ordering::Acquire) {
                tokio::select! {
                    // Receive new update
                    update = update_receiver.recv() => {
                        match update {
                            Some(event) => {
                                pending_updates.push(event);

                                // Process immediately if batch is full
                                if pending_updates.len() >= max_batch_size {
                                    Self::process_update_batch(
                                        &routing_rules,
                                        &backup_rules,
                                        &statistics,
                                        std::mem::take(&mut pending_updates)
                                    ).await;
                                }
                            }
                            None => {
                                debug!("Update channel closed");
                                break;
                            }
                        }
                    }

                    // Batch timeout
                    _ = batch_timer.tick() => {
                        if !pending_updates.is_empty() {
                            Self::process_update_batch(
                                &routing_rules,
                                &backup_rules,
                                &statistics,
                                std::mem::take(&mut pending_updates)
                            ).await;
                        }
                    }
                }
            }

            // Process remaining updates
            if !pending_updates.is_empty() {
                Self::process_update_batch(
                    &routing_rules,
                    &backup_rules,
                    &statistics,
                    pending_updates,
                )
                .await;
            }

            info!("Routing updater task terminated");
        });

        Ok(())
    }

    /// Stop the routing updater
    #[instrument(skip(self))]
    pub async fn stop(&self) {
        info!("Stopping routing updater");
        self.running
            .store(false, std::sync::atomic::Ordering::Release);

        // Give processing task time to finish
        tokio::time::sleep(Duration::from_millis(100)).await;

        info!("Routing updater stopped");
    }

    /// Queue routing update
    #[instrument(skip(self))]
    pub async fn queue_update(&self, event: RoutingUpdateEvent) -> Result<()> {
        debug!("Queuing routing update: {:?}", event);

        self.update_queue
            .send(event)
            .map_err(|e| anyhow::anyhow!("Failed to queue update: {}", e))?;

        Ok(())
    }

    /// Add routing rule
    #[instrument(skip(self))]
    pub async fn add_rule(&self, rule_id: String, rule: RoutingRule) -> Result<()> {
        self.queue_update(RoutingUpdateEvent::AddRule { rule_id, rule })
            .await
    }

    /// Remove routing rule
    #[instrument(skip(self))]
    pub async fn remove_rule(&self, rule_id: String) -> Result<()> {
        self.queue_update(RoutingUpdateEvent::RemoveRule { rule_id })
            .await
    }

    /// Update routing rule
    #[instrument(skip(self))]
    pub async fn update_rule(&self, rule_id: String, rule: RoutingRule) -> Result<()> {
        self.queue_update(RoutingUpdateEvent::UpdateRule { rule_id, rule })
            .await
    }

    /// Batch update routing rules
    #[instrument(skip(self, rules))]
    pub async fn batch_update(&self, rules: HashMap<String, RoutingRule>) -> Result<()> {
        self.queue_update(RoutingUpdateEvent::BatchUpdate { rules })
            .await
    }

    /// Clear all routing rules
    #[instrument(skip(self))]
    pub async fn clear_all(&self) -> Result<()> {
        self.queue_update(RoutingUpdateEvent::ClearAll).await
    }

    /// Get update statistics
    pub async fn get_statistics(&self) -> UpdateStatistics {
        self.statistics.read().await.clone()
    }

    /// Create backup of current rules
    async fn create_backup(
        routing_rules: &RoutingRules,
        backup_rules: &Arc<RwLock<HashMap<String, RoutingRule>>>,
    ) -> Result<()> {
        let current_rules = routing_rules.get_rules().await;
        *backup_rules.write().await = current_rules;
        debug!(
            "Created backup of {} routing rules",
            backup_rules.read().await.len()
        );
        Ok(())
    }

    /// Restore from backup
    async fn restore_from_backup(
        routing_rules: &RoutingRules,
        backup_rules: &Arc<RwLock<HashMap<String, RoutingRule>>>,
    ) -> Result<()> {
        info!("Restoring routing rules from backup");

        // Clear current rules
        routing_rules.clear_all_rules().await?;

        // Restore backup rules
        let backup = backup_rules.read().await.clone();
        let applied_rules = routing_rules.apply_rule_batch(backup).await?;

        info!("Restored {} routing rules from backup", applied_rules.len());
        Ok(())
    }

    /// Process batch of updates
    async fn process_update_batch(
        routing_rules: &Arc<RoutingRules>,
        backup_rules: &Arc<RwLock<HashMap<String, RoutingRule>>>,
        statistics: &Arc<RwLock<UpdateStatistics>>,
        updates: Vec<RoutingUpdateEvent>,
    ) {
        if updates.is_empty() {
            return;
        }

        let start_time = Timestamp::now();
        debug!("Processing batch of {} updates", updates.len());

        // Create backup before applying changes
        if let Err(e) = Self::create_backup(routing_rules, backup_rules).await {
            error!("Failed to create backup: {}", e);
            return;
        }

        let mut total_applied = 0;
        let mut total_failed = 0;
        let mut rollback_performed = false;

        for update in updates {
            let result = Self::process_single_update(routing_rules, &update).await;

            match result {
                Ok(update_result) => {
                    total_applied += update_result.applied_rules.len();
                    total_failed += update_result.failed_rules.len();

                    if !update_result.success && update_result.rollback_performed {
                        rollback_performed = true;
                        break; // Stop processing on rollback
                    }
                }
                Err(e) => {
                    error!("Failed to process update {:?}: {}", update, e);
                    total_failed += 1;

                    // Perform rollback on critical failure
                    if let Err(rollback_error) =
                        Self::restore_from_backup(routing_rules, backup_rules).await
                    {
                        error!(
                            "Failed to rollback after update failure: {}",
                            rollback_error
                        );
                    } else {
                        rollback_performed = true;
                    }
                    break;
                }
            }
        }

        // Update statistics
        let processing_time = Duration::from_nanos(
            Timestamp::now()
                .as_nanos()
                .saturating_sub(start_time.as_nanos()),
        );
        let mut stats = statistics.write().await;
        stats.total_updates += 1;

        if total_failed == 0 && !rollback_performed {
            stats.successful_updates += 1;
        } else {
            stats.failed_updates += 1;
        }

        if rollback_performed {
            stats.rollbacks_performed += 1;
        }

        // Update average processing time
        let total_time = stats.average_update_time_ms * (stats.total_updates - 1) as f64
            + processing_time.as_millis() as f64;
        stats.average_update_time_ms = total_time / stats.total_updates as f64;
        stats.last_update_time = Some(start_time);

        info!(
            "Processed update batch: {} applied, {} failed, rollback: {}, time: {:?}",
            total_applied, total_failed, rollback_performed, processing_time
        );
    }

    /// Process single update
    async fn process_single_update(
        routing_rules: &Arc<RoutingRules>,
        update: &RoutingUpdateEvent,
    ) -> Result<UpdateResult> {
        match update {
            RoutingUpdateEvent::AddRule { rule_id, rule } => {
                match routing_rules.add_rule(rule_id.clone(), rule.clone()).await {
                    Ok(()) => Ok(UpdateResult {
                        success: true,
                        applied_rules: vec![rule_id.clone()],
                        failed_rules: vec![],
                        rollback_performed: false,
                        error_message: None,
                    }),
                    Err(e) => Ok(UpdateResult {
                        success: false,
                        applied_rules: vec![],
                        failed_rules: vec![rule_id.clone()],
                        rollback_performed: false,
                        error_message: Some(e.to_string()),
                    }),
                }
            }

            RoutingUpdateEvent::RemoveRule { rule_id } => {
                match routing_rules.remove_rule(rule_id).await {
                    Ok(()) => Ok(UpdateResult {
                        success: true,
                        applied_rules: vec![rule_id.clone()],
                        failed_rules: vec![],
                        rollback_performed: false,
                        error_message: None,
                    }),
                    Err(e) => Ok(UpdateResult {
                        success: false,
                        applied_rules: vec![],
                        failed_rules: vec![rule_id.clone()],
                        rollback_performed: false,
                        error_message: Some(e.to_string()),
                    }),
                }
            }

            RoutingUpdateEvent::UpdateRule { rule_id, rule } => {
                match routing_rules
                    .update_rule(rule_id.clone(), rule.clone())
                    .await
                {
                    Ok(()) => Ok(UpdateResult {
                        success: true,
                        applied_rules: vec![rule_id.clone()],
                        failed_rules: vec![],
                        rollback_performed: false,
                        error_message: None,
                    }),
                    Err(e) => Ok(UpdateResult {
                        success: false,
                        applied_rules: vec![],
                        failed_rules: vec![rule_id.clone()],
                        rollback_performed: false,
                        error_message: Some(e.to_string()),
                    }),
                }
            }

            RoutingUpdateEvent::BatchUpdate { rules } => {
                match routing_rules.apply_rule_batch(rules.clone()).await {
                    Ok(applied_rules) => {
                        let failed_rules: Vec<String> = rules
                            .keys()
                            .filter(|k| !applied_rules.contains(k))
                            .cloned()
                            .collect();

                        Ok(UpdateResult {
                            success: failed_rules.is_empty(),
                            applied_rules,
                            failed_rules,
                            rollback_performed: false,
                            error_message: None,
                        })
                    }
                    Err(e) => Ok(UpdateResult {
                        success: false,
                        applied_rules: vec![],
                        failed_rules: rules.keys().cloned().collect(),
                        rollback_performed: false,
                        error_message: Some(e.to_string()),
                    }),
                }
            }

            RoutingUpdateEvent::ClearAll => match routing_rules.clear_all_rules().await {
                Ok(()) => Ok(UpdateResult {
                    success: true,
                    applied_rules: vec!["clear_all".to_string()],
                    failed_rules: vec![],
                    rollback_performed: false,
                    error_message: None,
                }),
                Err(e) => Ok(UpdateResult {
                    success: false,
                    applied_rules: vec![],
                    failed_rules: vec!["clear_all".to_string()],
                    rollback_performed: false,
                    error_message: Some(e.to_string()),
                }),
            },
        }
    }
}
