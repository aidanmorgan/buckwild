# Rust Development Standards (Buckwild)

These standards codify how we write Rust across this codebase. They emphasize
strong typing, layered error handling, idiomatic practices, and reliance on
well-known libraries over bespoke implementations.

## Guiding Principles

- **ALWAYS** use explicit, domain-specific types over primitives and aliases
- **ALWAYS** propagate failures with precise, layered error types - **NEVER** use stringly errors
- **ALWAYS** keep modules cohesive; each layer owns its error type and wraps lower layers
- **ALWAYS** prefer zero-cost abstractions and avoid unnecessary allocations or clones
- **ALWAYS** use proven crates for common concerns - **NEVER** reinvent infrastructure
- **ALWAYS** prefer adding a well‑maintained dependency over writing bespoke implementations - only hand‑roll code when no suitable crate exists, and document the rationale
- **ALWAYS** maintain a clean, warning-free build with consistent formatting

## Error Handling

- **NEVER** use string errors or `Box<dyn std::error::Error>` in library APIs
  - Library/public APIs **MUST** return concrete error types (enums/structs)
  - Top-level binaries **MAY** convert to a type-erased error solely at the process boundary for reporting/exit (e.g., `anyhow::Error` in `main`), but **NEVER** across internal layers
- **ALWAYS** use layered errors:
  - **ALWAYS** define error type for each layer capturing its failure modes using `thiserror` with clear variants
  - When a higher layer depends on a lower layer, **MUST** wrap the lower error (e.g., `#[from] lower::Error` or explicit mapping) and add context
  - **NEVER** expose lower-layer error details directly across layer boundaries
- **ALWAYS** add context and diagnostics:
  - **ALWAYS** add structured context at wrap sites (include identifiers like tenant, shard, path, offsets) - **ALWAYS** use `tracing` fields for context, **NEVER** use stringly concatenation
  - **ALWAYS** prefer `?` + `map_err`/`with_context` style over `unwrap`/`expect`
- **NO PANICS IN CORE SYSTEM CODE**:
  - **NEVER** use `panic!()`, `unwrap()`, `expect()`, `unreachable!()`, or any other construct that can panic in core system functionality (libraries, services, data processing, storage, networking).
  - Panics are ONLY acceptable at process boundaries (main functions, CLI argument parsing) for truly unrecoverable startup conditions.
  - **NEVER** use panics to signal recoverable errors or malformed input
  - FFI boundaries and async tasks **MUST NEVER** propagate panics
  - **ALWAYS** replace all `unwrap()` with proper error handling using `Result` types and `?` operator

**ALWAYS** use these recommended crates:
- **ALWAYS** use `thiserror` for typed error definitions and `#[from]` conversions
- **ONLY** use `miette` or `anyhow` in `bin` crates for final user-facing reporting
- `error-stack` acceptable for richer backtraces if justified - **ALWAYS** keep APIs typed

## Newtype Pattern (Domain Modeling)

Use newtypes to encode domain concepts and invariants.

- Wrap primitives in distinct types, e.g.:
  - `TenantId(String)`, `TenantStorageId([u8; 8] or String)`, `ShardId(u16)`,
    `PlacementEpoch(u64)`, `IngestNs(i64)`, `Bucket(u8)`, `Minute(u8)`.
- Provide smart constructors that validate invariants and return typed errors.
- Implement `Display`, `Serialize`/`Deserialize` (where needed), and `FromStr`.
- Avoid `type` aliases for domain concepts — they don’t prevent misuse.
- Derive `Copy`/`Clone`/`Eq`/`Hash` only when semantically valid.
- Use `#[repr(transparent)]` when ABI/layout is relevant.
- Prefer Prism newtypes: when a Prism-specific newtype exists (e.g.,
  `common::uuidx::Uuid7`, `common::types::Port`, `common::hlc::Hlc`), use it in
  public APIs and internal code instead of raw primitives or external types
  (e.g., avoid `uuid::Uuid` directly). Do not reintroduce ad-hoc aliases.


## API and Module Design

- Keep public interfaces minimal and strongly typed.
- Prefer iterators/streams over eager allocation where practical:
  - `impl Iterator<Item = T>` for sync; `impl Stream<Item = T>` for async.
- Accept `&[u8]`/`Bytes` rather than `Vec<u8>` where ownership isn’t needed.
- Return `Option` for absence and `Result` for failure; avoid `bool` flags.
- Use feature flags to contain optional dependencies and keep binaries lean.

## Idiomatic Rust Practices

- Idiomatic compliance:
  - Follow the Rust API Guidelines and the standard library’s conventions. Code
    must read and feel idiomatic: prefer iterator adapters over indexing loops,
    `Option`/`Result` over sentinel values, RAII over manual init/teardown, and
    pattern matching over ad-hoc flags.
  - Implement standard traits instead of ad‑hoc methods when applicable (e.g.,
    `Ord`/`PartialOrd` instead of a custom `cmp`, `From`/`TryFrom`, `AsRef`/
    `Borrow`, `Display`/`Debug`, `Error`).
  - Observe naming/style conventions (snake_case for functions/vars, CamelCase
    for types, SCREAMING_SNAKE_CASE for consts), write rustdoc for public APIs,
    and include concise examples where useful.
  - Treat clippy lints as guidance for idiomatic fixes; prefer addressing root
    causes rather than silencing lints. Keep `-D warnings` clean.

- Formatting and linting:
  - Enforce `rustfmt` and `clippy` in CI; treat warnings as errors (zero-warning policy) across the workspace.
  - Use Rust 2024 edition, resolver = "2" for workspaces.
  - Remove all compiler/clippy warnings at the source (unused imports/variables, dead code, etc.). **NEVER** add `#[allow(..)]` or other clippy exceptions to bypass linting - fix the underlying code issues instead.
  - **NEVER** write code with TODO comments, "to do later", "in a future version", or "in a production version" - all code must be production-ready and complete when submitted.
  - **NEVER** use placeholder implementations like `unimplemented!()`, `todo!()`, `panic!("not implemented")`, comments saying "implement this", "add logic here", "handle error properly", "add validation", "add logging", or any other indication that functionality is incomplete or stubbed out.
- Ownership:
  - Prefer borrowing over cloning; use `Cow` when helpful.
  - Avoid `Arc<Mutex<T>>` unless contended shared mutability is required; for
    async use `tokio::sync` primitives. Consider `parking_lot` if justified.
- Lifecycle and ownership discipline:
  - Do not “hack around” Rust lifecycle/borrow checker issues (e.g., sprinkling
    `clone()`, forcing `'static` bounds, or wrapping everything in `Arc/Mutex`)
    to silence errors. Instead, understand and correct the design and data
    ownership model.
  - Never add unnecessary `clone()` just to satisfy the borrow checker. Prefer
    restructuring code to narrow borrows, split mutable borrows, or move values
    when ownership is intended. Consider `Cow<'a, T>` for copy-on-write cases.
  - Use `Arc`/`Rc` only when shared ownership is required; use interior
    mutability (`Mutex`, `RwLock`, `Atomic*`) only when truly needed and with
    clear contention expectations.
  - Before changing code, understand the full context: call graph, module
    boundaries, invariants, and error types. Favor small refactors that make
    ownership and lifetimes explicit and clear.
  - Async: do not hold references across `await` unless they are strictly
    scoped; prefer owned values where appropriate. Ensure spawned tasks own
    what they use and have clear shutdown paths.
- Control flow:
  - Use `?` for propagation; map errors to layer types with `From`/`map_err`.
  - Avoid early `return` for error paths when `?` improves readability.
- Concurrency and async:
  - Do not block the async runtime; use `spawn_blocking` for CPU/IO-heavy
    work that lacks async interfaces (e.g., fsync). Prefer `tokio::fs` when
    appropriate, but be explicit about durability boundaries.
- Safety:
  - `unsafe` code must be rare, justified, reviewed, and encapsulated with
    safe APIs and tests. Document invariants and assumptions.

## File I/O and Durability (EFS/EBS)

**ALWAYS** follow the design doc's invariants for durability and coordination:

- **ONLY** perform same-directory atomic renames for claims/publishes
- **ALWAYS** `fsync` the containing directory after any create/rename/delete that changes directory metadata to ensure persistence across crashes
- **NEVER** rely on file mtimes/ctimes for liveness or ordering
- **ALWAYS** encode progress/liveness in small binary files and replace them atomically
- **NEVER** use multi-writer appends - **ALWAYS** use single-writer files with publish via rename

## Observability and Tracing

**IMPORTANT**: Use ONLY `tokio-tracing` directly for all observability needs. Do NOT create any abstraction layers, utility functions, or custom observability infrastructure.

### Core Principles

- **No custom metrics infrastructure**: Remove all AtomicU64 counters, custom metrics types, and observability abstractions
- **Direct tokio-tracing usage only**: All observability must use `tracing` macros directly (`info!`, `error!`, `warn!`, etc.)
- **No utility functions**: Do NOT create helper functions for metrics, counters, or observability
- **Spans over manual timing**: Use `#[tracing::instrument]` and spans instead of `Instant::now()` + `elapsed()`

### Proper Span Usage

Use spans to represent periods of time and operations with clear beginning and end:

```rust
// Good: Function-level instrumentation for operations
#[tracing::instrument(name = "ingest.build_entry", skip(req), fields(service_name = %req.service_name, operation = %req.operation, placement_epoch))]
pub fn build_entry(req: &IngestRequest, placement_epoch: u64) -> Result<(CRDTWalEntryV1, Vec<u8>), BuildError> {
    tracing::Span::current().record("placement_epoch", placement_epoch);
    // Function body - span automatically tracks duration
    validate_request(req)?;
    // ... rest of implementation
}

// Good: Manual spans for specific operations within functions
async fn process_files(dir: &Path) -> Result<(), Error> {
    let files = std::fs::read_dir(dir)?;
    for file_entry in files {
        let file_path = file_entry?.path();
        
        let span = tracing::span!(tracing::Level::INFO, "process_file", file = %file_path.display());
        let _guard = span.enter();
        
        // Process individual file - span tracks this operation's duration
        process_single_file(&file_path).await?;
    }
    Ok(())
}
```

### When to Use Spans vs Events

- **Spans**: Operations that have duration (function calls, file processing, network requests)
- **Events**: Single-point-in-time occurrences (errors, significant state changes, completion notifications)

```rust
// Span: Wraps an operation with duration
#[tracing::instrument(name = "wal.encode_frame", skip(entry), fields(service_name = %entry.service_name, operation = %entry.operation))]
pub fn encode_frame(entry: &CRDTWalEntryV1) -> Result<Vec<u8>, WalFrameError> {
    // Span automatically captures function duration
    let mut buf = Vec::with_capacity(1024);
    encode_to_buffer(&mut buf, entry)?;
    tracing::Span::current().record("payload_size", buf.len());
    Ok(buf)
}

// Event: Single point in time
tracing::info!(
    correlation_id = correlation_id,
    tenant_id = tenant_id,
    status = response.status_code,
    "Request processed successfully"
);
```

### Structured Logging with Fields

Always use structured fields instead of string interpolation:

```rust
// Good: Structured fields
tracing::info!(
    service_name = %request.service_name,
    operation = %request.operation,
    duration_ns = request.duration_ns,
    status_code = response.status,
    "Request ingested successfully"
);

// Bad: String interpolation
tracing::info!("Request for service {} operation {} completed with status {}", 
    request.service_name, request.operation, response.status);
```

### Hierarchical Spans

Create nested spans for complex operations:

```rust
async fn ingest_request(request: IngestRequest) -> Result<Response, Error> {
    let span = tracing::span!(tracing::Level::INFO, "ingest.request", 
        service = %request.service_name, 
        operation = %request.operation
    );
    let _guard = span.enter();
    
    // Validation step gets its own span
    {
        let _validation_span = tracing::span!(tracing::Level::DEBUG, "ingest.validate").entered();
        validate_request(&request)?;
    }
    
    // Build step gets its own span  
    let entry = {
        let _build_span = tracing::span!(tracing::Level::DEBUG, "ingest.build").entered();
        build_entry(&request)?
    };
    
    // Write step gets its own span
    let result = {
        let _write_span = tracing::span!(tracing::Level::INFO, "ingest.write", 
            tenant = %request.tenant_id
        ).entered();
        write_to_wal(entry).await?
    };
    
    Ok(result)
}
```

### Dynamic Field Recording

Use `Span::current().record()` to add fields during span execution:

```rust
#[tracing::instrument(name = "fs.write_part", skip(bytes), fields(filename, bytes_len = bytes.len()))]
pub async fn write_part(dir: &Path, filename: &str, bytes: &[u8]) -> Result<PathBuf, Error> {
    tracing::Span::current().record("filename", filename);
    
    let path = dir.join(filename);
    tokio::fs::write(&path, bytes).await?;
    
    tracing::Span::current().record("file_path", %path.display());
    Ok(path)
}
```

### Error Handling and Tracing

Use structured error fields, never string interpolation:

```rust
// Good: Structured error logging
match write_result {
    Ok(path) => {
        tracing::info!(
            file_path = %path.display(),
            bytes_written = frame.len(),
            "WAL entry written successfully"
        );
    }
    Err(e) => {
        tracing::error!(
            error = %e,
            operation = "wal_write",
            tenant_id = %tenant_id,
            "Failed to write WAL entry"
        );
        return Err(e);
    }
}
```

### Service Initialization and Lifecycle

Use spans and events for service lifecycle:

```rust
#[tokio::main]
async fn main() {
    let _subscriber = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let startup_span = tracing::span!(tracing::Level::INFO, "service.startup");
    let _guard = startup_span.enter();
    
    tracing::info!(service = env!("CARGO_PKG_NAME"), "Service starting");
    
    // Service initialization logic
    let app = create_router().await?;
    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    
    tracing::info!(bind_addr = %addr, "Service started successfully");
    
    drop(_guard); // End startup span
    
    // Run the service
    axum::serve(listener, app).await?;
}
```

### What NOT to Do

- **NO manual timing**: Never use `Instant::now()` and `elapsed()` - spans track duration automatically
- **NO atomic counters**: Never use `AtomicU64`, `AtomicBool` for metrics - use tracing events
- **NO custom metrics types**: Never create custom metric structs or registries
- **NO utility functions**: Never create helper functions like `log_duration()` or `increment_counter()`
- **NO abstraction layers**: Never wrap tracing in custom interfaces or facades

```rust
// Bad: Manual timing
let start = Instant::now();
do_work().await?;
let duration = start.elapsed();
tracing::info!(duration_ms = duration.as_millis(), "Work completed");

// Good: Span timing
let _span = tracing::span!(tracing::Level::INFO, "do_work").entered();
do_work().await?;
// Span automatically records duration when dropped
```

### Required Dependencies

Only these tracing dependencies are allowed:
- `tracing` - Core tracing macros and spans
- `tracing-subscriber` - For initialization and formatting
- Any specific tracing exporters (e.g., `tracing-opentelemetry`) as needed

Do NOT use:
- `tokio-metrics` or any other metrics crates
- Custom observability utilities
- Any abstraction layers over tracing

## Serialization and Binary Codecs

- **ALWAYS** use `serde` for structured serialization - **ALWAYS** set `#[serde(deny_unknown_fields)]` for externally facing types
- **ALWAYS** make endianness explicit for binary formats - **ALWAYS** validate lengths and CRCs
- **NEVER** panic in decoders - **ALWAYS** return precise error variants (e.g., Truncated, InvalidCrc, UnknownTag, Overflow)

## Dependency Policy

- **Use latest stable versions**: All dependencies MUST use the latest stable versions available at time of implementation.
- **Workspace dependency management**: Dependencies used in multiple crates MUST be defined in the workspace `Cargo.toml` `[workspace.dependencies]` section and imported using `workspace = true` in individual crate manifests.
- **Rust 2024 Edition**: All code MUST be written using Rust 2024 edition features and idioms. Update `edition = "2024"` in all `Cargo.toml` files.
- **ALWAYS** prefer well-known, well-maintained crates with permissive licenses:
  - Errors: **ALWAYS** use `thiserror`; Top-level reporting: **ONLY** use `anyhow`/`miette` (bin only)
  - Logging: **ALWAYS** use `tracing`, `tracing-subscriber`
  - Async: **ALWAYS** use `tokio` (current stable), `tokio-util`, `futures`
  - HTTP: **ALWAYS** use `axum`, `hyper`
  - Serde: **ALWAYS** use `serde`, `serde_json`
  - UUID/time: **ALWAYS** use `uuid`, `time` (or `chrono` if required by deps)
  - Bytes/IO: **ALWAYS** use `bytes`, `crc32fast`
  - Data/SQL: **ALWAYS** use `datafusion`, `arrow`, `sqlx`/`tokio-postgres`
  - Testing: **ALWAYS** use `proptest`/`quickcheck` when property tests add value
- **ALWAYS** audit dependencies:
  - **ALWAYS** pin MSRV to latest stable Rust - **ALWAYS** use `cargo-deny` and `cargo-audit` in CI
  - **NEVER** use abandoned or single-maintainer crates for critical paths

## Testing

- **ALWAYS** write unit tests close to the code - **ALWAYS** use property tests for parsers/codecs - **ALWAYS** fuzz where practical - **NEVER** allow panics in parsing on malformed input
- **ALWAYS** write integration tests for IO boundaries (rename+fsync sequences), recovery, and concurrency edges (claim contention, adoption)
- **ALWAYS** write deterministic tests - **NEVER** use wall-clock in assertions - **ALWAYS** use fixed seeds/data
- **ALWAYS** use tempdirs or in-memory FS abstractions for isolation - **ALWAYS** clean up outputs
- **NEVER** "fix" failing tests by removing or commenting out production code, deleting functionality, or by disabling/skipping tests. **It is completely unacceptable to delete code to make tests pass.** Always address the root cause in code. Only update tests when requirements change, and document the rationale in the change.
- **NEVER** hide failures behind feature flags or visibility changes - Features are for capabilities, **NEVER** for masking defects during testing
- **ALWAYS** run the full suite: **ALWAYS** run the entire workspace's tests and features together before merging: `cargo test --all --all-features` - Partial runs are acceptable during local iteration, but the gate is **ALWAYS** a green full-suite run
- **ALWAYS** use verbose output when diagnosing failures: **ALWAYS** prefer `cargo test --all --all-features -- --nocapture` (and optionally `-Z unstable-options --report-time` locally) to surface which test fails and capture println!/tracing output - **NEVER** use `-q` during debugging
- CI **MUST** execute the full suite (`--all --all-features`) and fail the job on any test failure - **NEVER** keep flaky tests in main - **ALWAYS** fix root causes promptly
  - Code **MUST ALWAYS** compile and test with zero warnings and zero failures - **ALWAYS** configure CI to fail on any warning (e.g., `RUSTFLAGS=-Dwarnings`, `clippy -D warnings`)

## Practical Examples

Typed error per layer with wrapping:
```rust
#[derive(thiserror::Error, Debug)]
pub enum WalError {
    #[error("io error writing wal: {path}")]
    Io {
        #[source] source: std::io::Error,
        path: std::path::PathBuf,
    },
    #[error("checksum mismatch at frame {frame}")]
    Checksum { frame: u64 },
}

#[derive(thiserror::Error, Debug)]
pub enum IngestError {
    #[error(transparent)]
    Wal(#[from] WalError),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
}
```

Newtype with smart constructor and `FromStr`:
```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PlacementEpoch(u64);

impl PlacementEpoch {
    pub fn new(v: u64) -> Self { Self(v) }
    pub fn get(&self) -> u64 { self.0 }
}

impl std::str::FromStr for PlacementEpoch {
    type Err = EpochParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v: u64 = s.parse().map_err(|_| EpochParseError::Invalid)?;
        Ok(Self(v))
    }
}

#[derive(thiserror::Error, Debug)]
pub enum EpochParseError { #[error("invalid epoch")] Invalid }
```

Avoiding stringly and boxed errors in libraries:
```rust
// Bad (don’t do this in library code):
pub fn write_wal(...) -> Result<(), Box<dyn std::error::Error>> { ... }

// Good:
pub fn write_wal(...) -> Result<(), WalError> { ... }
```

## Code Quality and CI

- CI MUST run: `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`,
  and `cargo test --all`.
- Keep lints actionable; **NEVER** use `#[allow(..)]` or other clippy exceptions - fix the root code issues instead.
- Document unsafe blocks, invariants, and performance-critical sections.
- Enforce zero warnings in CI and locally (e.g., `RUSTFLAGS=-Dwarnings`) so new warnings cannot land.

## Tool Configuration - READ ONLY

**Agents must NEVER modify static analysis or linting tool configurations.**

The following files and configurations are READ ONLY. Agents must treat them as immutable:

| File/Pattern | Purpose |
|--------------|---------|
| `clippy.toml` | Clippy lint configuration |
| `rustfmt.toml` | Rust formatting configuration |
| `.rustfmt.toml` | Rust formatting configuration (alternate location) |
| `rust-toolchain.toml` | Rust toolchain version pinning |
| `.clang-format` | C/C++ formatting configuration |
| `.clang-tidy` | C/C++ static analysis configuration |
| `pyproject.toml` (tool sections) | Python linting/formatting configuration (ruff, black, mypy, etc.) |
| `.ruff.toml` | Ruff linter configuration |
| `ruff.toml` | Ruff linter configuration |
| `.pylintrc` | Pylint configuration |
| `setup.cfg` (tool sections) | Python tool configuration |
| `.editorconfig` | Editor configuration |
| `.pre-commit-config.yaml` | Pre-commit hook configuration |
| `deny.toml` | cargo-deny configuration |
| `.cargo/config.toml` | Cargo configuration |
| `CMakeLists.txt` (compiler flags) | C/C++ compiler warning flags |

**Why this rule exists:**
- Tool configurations define project-wide quality standards agreed upon by the team.
- Modifying configurations to silence warnings bypasses code review and weakens quality gates.
- Agents may be tempted to disable lints rather than fix underlying code issues.
- Configuration changes have project-wide impact and require human review.

**What agents MUST do instead:**
- Fix the underlying code issue that triggered the lint or warning.
- If a lint appears genuinely incorrect, report it to the coordinator for human review.
- Never add `#[allow(...)]`, `// NOLINT`, `# noqa`, `@SuppressWarnings`, or equivalent suppressions.
- Never modify compiler flags to reduce warning levels.

**Violation of this rule is grounds for immediate task failure.**

## Enhanced Linting and Documentation Standards

### Linting Configuration

Use enhanced clippy lints for better code quality:
```rust
#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(
    missing_docs,
    rust_2021_compatibility,
    future_incompatible,
    nonstandard_style,
    unused,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo
)]
#![allow(clippy::module_name_repetitions)] // Allow for clarity in module organization
```

Configure `clippy.toml` in the project root to customize lint behavior:
- Set appropriate complexity thresholds
- Configure type complexity limits
- Allow necessary exceptions with clear justification

### Documentation Requirements

- ALL public APIs MUST have complete documentation with examples
- Module-level documentation MUST explain the module's purpose and provide usage examples
- Function documentation MUST include:
  - Purpose and behavior description
  - Parameter descriptions with constraints
  - Return value explanation
  - Error conditions and edge cases
  - Usage examples for complex APIs

Documentation example:
```rust
//! Metrics collection and reporting utilities.
//! 
//! This module provides a simplified interface for OpenTelemetry metrics
//! with automatic instrument registration and caching.
//! 
//! # Examples
//! 
//! ```rust
//! use common::metrics;
//! 
//! // Increment a counter
//! metrics::inc("requests.total", 1);
//! 
//! // Record a timing measurement
//! let start = std::time::Instant::now();
//! // ... do work ...
//! metrics::observe_ms_from(start, "request.duration");
//! ```

/// Increment a counter by the specified value.
/// 
/// # Arguments
/// 
/// * `name` - The metric name (must be a static string for performance)
/// * `value` - The value to add to the counter
pub fn inc(name: &'static str, value: u64) {
    counter(name).add(value, &[]);
}
```

### Performance and Safety Best Practices

- Replace `.unwrap()` calls with `.expect()` and descriptive messages
- Use `entry()` API to reduce mutex lock contention in concurrent data structures
- Implement proper error handling for lock poisoning scenarios
- Validate input parameters and provide meaningful error types

Example of improved error handling:
```rust
// Bad:
regs.counters.lock().unwrap().insert(name, counter);

// Good:
regs.counters
    .lock()
    .expect("metrics counter registry poisoned")
    .entry(name)
    .or_insert_with(|| create_counter(name))
    .clone()
```

### Type Safety Enhancements

Enhance domain types with full validation:
```rust
impl Port {
    /// Create a new Port, validating that it's not zero or privileged.
    pub fn new(port: u16) -> Result<Self, PortError> {
        match port {
            0 => Err(PortError::Zero),
            1..=1023 => Err(PortError::Privileged(port)),
            _ => Ok(Self(port)),
        }
    }
    
    /// Create a new Port without validation (for privileged use cases).
    pub fn new_privileged(port: u16) -> Result<Self, PortError> {
        if port == 0 {
            return Err(PortError::Zero);
        }
        Ok(Self(port))
    }
}

#[derive(thiserror::Error, Debug)]
pub enum PortError {
    #[error("port cannot be zero")]
    Zero,
    #[error("port {0} is privileged (1-1023)")]
    Privileged(u16),
}
```

## Exceptions and Boundaries

- Type-erased errors (`anyhow::Error`) are acceptable **ONLY** at process edges (`main`, CLI, or Lambda handler boundary) for final reporting/logging
- Quick prototypes **MAY** temporarily relax rules, but **MUST** be refactored to typed errors and newtypes before merging to main

## AI/Vibe Coding Anti-Pattern Prevention

These rules specifically prevent AI coding tools from taking shortcuts that produce non-production-quality Rust code:

### Ownership & Borrowing - No Shortcuts
- **NEVER** add `.clone()` just to satisfy compiler errors - restructure ownership instead
- **NEVER** wrap everything in `Arc<Mutex<T>>` to avoid ownership issues
- **NEVER** use `'static` bounds everywhere to bypass lifetime checking
- **NEVER** use `&*` patterns to convert owned values to references unnecessarily
- **NEVER** use `unsafe` to bypass ownership rules

### Error Handling - Zero Tolerance for Shortcuts
- **NEVER** use `.unwrap()` in library code or core functionality
- **NEVER** use `.expect()` without descriptive error messages explaining the invariant
- **NEVER** use `panic!()` for recoverable errors or user input validation
- **NEVER** use `Box<dyn std::error::Error>` in public APIs - use typed errors with `thiserror`
- **NEVER** use string-based errors or `anyhow::Error` in library interfaces
- **NEVER** convert all errors to generic types with `.into()` - preserve error context

### Type System - No Fighting the Compiler
- **NEVER** use `type` aliases for domain concepts - use newtypes with smart constructors
- **NEVER** implement `Deref` to convert between unrelated types
- **NEVER** use `as` casting without validation for numeric conversions that can overflow
- **NEVER** use `Any` trait to bypass type safety
- **NEVER** use excessive `unsafe` blocks to work around type system limitations

### Concurrency & Async - No Blocking Shortcuts
- **NEVER** use sync `Mutex` when holding locks across `.await` points - use `tokio::sync::Mutex`
- **NEVER** spawn unbounded async tasks without backpressure control
- **NEVER** use `Arc<Mutex<T>>` for simple counters - use `AtomicU64` instead
- **NEVER** block async executor with sync I/O - use `tokio::fs` or `spawn_blocking`
- **NEVER** use `unbounded_channel()` - size channels based on expected load
- **NEVER** use `block_on` inside async contexts

### Performance - No Lazy Allocations
- **NEVER** collect iterators unnecessarily - chain with lazy evaluation
- **NEVER** use `Vec<T>` when size is known - use `[T; N]` arrays
- **NEVER** allocate in hot loops without reusing buffers
- **NEVER** use `String` concatenation in loops - use `format!` or pre-allocate with capacity
- **NEVER** use `HashMap` for small fixed key sets - use `match` statements
- **NEVER** repeatedly convert between `String` and `&str` in same function

### Testing - No Sloppy Test Code
- **NEVER** use `.unwrap()` in tests without meaningful failure messages
- **NEVER** test private implementation details - test public APIs only
- **NEVER** write non-deterministic tests - use fixed seeds or deterministic data
- **NEVER** ignore test errors with `let _ = result;`
- **NEVER** use `panic!()` instead of proper assertion macros with descriptive messages

### Ecosystem Usage - No Dependency Bloat
- **NEVER** use `regex` for simple string operations that `str` methods handle
- **NEVER** add heavy dependencies for single utility functions
- **NEVER** use outdated versions of foundational crates
- **NEVER** use multiple competing crates for same functionality
- **NEVER** implement custom solutions when maintained crates exist

### Idiomatic Rust - No C-Style Code
- **NEVER** use C-style loops instead of iterator adapters
- **NEVER** use index-based loops when iterators are more appropriate
- **NEVER** use `match` with boolean conditions instead of `if let`
- **NEVER** implement manual `Drop` when RAII patterns suffice
- **NEVER** write imperative code when functional style is clearer

### Memory Safety - No Unsafe Shortcuts
- **NEVER** use `mem::forget` or `mem::transmute` casually
- **NEVER** leak memory with `Box::leak` without documentation and justification
- **NEVER** use raw pointer arithmetic without bounds checking
- **NEVER** cast between incompatible types without validation
- **NEVER** access uninitialized memory through `unsafe` - use `MaybeUninit<T>`

### Production Readiness - Zero Placeholders
- **NEVER** submit code with TODO comments or `unimplemented!()` macros
- **NEVER** use `.unwrap()` or `.expect()` in error handling paths
- **NEVER** panic on user input or external data
- **NEVER** leave debug prints or temporary logging statements
- **NEVER** ship code with dead code or unused imports
- **NEVER** use deprecated APIs without migration plans

### Documentation Reading - Full Context Required
- **ALWAYS** read documentation files in full when instructed to read them
- **NEVER** summarize or truncate documentation when asked to read it
- **ALWAYS** process the complete content of documentation files
- **NEVER** skip sections or provide partial readings of documentation

### Code Editing - Manual Source Changes Only
- **NEVER** use `sed`, `awk`, or similar text processing tools to modify source code
- **NEVER** write Python scripts or other automated tools to edit code files
- **ALWAYS** edit source files directly using proper editing tools
- **ALWAYS** make changes to code by reading and manually editing the source files
- Code changes must be made through direct file editing, ensuring proper understanding of context and maintaining code integrity

---
Adhering to these rules yields code that is safer, easier to reason about,
more testable, and friendlier to long-term maintenance.
