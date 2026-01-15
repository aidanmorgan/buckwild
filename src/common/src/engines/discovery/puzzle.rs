// Computational puzzle for discovery requests
//
// Implements proof-of-work puzzles to prevent spam and DoS attacks.
// Uses partial hash collision with configurable difficulty.

use ring::digest;
use std::time::Instant;
use tracing::{debug, trace};

use crate::error::EngineError;

/// Puzzle difficulty configuration
#[derive(Debug, Clone, Copy)]
pub struct PuzzleDifficulty {
    /// Number of leading zero bits required in hash
    pub leading_zero_bits: u8,
}

impl PuzzleDifficulty {
    /// Easy difficulty (4 bits = 16 hash attempts average)
    pub const EASY: Self = Self {
        leading_zero_bits: 4,
    };

    /// Medium difficulty (8 bits = 256 hash attempts average)
    pub const MEDIUM: Self = Self {
        leading_zero_bits: 8,
    };

    /// Hard difficulty (12 bits = 4096 hash attempts average)
    pub const HARD: Self = Self {
        leading_zero_bits: 12,
    };

    /// Very hard difficulty (16 bits = 65536 hash attempts average)
    pub const VERY_HARD: Self = Self {
        leading_zero_bits: 16,
    };

    /// Create custom difficulty
    pub fn custom(leading_zero_bits: u8) -> Self {
        Self { leading_zero_bits }
    }

    /// Estimate average attempts needed
    pub fn expected_attempts(&self) -> u32 {
        2u32.pow(self.leading_zero_bits as u32)
    }
}

impl Default for PuzzleDifficulty {
    fn default() -> Self {
        Self::MEDIUM // 256 attempts average - good balance
    }
}

/// Puzzle challenge issued to requester
#[derive(Debug, Clone)]
pub struct PuzzleChallenge {
    /// Challenge nonce from server
    pub challenge: [u8; 32],
    /// Difficulty level
    pub difficulty: PuzzleDifficulty,
    /// Session salt for binding
    pub session_salt: u32,
}

impl PuzzleChallenge {
    /// Create a new puzzle challenge
    pub fn new(challenge: [u8; 32], difficulty: PuzzleDifficulty, session_salt: u32) -> Self {
        Self {
            challenge,
            difficulty,
            session_salt,
        }
    }

    /// Generate a random challenge
    pub fn generate(difficulty: PuzzleDifficulty, session_salt: u32) -> Result<Self, EngineError> {
        let mut challenge = [0u8; 32];
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        rng.fill(&mut challenge)
            .map_err(|_| EngineError::EngineCoordinationError {
                reason: "Failed to generate puzzle challenge".to_string(),
            })?;

        Ok(Self::new(challenge, difficulty, session_salt))
    }
}

/// Puzzle solution from requester
#[derive(Debug, Clone)]
pub struct PuzzleSolution {
    /// Solution nonce found by requester
    pub nonce: u64,
    /// Hash result (for verification)
    pub hash: [u8; 32],
}

impl PuzzleSolution {
    /// Create a new puzzle solution
    pub fn new(nonce: u64, hash: [u8; 32]) -> Self {
        Self { nonce, hash }
    }
}

/// Puzzle solver and verifier
pub struct PuzzleSolver {
    pub difficulty: PuzzleDifficulty,
}

impl PuzzleSolver {
    /// Create a new puzzle solver with specified difficulty
    pub fn new(difficulty: PuzzleDifficulty) -> Self {
        Self { difficulty }
    }

    /// Solve a puzzle challenge
    ///
    /// Attempts to find a nonce that produces a hash with the required
    /// number of leading zero bits. Returns the solution or gives up
    /// after max_attempts.
    pub fn solve(
        &self,
        challenge: &PuzzleChallenge,
        max_attempts: u64,
    ) -> Result<PuzzleSolution, EngineError> {
        let start = Instant::now();
        let required_zeros = challenge.difficulty.leading_zero_bits;

        trace!(
            difficulty_bits = required_zeros,
            max_attempts, "Starting puzzle solve"
        );

        for nonce in 0..max_attempts {
            // Construct input: challenge || session_salt || nonce
            let mut input = Vec::with_capacity(44);
            input.extend_from_slice(&challenge.challenge);
            input.extend_from_slice(&challenge.session_salt.to_be_bytes());
            input.extend_from_slice(&nonce.to_be_bytes());

            // Hash the input
            let hash_result = digest::digest(&digest::SHA256, &input);
            let hash_bytes = hash_result.as_ref();

            // Check if it meets difficulty requirement
            if self.check_leading_zeros(hash_bytes, required_zeros) {
                let elapsed = start.elapsed();
                debug!(
                    nonce,
                    attempts = nonce + 1,
                    elapsed_ms = elapsed.as_millis(),
                    "Puzzle solved"
                );

                let mut hash = [0u8; 32];
                hash.copy_from_slice(hash_bytes);
                return Ok(PuzzleSolution::new(nonce, hash));
            }
        }

        Err(EngineError::EngineCoordinationError {
            reason: format!("Failed to solve puzzle after {} attempts", max_attempts),
        })
    }

    /// Verify a puzzle solution
    pub fn verify(
        &self,
        challenge: &PuzzleChallenge,
        solution: &PuzzleSolution,
    ) -> Result<(), EngineError> {
        let required_zeros = challenge.difficulty.leading_zero_bits;

        // Reconstruct the hash from challenge + nonce
        let mut input = Vec::with_capacity(44);
        input.extend_from_slice(&challenge.challenge);
        input.extend_from_slice(&challenge.session_salt.to_be_bytes());
        input.extend_from_slice(&solution.nonce.to_be_bytes());

        let hash_result = digest::digest(&digest::SHA256, &input);
        let computed_hash = hash_result.as_ref();

        // Verify the hash matches what was provided
        if computed_hash != solution.hash {
            return Err(EngineError::EngineCoordinationError {
                reason: "Puzzle solution hash mismatch".to_string(),
            });
        }

        // Verify it meets difficulty requirement
        if !self.check_leading_zeros(computed_hash, required_zeros) {
            return Err(EngineError::EngineCoordinationError {
                reason: format!(
                    "Puzzle solution does not meet difficulty requirement ({} leading zeros)",
                    required_zeros
                ),
            });
        }

        debug!(nonce = solution.nonce, "Puzzle solution verified");
        Ok(())
    }

    /// Check if hash has required number of leading zero bits
    fn check_leading_zeros(&self, hash: &[u8], required_bits: u8) -> bool {
        let required_full_bytes = (required_bits / 8) as usize;
        let remaining_bits = required_bits % 8;

        // Check full bytes
        for &byte in &hash[..required_full_bytes] {
            if byte != 0 {
                return false;
            }
        }

        // Check remaining bits if any
        if remaining_bits > 0 && required_full_bytes < hash.len() {
            let mask = 0xFFu8 << (8 - remaining_bits);
            if hash[required_full_bytes] & mask != 0 {
                return false;
            }
        }

        true
    }
}

impl Default for PuzzleSolver {
    fn default() -> Self {
        Self::new(PuzzleDifficulty::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_leading_zeros() {
        let solver = PuzzleSolver::new(PuzzleDifficulty::custom(4));

        // 4 leading zero bits = first nibble must be 0
        assert!(solver.check_leading_zeros(&[0x00, 0xFF, 0xFF], 4));
        assert!(solver.check_leading_zeros(&[0x0F, 0xFF, 0xFF], 4));
        assert!(!solver.check_leading_zeros(&[0x10, 0xFF, 0xFF], 4));
        assert!(!solver.check_leading_zeros(&[0xFF, 0xFF, 0xFF], 4));

        // 8 leading zero bits = first byte must be 0
        let solver = PuzzleSolver::new(PuzzleDifficulty::custom(8));
        assert!(solver.check_leading_zeros(&[0x00, 0xFF, 0xFF], 8));
        assert!(!solver.check_leading_zeros(&[0x01, 0xFF, 0xFF], 8));
    }

    #[test]
    fn test_puzzle_solve_and_verify_easy() {
        let difficulty = PuzzleDifficulty::EASY; // 4 bits
        let challenge = PuzzleChallenge::generate(difficulty, 12345).expect("Failed to generate");
        let solver = PuzzleSolver::new(difficulty);

        // Should solve quickly with easy difficulty
        let solution = solver
            .solve(&challenge, 10000)
            .expect("Failed to solve puzzle");

        // Verify the solution
        assert!(solver.verify(&challenge, &solution).is_ok());
    }

    #[test]
    fn test_puzzle_solve_and_verify_medium() {
        let difficulty = PuzzleDifficulty::MEDIUM; // 8 bits
        let challenge = PuzzleChallenge::generate(difficulty, 67890).expect("Failed to generate");
        let solver = PuzzleSolver::new(difficulty);

        // Should solve with medium difficulty (might take a few hundred attempts)
        let solution = solver
            .solve(&challenge, 50000)
            .expect("Failed to solve puzzle");

        // Verify the solution
        assert!(solver.verify(&challenge, &solution).is_ok());
    }

    #[test]
    fn test_invalid_solution_rejected() {
        let difficulty = PuzzleDifficulty::EASY;
        let challenge = PuzzleChallenge::generate(difficulty, 11111).expect("Failed to generate");
        let solver = PuzzleSolver::new(difficulty);

        // Create an invalid solution (wrong nonce)
        let invalid_solution = PuzzleSolution::new(0, [0u8; 32]);

        // Should fail verification
        assert!(solver.verify(&challenge, &invalid_solution).is_err());
    }

    #[test]
    fn test_difficulty_levels() {
        assert_eq!(PuzzleDifficulty::EASY.expected_attempts(), 16);
        assert_eq!(PuzzleDifficulty::MEDIUM.expected_attempts(), 256);
        assert_eq!(PuzzleDifficulty::HARD.expected_attempts(), 4096);
        assert_eq!(PuzzleDifficulty::VERY_HARD.expected_attempts(), 65536);
    }

    #[test]
    fn test_different_challenges_require_different_solutions() {
        let difficulty = PuzzleDifficulty::EASY;
        let solver = PuzzleSolver::new(difficulty);

        let challenge1 = PuzzleChallenge::generate(difficulty, 11111).expect("Failed to generate");
        let challenge2 = PuzzleChallenge::generate(difficulty, 22222).expect("Failed to generate");

        let solution1 = solver.solve(&challenge1, 10000).expect("Failed to solve");

        // Solution for challenge1 should not work for challenge2
        assert!(solver.verify(&challenge2, &solution1).is_err());
    }

    #[test]
    fn test_session_salt_binding() {
        let difficulty = PuzzleDifficulty::EASY;
        let solver = PuzzleSolver::new(difficulty);

        let mut challenge =
            PuzzleChallenge::generate(difficulty, 12345).expect("Failed to generate");
        let solution = solver.solve(&challenge, 10000).expect("Failed to solve");

        // Solution should verify with correct salt
        assert!(solver.verify(&challenge, &solution).is_ok());

        // Change the salt - solution should no longer verify
        challenge.session_salt = 99999;
        assert!(solver.verify(&challenge, &solution).is_err());
    }
}
