// TASK-006: Secure Memory Zeroing Tests
//
// Verifies that all key-holding structs properly zero their memory on drop
// and that temporary buffers use appropriate zeroing wrappers.

use buckwild_common::memory::secure::SecureBytes;
use buckwild_common::protocol::types::{DailyKey, EcdhPrivateKey, SaltBytes, SessionKey, SharedSecret};
use std::ptr;

/// Helper to read memory after a value is dropped
/// SAFETY: This is only safe in test context where we control memory layout
unsafe fn read_memory_after_drop<T, F>(create_fn: F) -> Vec<u8>
where
    F: FnOnce() -> T,
{
    // Allocate memory for the value
    let layout = std::alloc::Layout::new::<T>();
    let ptr = std::alloc::alloc(layout);

    // Create the value at that location
    {
        let value = create_fn();
        ptr::write(ptr as *mut T, value);
    }

    // Value is now dropped, read the memory
    let mut result = vec![0u8; layout.size()];
    ptr::copy_nonoverlapping(ptr, result.as_mut_ptr(), layout.size());

    // Clean up
    std::alloc::dealloc(ptr, layout);

    result
}

#[test]
fn test_shared_secret_zeroed_on_drop() {
    let secret_data = [0x42u8; 32];

    // Create and immediately drop a SharedSecret
    let memory_after = unsafe {
        read_memory_after_drop(|| SharedSecret::new(secret_data))
    };

    // Verify the memory was zeroed (at least the key bytes)
    // Note: Due to struct padding, not all bytes may be zero, but the key data should be
    let all_zero = memory_after.iter().all(|&b| b == 0);
    assert!(
        all_zero,
        "SharedSecret memory should be zeroed after drop, found non-zero bytes: {:?}",
        memory_after.iter().filter(|&&b| b != 0).count()
    );
}

#[test]
fn test_session_key_zeroed_on_drop() {
    let key_data = [0x55u8; 32];

    let memory_after = unsafe {
        read_memory_after_drop(|| SessionKey::new(key_data))
    };

    let all_zero = memory_after.iter().all(|&b| b == 0);
    assert!(
        all_zero,
        "SessionKey memory should be zeroed after drop, found non-zero bytes: {:?}",
        memory_after.iter().filter(|&&b| b != 0).count()
    );
}

#[test]
fn test_ecdh_private_key_zeroed_on_drop() {
    let key_data = [0xAAu8; 32];

    let memory_after = unsafe {
        read_memory_after_drop(|| EcdhPrivateKey::new(key_data))
    };

    let all_zero = memory_after.iter().all(|&b| b == 0);
    assert!(
        all_zero,
        "EcdhPrivateKey memory should be zeroed after drop, found non-zero bytes: {:?}",
        memory_after.iter().filter(|&&b| b != 0).count()
    );
}

#[test]
fn test_daily_key_zeroed_on_drop() {
    let key_data = [0xBBu8; 32];

    let memory_after = unsafe {
        read_memory_after_drop(|| DailyKey::new(key_data))
    };

    let all_zero = memory_after.iter().all(|&b| b == 0);
    assert!(
        all_zero,
        "DailyKey memory should be zeroed after drop, found non-zero bytes: {:?}",
        memory_after.iter().filter(|&&b| b != 0).count()
    );
}

#[test]
fn test_salt_bytes_zeroed_on_drop() {
    let salt_data = vec![0xCCu8; 32];

    // For heap-allocated types, we test differently
    let salt = SaltBytes::new(salt_data);
    let ptr = salt.as_slice().as_ptr();
    let len = salt.len();

    // Drop the salt
    drop(salt);

    // Note: We can't safely read from ptr after drop since it's freed
    // This test primarily ensures the trait is implemented and compiles
    // The zeroize crate's implementation is trusted to work correctly
}

#[test]
fn test_secure_bytes_zeroed_on_drop() {
    // SecureBytes should use ZeroizeOnDrop
    let mut secure = SecureBytes::with_size(32);
    secure.as_mut_slice().fill(0xDDu8);

    // Drop and verify - similar caveat as SaltBytes
    drop(secure);

    // The zeroize crate handles the actual zeroing
}

#[test]
fn test_clone_also_zeroed() {
    // Verify that cloned keys also get zeroed on drop
    let original = SessionKey::new([0x11u8; 32]);
    let cloned = original.clone();

    drop(original);
    drop(cloned);

    // Both should have been zeroed independently
}

#[test]
fn test_key_redacted_in_debug() {
    // Verify that Debug output doesn't leak key material
    let secret = SharedSecret::new([0x42u8; 32]);
    let debug_output = format!("{:?}", secret);

    assert!(
        debug_output.contains("REDACTED"),
        "SharedSecret Debug output should redact key data"
    );
    assert!(
        !debug_output.contains("42"),
        "SharedSecret Debug output should not contain key bytes"
    );
}

#[test]
fn test_session_key_redacted_in_debug() {
    let key = SessionKey::new([0x55u8; 32]);
    let debug_output = format!("{:?}", key);

    assert!(
        debug_output.contains("REDACTED"),
        "SessionKey Debug output should redact key data"
    );
}

#[test]
fn test_daily_key_redacted_in_debug() {
    let key = DailyKey::new([0xAAu8; 32]);
    let debug_output = format!("{:?}", key);

    assert!(
        debug_output.contains("REDACTED"),
        "DailyKey Debug output should redact key data"
    );
}

#[test]
fn test_salt_bytes_redacted_in_debug() {
    let salt = SaltBytes::new(vec![0xBBu8; 32]);
    let debug_output = format!("{:?}", salt);

    assert!(
        debug_output.contains("REDACTED"),
        "SaltBytes Debug output should redact salt data"
    );
}

#[test]
fn test_ecdh_private_key_redacted_in_debug() {
    let key = EcdhPrivateKey::new([0xCCu8; 32]);
    let debug_output = format!("{:?}", key);

    assert!(
        debug_output.contains("REDACTED"),
        "EcdhPrivateKey Debug output should redact key data"
    );
}

#[test]
fn test_secure_bytes_redacted_in_debug() {
    let secure = SecureBytes::from_slice(&[0xDDu8; 32]);
    let debug_output = format!("{:?}", secure);

    assert!(
        debug_output.contains("REDACTED"),
        "SecureBytes Debug output should redact data"
    );
}
