//! Unit tests for cryptographic components

use buckwild::crypto::{
    ecdh::{self, ThreadSafeEcdhManager},
    hmac::{HmacContext, HmacPolicy, ThreadSafeHmacContext},
    kdf::{Kdf, ChunkType, Pbkdf2Params},
    secure_memory::SecureBytes,
    constant_time,
    precomputation,
};

#[test]
fn test_ecdh_key_exchange() {
    // Create ECDH manager
    let manager = ecdh::create_default_ecdh_manager();
    
    // Generate key pairs
    let alice_public = manager.get_key_pair("alice").unwrap();
    let bob_public = manager.get_key_pair("bob").unwrap();
    
    // Compute shared secrets
    let alice_secret = manager.compute_shared_secret("alice", &bob_public).unwrap();
    let bob_secret = manager.compute_shared_secret("bob", &alice_public).unwrap();
    
    // Verify that the shared secrets are the same
    assert_eq!(alice_secret.as_slice(), bob_secret.as_slice());
}

#[test]
fn test_hmac_sign_verify() {
    // Create HMAC context
    let key = b"test key";
    let context = HmacContext::new(key, HmacPolicy::Medium);
    
    // Sign a message
    let message = b"test message";
    let tag = context.sign(message);
    
    // Verify the tag
    let truncated_tag = &tag.as_ref()[..context.policy().tag_length()];
    assert!(context.verify(message, truncated_tag).is_ok());
    
    // Verify with wrong message
    let wrong_message = b"wrong message";
    assert!(context.verify(wrong_message, truncated_tag).is_err());
    
    // Verify with wrong tag
    let mut wrong_tag = truncated_tag.to_vec();
    wrong_tag[0] ^= 1;
    assert!(context.verify(message, &wrong_tag).is_err());
}

#[test]
fn test_kdf_derive_parameters() {
    // Create KDF
    let kdf = Kdf::default();
    
    // Derive parameters
    let key = b"test key";
    let params = kdf.derive_parameters(key).unwrap();
    
    // Check length
    assert_eq!(params.len(), 128);
    
    // Get chunks
    let chunk1 = Kdf::get_chunk(&params, ChunkType::FrequencyHopping, 0).unwrap();
    let chunk2 = Kdf::get_chunk(&params, ChunkType::FrequencyHopping, 1).unwrap();
    
    // Check that chunks are different
    assert_ne!(chunk1, chunk2);
}

#[test]
fn test_secure_memory() {
    // Create secure bytes
    let mut secure_bytes = SecureBytes::new(32).unwrap();
    assert_eq!(secure_bytes.len(), 32);
    
    // Fill with data
    for i in 0..32 {
        secure_bytes[i] = i as u8;
    }
    
    // Check data
    for i in 0..32 {
        assert_eq!(secure_bytes[i], i as u8);
    }
    
    // Clear data
    secure_bytes.clear();
    
    // Check that data is cleared
    for i in 0..32 {
        assert_eq!(secure_bytes[i], 0);
    }
}

#[test]
fn test_constant_time_eq() {
    // Equal slices
    let a = [1, 2, 3, 4, 5];
    let b = [1, 2, 3, 4, 5];
    assert!(constant_time::constant_time_eq(&a, &b));
    
    // Different slices
    let c = [1, 2, 3, 4, 6];
    assert!(!constant_time::constant_time_eq(&a, &c));
    
    // Different lengths
    let d = [1, 2, 3, 4];
    assert!(!constant_time::constant_time_eq(&a, &d));
}

#[test]
fn test_precomputation() {
    // Get HMAC context
    let key = b"test key";
    let context = precomputation::get_hmac_context(key, HmacPolicy::Medium);
    
    // Sign a message
    let message = b"test message";
    let tag = context.sign(message);
    
    // Verify the tag
    let truncated_tag = &tag.as_ref()[..context.policy().tag_length()];
    assert!(context.verify(message, truncated_tag).is_ok());
    
    // Get the same context again
    let context2 = precomputation::get_hmac_context(key, HmacPolicy::Medium);
    
    // Verify that it's the same context
    let tag2 = context2.sign(message);
    assert_eq!(tag.as_ref(), tag2.as_ref());
    
    // Clear the cache
    precomputation::clear_hmac_context_cache();
}