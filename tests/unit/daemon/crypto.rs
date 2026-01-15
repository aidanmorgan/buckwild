use buckwild_common::daemon::crypto::*;

#[test]
fn test_secure_bytes() {
    let data = b"test data";
    let secure = SecureBytes::new(data);
    
    assert_eq!(secure.as_slice(), data);
    assert_eq!(secure.len(), data.len());
    assert!(!secure.is_empty());
    
    let empty = SecureBytes::new(&[]);
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
}

#[test]
fn test_constant_time_compare() {
    let a = b"hello";
    let b = b"hello";
    let c = b"world";
    let d = b"hell";
    
    assert!(constant_time_compare(a, b));
    assert!(!constant_time_compare(a, c));
    assert!(!constant_time_compare(a, d));
    assert!(!constant_time_compare(d, a));
}