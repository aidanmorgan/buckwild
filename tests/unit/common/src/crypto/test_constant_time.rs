use buckwild_common::crypto::constant_time::*;
#[test]
    fn test_constant_time_eq() {
        // Equal slices
        let a = [1, 2, 3, 4, 5];
        let b = [1, 2, 3, 4, 5];
        assert!(constant_time_eq(&a, &b));
        
        // Different slices
        let c = [1, 2, 3, 4, 6];
        assert!(!constant_time_eq(&a, &c));
        
        // Different lengths
        let d = [1, 2, 3, 4];
        assert!(!constant_time_eq(&a, &d));
    }
    
    #[test]
    fn test_verify_slices_are_equal() {
        // Equal slices
        let a = [1, 2, 3, 4, 5];
        let b = [1, 2, 3, 4, 5];
        assert!(verify_slices_are_equal(&a, &b).is_ok());
        
        // Different slices
        let c = [1, 2, 3, 4, 6];
        assert!(verify_slices_are_equal(&a, &c).is_err());
        
        // Different lengths
        let d = [1, 2, 3, 4];
        assert!(verify_slices_are_equal(&a, &d).is_err());
    }
    
    #[test]
    fn test_select_u8() {
        // Select first value
        assert_eq!(select_u8(0, 10, 20), 10);
        
        // Select second value
        assert_eq!(select_u8(1, 10, 20), 20);
    }
    
    #[test]
    fn test_conditional_copy() {
        // Test with condition = 0 (no copy)
        let src = [1, 2, 3, 4, 5];
        let mut dst = [10, 20, 30, 40, 50];
        assert!(conditional_copy(0, &src, &mut dst).is_ok());
        assert_eq!(dst, [10, 20, 30, 40, 50]);
        
        // Test with condition = 1 (copy)
        assert!(conditional_copy(1, &src, &mut dst).is_ok());
        assert_eq!(dst, [1, 2, 3, 4, 5]);
        
        // Test with different lengths
        let src = [1, 2, 3];
        let mut dst = [10, 20, 30, 40, 50];
        assert!(conditional_copy(1, &src, &mut dst).is_err());
    }
