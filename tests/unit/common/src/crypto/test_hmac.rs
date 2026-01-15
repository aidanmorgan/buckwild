use buckwild_common::crypto::hmac::*;
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
    fn test_hmac_policies() {
        // Test Light policy
        let key = b"test key";
        let context = HmacContext::new(key, HmacPolicy::Light);
        let message = b"test message";
        let tag = context.sign(message);
        let truncated_tag = &tag.as_ref()[..context.policy().tag_length()];
        assert_eq!(truncated_tag.len(), 8);
        assert!(context.verify(message, truncated_tag).is_ok());
        
        // Test Medium policy
        let context = HmacContext::new(key, HmacPolicy::Medium);
        let tag = context.sign(message);
        let truncated_tag = &tag.as_ref()[..context.policy().tag_length()];
        assert_eq!(truncated_tag.len(), 16);
        assert!(context.verify(message, truncated_tag).is_ok());
        
        // Test Strong policy
        let context = HmacContext::new(key, HmacPolicy::Strong);
        let tag = context.sign(message);
        let truncated_tag = &tag.as_ref()[..context.policy().tag_length()];
        assert_eq!(truncated_tag.len(), 32);
        assert!(context.verify(message, truncated_tag).is_ok());
    }
    
    #[test]
    fn test_thread_safe_context() {
        // Create thread-safe HMAC context
        let key = b"test key";
        let context = ThreadSafeHmacContext::new(key, HmacPolicy::Medium);
        
        // Sign a message
        let message = b"test message";
        let tag = context.sign(message);
        
        // Verify the tag
        let truncated_tag = &tag.as_ref()[..context.policy().tag_length()];
        assert!(context.verify(message, truncated_tag).is_ok());
    }
    
    #[test]
    fn test_policy_negotiation() {
        // Create negotiation with all policies
        let negotiation = HmacPolicyNegotiation::all_policies();
        
        // Negotiate with remote supporting all policies
        let remote_policies = vec![
            HmacPolicy::Light,
            HmacPolicy::Medium,
            HmacPolicy::Strong,
        ];
        let policy = negotiation.negotiate(&remote_policies).unwrap();
        assert_eq!(policy, HmacPolicy::Strong);
        
        // Negotiate with remote supporting only Light
        let remote_policies = vec![HmacPolicy::Light];
        let policy = negotiation.negotiate(&remote_policies).unwrap();
        assert_eq!(policy, HmacPolicy::Light);
        
        // Negotiate with remote supporting Medium and Light
        let remote_policies = vec![HmacPolicy::Light, HmacPolicy::Medium];
        let policy = negotiation.negotiate(&remote_policies).unwrap();
        assert_eq!(policy, HmacPolicy::Medium);
        
        // Negotiate with no common policies
        let negotiation = HmacPolicyNegotiation::new(vec![HmacPolicy::Strong]);
        let remote_policies = vec![HmacPolicy::Light];
        assert!(negotiation.negotiate(&remote_policies).is_none());
    }
    
    #[test]
    fn test_policy_serialization() {
        // Create negotiation with all policies
        let negotiation = HmacPolicyNegotiation::all_policies();
        
        // Serialize
        let data = negotiation.serialize();
        
        // Deserialize
        let policies = HmacPolicyNegotiation::deserialize(&data).unwrap();
        
        // Check policies
        assert_eq!(policies.len(), 3);
        assert!(policies.contains(&HmacPolicy::Light));
        assert!(policies.contains(&HmacPolicy::Medium));
        assert!(policies.contains(&HmacPolicy::Strong));
    }
