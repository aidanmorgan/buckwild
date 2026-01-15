use buckwild_common::protocol:packet::types::*;
#[test]
    fn test_packet_type() {
        assert_eq!(PacketType::from_u8(0x01), Some(PacketType::Syn));
        assert_eq!(PacketType::from_u8(0x04), Some(PacketType::Data));
        assert_eq!(PacketType::from_u8(0xFF), None);

        assert_eq!(PacketType::Syn.packet_class(), PacketClass::Critical);
        assert_eq!(PacketType::Data.packet_class(), PacketClass::Data);
        assert_eq!(PacketType::Control.packet_class(), PacketClass::Control);

        assert!(PacketType::Syn.requires_ack());
        assert!(PacketType::Data.requires_ack());
        assert!(!PacketType::Ack.requires_ack());

        assert!(PacketType::Syn.is_connection_packet());
        assert!(!PacketType::Data.is_connection_packet());

        assert!(PacketType::Data.carries_data());
        assert!(!PacketType::Syn.carries_data());
    }

    #[test]
    fn test_packet_flags() {
        let mut flags = PacketFlags::new();
        assert_eq!(flags.as_u8(), 0);

        flags.set(PacketFlags::SYN);
        assert!(flags.is_syn());
        assert!(!flags.is_ack());

        flags.set(PacketFlags::ACK);
        assert!(flags.is_syn());
        assert!(flags.is_ack());

        flags.clear(PacketFlags::SYN);
        assert!(!flags.is_syn());
        assert!(flags.is_ack());
    }

    #[test]
    fn test_version_byte() {
        let version = VersionByte::new(SessionIdLength::Bits32, TimestampConfig::Bits24);
        assert_eq!(version.session_id_length(), SessionIdLength::Bits32);
        assert_eq!(version.timestamp_config(), TimestampConfig::Bits24);
        assert_eq!(version.version(), 1);

        let reconstructed = VersionByte::from_u8(version.as_u8());
        assert_eq!(reconstructed.session_id_length(), SessionIdLength::Bits32);
        assert_eq!(reconstructed.timestamp_config(), TimestampConfig::Bits24);
        assert_eq!(reconstructed.version(), 1);
    }

    #[test]
    fn test_session_id_length() {
        assert_eq!(SessionIdLength::Bits16.len(), 2);
        assert_eq!(SessionIdLength::Bits32.len(), 4);
        assert_eq!(SessionIdLength::Bits64.len(), 8);

        assert_eq!(SessionIdLength::from_u8(0), SessionIdLength::Bits16);
        assert_eq!(SessionIdLength::from_u8(1), SessionIdLength::Bits32);
        assert_eq!(SessionIdLength::from_u8(2), SessionIdLength::Bits64);
        assert_eq!(SessionIdLength::from_u8(3), SessionIdLength::Bits32); // Fallback
    }

    #[test]
    fn test_timestamp_config() {
        assert_eq!(TimestampConfig::Bits16.len(), 2);
        assert_eq!(TimestampConfig::Bits24.len(), 3);
        assert_eq!(TimestampConfig::Bits24High.len(), 3);
        assert_eq!(TimestampConfig::Bits32.len(), 4);

        assert_eq!(TimestampConfig::from_u8(0), TimestampConfig::Bits16);
        assert_eq!(TimestampConfig::from_u8(1), TimestampConfig::Bits24);
        assert_eq!(TimestampConfig::from_u8(2), TimestampConfig::Bits24High);
        assert_eq!(TimestampConfig::from_u8(3), TimestampConfig::Bits32);
    }

    #[test]
    fn test_hmac_policy() {
        assert_eq!(HmacPolicy::Light.len(), 8);
        assert_eq!(HmacPolicy::Medium.len(), 16);
        assert_eq!(HmacPolicy::Strong.len(), 32);

        assert_eq!(HmacPolicy::for_packet_class(PacketClass::Critical), HmacPolicy::Strong);
        assert_eq!(HmacPolicy::for_packet_class(PacketClass::Control), HmacPolicy::Medium);
        assert_eq!(HmacPolicy::for_packet_class(PacketClass::Data), HmacPolicy::Light);
    }

    #[test]
    fn test_config_presets() {
        let (version, hmac) = config::iot_config();
        assert_eq!(version.session_id_length(), SessionIdLength::Bits16);
        assert_eq!(version.timestamp_config(), TimestampConfig::Bits16);
        assert_eq!(hmac, HmacPolicy::Light);

        let (version, hmac) = config::standard_config();
        assert_eq!(version.session_id_length(), SessionIdLength::Bits32);
        assert_eq!(version.timestamp_config(), TimestampConfig::Bits24);
        assert_eq!(hmac, HmacPolicy::Medium);

        let (version, hmac) = config::secure_config();
        assert_eq!(version.session_id_length(), SessionIdLength::Bits32);
        assert_eq!(version.timestamp_config(), TimestampConfig::Bits32);
        assert_eq!(hmac, HmacPolicy::Strong);

        let (version, hmac) = config::infrastructure_config();
        assert_eq!(version.session_id_length(), SessionIdLength::Bits64);
        assert_eq!(version.timestamp_config(), TimestampConfig::Bits32);
        assert_eq!(hmac, HmacPolicy::Strong);
    }
