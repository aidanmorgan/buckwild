// C FFI Integration Tests
//!
//! These tests use actual C code to create packet_event structs
//! and verify Rust can parse them correctly.

#[cfg(test)]
mod ffi_tests {
    use std::os::raw::c_void;

    // FFI declarations for C test helper functions
    extern "C" {
        fn create_test_packet_event(buffer: *mut u8);
        fn create_packet_event(
            buffer: *mut u8,
            session_id: u64,
            sequence: u64,
            timestamp_us: u64,
            payload_length: u16,
            packet_type: u8,
            flags: u8,
            src_ip: u32,
        );
        fn get_packet_event_size() -> u32;
        fn verify_packet_event_layout() -> i32;
        fn create_batch_events(buffer: *mut u8, count: u32);
        fn extract_packet_event_values(
            buffer: *const u8,
            session_id: *mut u64,
            sequence: *mut u64,
            timestamp_us: *mut u64,
            payload_length: *mut u16,
            packet_type: *mut u8,
            flags: *mut u8,
            src_ip: *mut u32,
        );
        fn test_endianness() -> i32;
        fn create_max_values_event(buffer: *mut u8);
        fn create_zero_values_event(buffer: *mut u8);
    }

    #[test]
    fn test_c_struct_size_matches() {
        unsafe {
            let size = get_packet_event_size();
            assert_eq!(
                size, 32,
                "C packet_event size must be 32 bytes, got {}",
                size
            );
        }
    }

    #[test]
    fn test_c_struct_layout_verified() {
        unsafe {
            let result = verify_packet_event_layout();
            assert_eq!(
                result, 1,
                "C packet_event layout verification failed"
            );
        }
    }

    #[test]
    fn test_c_endianness() {
        unsafe {
            let result = test_endianness();
            assert_eq!(result, 1, "Endianness test failed");
        }
    }

    #[test]
    fn test_parse_c_generated_event() {
        let mut buffer = vec![0u8; 32];

        unsafe {
            create_test_packet_event(buffer.as_mut_ptr());
        }

        // Parse using Rust logic (same as RingBufferManager)
        let session_id = u64::from_le_bytes([
            buffer[0], buffer[1], buffer[2], buffer[3],
            buffer[4], buffer[5], buffer[6], buffer[7],
        ]);
        let sequence = u64::from_le_bytes([
            buffer[8], buffer[9], buffer[10], buffer[11],
            buffer[12], buffer[13], buffer[14], buffer[15],
        ]);
        let timestamp_us = u64::from_le_bytes([
            buffer[16], buffer[17], buffer[18], buffer[19],
            buffer[20], buffer[21], buffer[22], buffer[23],
        ]);
        let payload_length = u16::from_le_bytes([buffer[24], buffer[25]]);
        let packet_type = buffer[26];
        let flags = buffer[27];
        let src_ip = u32::from_le_bytes([buffer[28], buffer[29], buffer[30], buffer[31]]);

        // Verify parsed values match expected
        assert_eq!(session_id, 0x1234567890ABCDEF, "session_id mismatch");
        assert_eq!(sequence, 42, "sequence mismatch");
        assert_eq!(timestamp_us, 1000000, "timestamp_us mismatch");
        assert_eq!(payload_length, 1500, "payload_length mismatch");
        assert_eq!(packet_type, 0x01, "packet_type mismatch");
        assert_eq!(flags, 0x80, "flags mismatch");
        assert_eq!(src_ip, 0xC0A80164, "src_ip mismatch");

        // Verify IP address conversion
        let ip_addr = std::net::Ipv4Addr::from(src_ip);
        assert_eq!(ip_addr, std::net::Ipv4Addr::new(192, 168, 1, 100));
    }

    #[test]
    fn test_c_generated_custom_values() {
        let mut buffer = vec![0u8; 32];

        let test_session_id = 0xDEADBEEFCAFEBABE;
        let test_sequence = 999;
        let test_timestamp = 5000000;
        let test_payload = 2000;

        unsafe {
            create_packet_event(
                buffer.as_mut_ptr(),
                test_session_id,
                test_sequence,
                test_timestamp,
                test_payload,
                0x02,
                0x42,
                0x7F000001, // 127.0.0.1
            );
        }

        // Parse and verify
        let session_id = u64::from_le_bytes([
            buffer[0], buffer[1], buffer[2], buffer[3],
            buffer[4], buffer[5], buffer[6], buffer[7],
        ]);
        let sequence = u64::from_le_bytes([
            buffer[8], buffer[9], buffer[10], buffer[11],
            buffer[12], buffer[13], buffer[14], buffer[15],
        ]);

        assert_eq!(session_id, test_session_id);
        assert_eq!(sequence, test_sequence);
    }

    #[test]
    fn test_c_generated_batch_events() {
        const EVENT_COUNT: u32 = 10;
        let mut buffer = vec![0u8; (32 * EVENT_COUNT) as usize];

        unsafe {
            create_batch_events(buffer.as_mut_ptr(), EVENT_COUNT);
        }

        // Verify all events
        for i in 0..EVENT_COUNT {
            let offset = (i * 32) as usize;
            let event_buffer = &buffer[offset..offset + 32];

            let session_id = u64::from_le_bytes([
                event_buffer[0], event_buffer[1], event_buffer[2], event_buffer[3],
                event_buffer[4], event_buffer[5], event_buffer[6], event_buffer[7],
            ]);
            let sequence = u64::from_le_bytes([
                event_buffer[8], event_buffer[9], event_buffer[10], event_buffer[11],
                event_buffer[12], event_buffer[13], event_buffer[14], event_buffer[15],
            ]);

            assert_eq!(session_id, i as u64, "Batch event {} session_id mismatch", i);
            assert_eq!(sequence, (i * 10) as u64, "Batch event {} sequence mismatch", i);
        }
    }

    #[test]
    fn test_c_extract_and_rust_parse_roundtrip() {
        let mut buffer = vec![0u8; 32];

        unsafe {
            create_test_packet_event(buffer.as_mut_ptr());
        }

        // Extract values using C
        let mut c_session_id: u64 = 0;
        let mut c_sequence: u64 = 0;
        let mut c_timestamp: u64 = 0;
        let mut c_payload: u16 = 0;
        let mut c_type: u8 = 0;
        let mut c_flags: u8 = 0;
        let mut c_ip: u32 = 0;

        unsafe {
            extract_packet_event_values(
                buffer.as_ptr(),
                &mut c_session_id,
                &mut c_sequence,
                &mut c_timestamp,
                &mut c_payload,
                &mut c_type,
                &mut c_flags,
                &mut c_ip,
            );
        }

        // Parse using Rust
        let rust_session_id = u64::from_le_bytes([
            buffer[0], buffer[1], buffer[2], buffer[3],
            buffer[4], buffer[5], buffer[6], buffer[7],
        ]);
        let rust_sequence = u64::from_le_bytes([
            buffer[8], buffer[9], buffer[10], buffer[11],
            buffer[12], buffer[13], buffer[14], buffer[15],
        ]);

        // Verify C and Rust parse the same values
        assert_eq!(c_session_id, rust_session_id, "Session ID mismatch between C and Rust");
        assert_eq!(c_sequence, rust_sequence, "Sequence mismatch between C and Rust");
        assert_eq!(c_timestamp, 1000000, "C timestamp mismatch");
        assert_eq!(c_payload, 1500, "C payload mismatch");
        assert_eq!(c_type, 0x01, "C packet type mismatch");
        assert_eq!(c_flags, 0x80, "C flags mismatch");
        assert_eq!(c_ip, 0xC0A80164, "C IP mismatch");
    }

    #[test]
    fn test_c_generated_max_values() {
        let mut buffer = vec![0u8; 32];

        unsafe {
            create_max_values_event(buffer.as_mut_ptr());
        }

        // Parse and verify max values
        let session_id = u64::from_le_bytes([
            buffer[0], buffer[1], buffer[2], buffer[3],
            buffer[4], buffer[5], buffer[6], buffer[7],
        ]);
        let payload_length = u16::from_le_bytes([buffer[24], buffer[25]]);

        assert_eq!(session_id, u64::MAX);
        assert_eq!(payload_length, u16::MAX);
        assert_eq!(buffer[26], u8::MAX);
        assert_eq!(buffer[27], u8::MAX);
    }

    #[test]
    fn test_c_generated_zero_values() {
        let mut buffer = vec![0u8; 32];

        unsafe {
            create_zero_values_event(buffer.as_mut_ptr());
        }

        // Verify all bytes are zero
        for &byte in &buffer {
            assert_eq!(byte, 0, "Expected all zero bytes");
        }

        // Parse and verify zero values
        let session_id = u64::from_le_bytes([
            buffer[0], buffer[1], buffer[2], buffer[3],
            buffer[4], buffer[5], buffer[6], buffer[7],
        ]);

        assert_eq!(session_id, 0);
    }

    #[test]
    fn test_alignment_independence() {
        // Test that parsing works even with misaligned data
        let mut larger_buffer = vec![0xFFu8; 64];

        // Place event at offset 1 (misaligned)
        unsafe {
            create_test_packet_event(larger_buffer[1..33].as_mut_ptr());
        }

        // Parse from offset 1
        let offset_buffer = &larger_buffer[1..33];
        let session_id = u64::from_le_bytes([
            offset_buffer[0], offset_buffer[1], offset_buffer[2], offset_buffer[3],
            offset_buffer[4], offset_buffer[5], offset_buffer[6], offset_buffer[7],
        ]);

        assert_eq!(session_id, 0x1234567890ABCDEF);
    }

    #[test]
    fn test_memory_safety() {
        // Verify no buffer overflows
        let mut buffer = vec![0xAAu8; 64];  // Larger buffer with canary values

        unsafe {
            create_test_packet_event(buffer.as_mut_ptr());
        }

        // Check canary values after the event
        for i in 32..64 {
            assert_eq!(
                buffer[i], 0xAA,
                "Buffer overflow detected at offset {}",
                i
            );
        }
    }
}
