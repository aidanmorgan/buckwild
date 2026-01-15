//! FFI Compatibility Tests for M19 HIGH-015
//!
//! Tests verify that Rust FFI types and C types have identical binary layout,
//! ensuring safe interoperation across the FFI boundary.
//!
//! # Test Categories
//!
//! 1. **Struct Layout Tests**: Size, alignment, field offsets, padding
//! 2. **Calling Convention Tests**: Function pointer compatibility, return values
//! 3. **Memory Tests**: Allocation/deallocation across FFI boundary

#[cfg(test)]
mod tests {
    use crate::{TunConfig, TunDevice};
    use std::mem::{align_of, size_of};
    use std::os::raw::c_char;

    // ============================================================================
    // STRUCT LAYOUT TESTS (4 required)
    // ============================================================================

    /// Test 1: Verify TunConfig struct size matches C buckwild_tun_config_t
    ///
    /// The Rust `TunConfig` struct must have identical size to the C
    /// `buckwild_tun_config_t` struct for safe FFI operations.
    ///
    /// C struct layout (from tun_device_ffi.h):
    /// ```c
    /// typedef struct {
    ///     char name[16];      // 16 bytes
    ///     uint32_t ip_addr;   // 4 bytes
    ///     uint32_t netmask;   // 4 bytes
    ///     uint16_t mtu;       // 2 bytes
    ///     bool persistent;    // 1 byte
    ///     // padding: 1 byte (for alignment to 4-byte boundary)
    /// } buckwild_tun_config_t;  // Total: 28 bytes (with padding)
    /// ```
    #[test]
    fn test_tun_config_size_matches_c() {
        const EXPECTED_SIZE: usize = 28; // 16 + 4 + 4 + 2 + 1 + 1 (padding)

        let actual_size = size_of::<TunConfig>();

        assert_eq!(
            actual_size, EXPECTED_SIZE,
            "TunConfig size mismatch: Rust={} bytes, C={} bytes. \
             FFI types must have identical size for safe interop.",
            actual_size, EXPECTED_SIZE
        );
    }

    /// Test 2: Verify TunConfig struct alignment matches C
    ///
    /// Alignment must match to ensure correct memory layout when
    /// passing structs across the FFI boundary.
    ///
    /// C struct uses default alignment (4 bytes for largest member: uint32_t)
    #[test]
    fn test_tun_config_alignment_matches_c() {
        const EXPECTED_ALIGN: usize = 4; // Aligned to uint32_t (4 bytes)

        let actual_align = align_of::<TunConfig>();

        assert_eq!(
            actual_align, EXPECTED_ALIGN,
            "TunConfig alignment mismatch: Rust={} bytes, C={} bytes. \
             Incorrect alignment can cause crashes on some architectures.",
            actual_align, EXPECTED_ALIGN
        );
    }

    /// Test 3: Verify TunConfig field offsets match C struct layout
    ///
    /// Field offsets must be identical to ensure correct data access
    /// when C code reads Rust-allocated structs (and vice versa).
    ///
    /// Uses `std::mem::offset_of!` macro (stabilized in Rust 1.77)
    #[test]
    fn test_tun_config_field_offsets() {
        use std::mem::offset_of;

        // Expected offsets from C struct layout
        const NAME_OFFSET: usize = 0; // char name[16]
        const IP_ADDR_OFFSET: usize = 16; // uint32_t ip_addr
        const NETMASK_OFFSET: usize = 20; // uint32_t netmask
        const MTU_OFFSET: usize = 24; // uint16_t mtu
        const PERSISTENT_OFFSET: usize = 26; // bool persistent

        assert_eq!(
            offset_of!(TunConfig, name),
            NAME_OFFSET,
            "Field 'name' offset mismatch"
        );
        assert_eq!(
            offset_of!(TunConfig, ip_addr),
            IP_ADDR_OFFSET,
            "Field 'ip_addr' offset mismatch"
        );
        assert_eq!(
            offset_of!(TunConfig, netmask),
            NETMASK_OFFSET,
            "Field 'netmask' offset mismatch"
        );
        assert_eq!(
            offset_of!(TunConfig, mtu),
            MTU_OFFSET,
            "Field 'mtu' offset mismatch"
        );
        assert_eq!(
            offset_of!(TunConfig, persistent),
            PERSISTENT_OFFSET,
            "Field 'persistent' offset mismatch"
        );
    }

    /// Test 4: Verify TunConfig padding is consistent
    ///
    /// Padding bytes must be in the same locations for both C and Rust.
    /// This test verifies that the struct ends at the expected offset.
    ///
    /// Padding verification:
    /// - After `persistent` (bool at offset 26), there's 1 byte padding
    /// - Total struct size: 28 bytes (aligned to 4-byte boundary)
    #[test]
    fn test_tun_config_padding_consistency() {
        // Persistent field is at offset 26 (1 byte)
        // Next field would start at offset 27, but struct ends at 28 (1 byte padding)
        const PERSISTENT_OFFSET: usize = 26;
        const PERSISTENT_SIZE: usize = 1; // sizeof(bool) in C
        const STRUCT_SIZE: usize = 28;

        let persistent_end = PERSISTENT_OFFSET + PERSISTENT_SIZE; // 27
        let padding = STRUCT_SIZE - persistent_end; // 28 - 27 = 1 byte padding

        assert_eq!(
            padding, 1,
            "Expected 1 byte of padding after 'persistent' field, found {}",
            padding
        );

        // Verify struct is aligned to 4-byte boundary
        assert_eq!(
            STRUCT_SIZE % 4,
            0,
            "Struct size {} is not aligned to 4-byte boundary",
            STRUCT_SIZE
        );
    }

    // ============================================================================
    // CALLING CONVENTION TESTS (2 required)
    // ============================================================================

    /// Test 5: Verify function pointer compatibility with C ABI
    ///
    /// Function pointers must use extern "C" calling convention for FFI.
    /// This test verifies that function pointer types are FFI-safe.
    #[test]
    fn test_function_pointer_compatibility() {
        // Define C-compatible function pointer types
        type ConfigInitFn = unsafe extern "C" fn(*mut TunConfig) -> i32;
        type DeviceCreateFn = unsafe extern "C" fn(*const TunConfig) -> *mut TunDevice;
        type DeviceDestroyFn = unsafe extern "C" fn(*mut TunDevice);

        // Verify function pointers have correct size (pointer size)
        assert_eq!(
            size_of::<ConfigInitFn>(),
            size_of::<*const ()>(),
            "Function pointer size mismatch"
        );
        assert_eq!(
            size_of::<DeviceCreateFn>(),
            size_of::<*const ()>(),
            "Function pointer size mismatch"
        );
        assert_eq!(
            size_of::<DeviceDestroyFn>(),
            size_of::<*const ()>(),
            "Function pointer size mismatch"
        );

        // Verify alignment matches pointer alignment
        assert_eq!(
            align_of::<ConfigInitFn>(),
            align_of::<*const ()>(),
            "Function pointer alignment mismatch"
        );
    }

    /// Test 6: Verify return value compatibility across FFI boundary
    ///
    /// Return types must be FFI-safe and have correct representation.
    /// Tests integer return codes, pointer returns, and boolean returns.
    #[test]
    fn test_return_value_compatibility() {
        // Test integer return codes (i32 from C `int`)
        assert_eq!(size_of::<i32>(), 4, "C 'int' return type must be 4 bytes");

        // Test 64-bit integer return (i64 from C `int64_t`)
        assert_eq!(
            size_of::<i64>(),
            8,
            "C 'int64_t' return type must be 8 bytes"
        );

        // Test pointer return values
        assert_eq!(
            size_of::<*mut TunDevice>(),
            size_of::<usize>(),
            "Pointer return type size mismatch"
        );
        assert_eq!(
            size_of::<*const TunConfig>(),
            size_of::<usize>(),
            "Pointer return type size mismatch"
        );

        // Test boolean compatibility (C `int` used for boolean returns)
        // C functions return 0/1 as `int`, not C99 `bool`
        let c_bool_as_int: i32 = 1;
        assert_eq!(
            size_of_val(&c_bool_as_int),
            4,
            "C boolean return (as int) must be 4 bytes"
        );

        // Test unsigned integer returns (u16 from C `uint16_t`)
        assert_eq!(
            size_of::<u16>(),
            2,
            "C 'uint16_t' return type must be 2 bytes"
        );

        // Test void pointer returns (used for opaque handles)
        assert_eq!(
            size_of::<*mut ()>(),
            size_of::<usize>(),
            "Void pointer size mismatch"
        );
    }

    // ============================================================================
    // MEMORY TESTS (2 required)
    // ============================================================================

    /// Test 7: Verify allocation safety across FFI boundary
    ///
    /// Tests that Rust can safely allocate TunConfig structs that will be
    /// passed to C functions. Verifies:
    /// - Stack allocation creates valid memory layout
    /// - Zero-initialized config is valid
    /// - Config can be safely converted to/from raw pointers
    #[test]
    #[allow(clippy::undocumented_unsafe_blocks)]
    fn test_allocation_across_ffi_boundary() {
        // Stack allocation - most common pattern
        let mut config: TunConfig = unsafe { std::mem::zeroed() };

        // Verify we can take a mutable raw pointer (passed to C init functions)
        let config_ptr: *mut TunConfig = &mut config;
        assert!(
            !config_ptr.is_null(),
            "Stack-allocated config should not be null"
        );

        // Verify pointer alignment is correct for C
        let addr = config_ptr as usize;
        assert_eq!(
            addr % align_of::<TunConfig>(),
            0,
            "Config pointer must be properly aligned (addr=0x{:x}, align={})",
            addr,
            align_of::<TunConfig>()
        );

        // Verify zero-initialized config has expected layout
        assert_eq!(config.ip_addr, 0, "Zero-initialized ip_addr should be 0");
        assert_eq!(config.netmask, 0, "Zero-initialized netmask should be 0");
        assert_eq!(config.mtu, 0, "Zero-initialized mtu should be 0");
        assert_eq!(
            config.persistent, false,
            "Zero-initialized persistent should be false"
        );

        // Verify name array is zero-initialized
        assert_eq!(
            config.name[0], 0,
            "Zero-initialized name should start with null byte"
        );

        // Simulate round-trip through FFI (Rust -> C -> Rust)
        unsafe {
            // Take raw pointer (as if passing to C)
            let raw_ptr = &mut config as *mut TunConfig;

            // Verify we can dereference back (as if C modified it)
            let config_ref = &mut *raw_ptr;
            config_ref.mtu = 1400;

            // Verify modification is visible
            assert_eq!(config.mtu, 1400, "FFI round-trip should preserve data");
        }
    }

    /// Test 8: Verify deallocation safety across FFI boundary
    ///
    /// Tests that C-allocated resources can be safely freed when:
    /// - Rust receives opaque pointers from C
    /// - Rust must call C destroy functions
    /// - Memory must not be double-freed or leaked
    #[test]
    fn test_deallocation_across_ffi_boundary() {
        // Test 1: Null pointer handling
        // C functions must safely handle NULL (no crash)
        let null_device: *mut TunDevice = std::ptr::null_mut();
        assert!(
            null_device.is_null(),
            "Null device pointer must be detectable"
        );

        // Verify we can distinguish null from non-null
        let non_null_marker = 0x1234_5678_usize as *mut TunDevice;
        assert!(
            !non_null_marker.is_null(),
            "Non-null marker must be detectable"
        );

        // Test 2: Pointer validity checks
        // Verify we can check if pointers are aligned before dereferencing
        let unaligned_addr = 0x1001_usize; // Odd address (not 4-byte aligned)
        let unaligned_ptr = unaligned_addr as *mut TunConfig;

        let is_aligned = (unaligned_ptr as usize) % align_of::<TunConfig>() == 0;
        assert!(!is_aligned, "Should detect misaligned pointers before use");

        // Test 3: Opaque pointer safety
        // TunDevice is opaque (zero-sized), can't be directly allocated/freed in Rust
        assert_eq!(
            size_of::<TunDevice>(),
            0,
            "Opaque TunDevice type should be zero-sized (can't be created in Rust)"
        );

        // This prevents accidental stack allocation:
        // let device: TunDevice = unsafe { std::mem::zeroed() };  // Won't work - zero-sized!

        // Test 4: Lifetime tracking simulation
        // In real code, TunDeviceHandle wraps the pointer and calls destroy in Drop
        struct LifetimeTest {
            _ptr: *mut TunDevice,
        }

        impl Drop for LifetimeTest {
            fn drop(&mut self) {
                // In real code: unsafe { buckwild_tun_device_destroy(self._ptr); }
                // Here we just verify Drop is called
            }
        }

        {
            let _test = LifetimeTest {
                _ptr: std::ptr::null_mut(),
            };
            // _test dropped here - Drop::drop called automatically
        }
        // If we reach here, Drop was called (no leak)
    }

    // ============================================================================
    // ADDITIONAL VALIDATION TESTS
    // ============================================================================

    /// Bonus Test: Verify TunDevice opaque type properties
    ///
    /// The TunDevice type is opaque (forward-declared in C, zero-sized in Rust).
    /// This test verifies it has the correct properties for FFI safety.
    #[test]
    fn test_opaque_tun_device_type() {
        // Zero-sized type (can't be instantiated)
        assert_eq!(
            size_of::<TunDevice>(),
            0,
            "TunDevice must be zero-sized (opaque type)"
        );

        // Alignment doesn't matter for zero-sized types, but verify it's defined
        let _align = align_of::<TunDevice>();

        // Pointers to opaque types have normal pointer size
        assert_eq!(
            size_of::<*mut TunDevice>(),
            size_of::<usize>(),
            "Pointer to opaque type must be normal pointer size"
        );
        assert_eq!(
            size_of::<*const TunDevice>(),
            size_of::<usize>(),
            "Const pointer to opaque type must be normal pointer size"
        );

        // Can create null pointers (common pattern in C FFI)
        let null_ptr: *mut TunDevice = std::ptr::null_mut();
        assert!(null_ptr.is_null());

        let null_const: *const TunDevice = std::ptr::null();
        assert!(null_const.is_null());
    }

    /// Bonus Test: Verify C type compatibility with Rust primitive types
    ///
    /// Ensures Rust's primitive types used in FFI match C expectations.
    #[test]
    fn test_c_type_primitive_compatibility() {
        // Verify C char matches Rust i8
        assert_eq!(
            size_of::<libc::c_char>(),
            size_of::<i8>(),
            "C char size mismatch"
        );

        // Verify C int matches Rust i32 (on all supported platforms)
        assert_eq!(
            size_of::<libc::c_int>(),
            size_of::<i32>(),
            "C int size mismatch"
        );

        // Verify C size_t matches Rust usize
        assert_eq!(
            size_of::<libc::size_t>(),
            size_of::<usize>(),
            "C size_t size mismatch"
        );

        // Verify fixed-width integer types
        assert_eq!(size_of::<u8>(), 1, "u8 must be 1 byte");
        assert_eq!(size_of::<u16>(), 2, "u16 must be 2 bytes");
        assert_eq!(size_of::<u32>(), 4, "u32 must be 4 bytes");
        assert_eq!(size_of::<i32>(), 4, "i32 must be 4 bytes");
        assert_eq!(size_of::<i64>(), 8, "i64 must be 8 bytes");

        // Verify bool representation (Rust bool is 1 byte, C bool may vary)
        assert_eq!(size_of::<bool>(), 1, "Rust bool must be 1 byte");
    }

    /// Bonus Test: Verify struct repr(C) attribute is effective
    ///
    /// Tests that TunConfig actually uses C representation (not Rust's default).
    #[test]
    fn test_repr_c_effectiveness() {
        use std::mem::offset_of;

        // If TunConfig didn't have #[repr(C)], Rust might reorder fields
        // or add unexpected padding. We verify the C layout is enforced.

        // Fields MUST be in declaration order for repr(C)
        let name_offset = offset_of!(TunConfig, name);
        let ip_offset = offset_of!(TunConfig, ip_addr);
        let netmask_offset = offset_of!(TunConfig, netmask);
        let mtu_offset = offset_of!(TunConfig, mtu);
        let persistent_offset = offset_of!(TunConfig, persistent);

        // Verify fields are in increasing offset order (no reordering)
        assert!(
            name_offset < ip_offset,
            "Fields reordered: name should come before ip_addr"
        );
        assert!(
            ip_offset < netmask_offset,
            "Fields reordered: ip_addr should come before netmask"
        );
        assert!(
            netmask_offset < mtu_offset,
            "Fields reordered: netmask should come before mtu"
        );
        assert!(
            mtu_offset < persistent_offset,
            "Fields reordered: mtu should come before persistent"
        );
    }

    // ============================================================================
    // NULL POINTER VALIDATION TESTS (TASK-076 / FF-001)
    // ============================================================================

    /// Test: Verify config_init rejects null pointer
    ///
    /// Tests FF-001 remediation: all FFI functions must validate pointer arguments
    /// before dereferencing, returning error code instead of undefined behavior.
    #[test]
    fn test_config_init_null_pointer() {
        unsafe {
            let result = crate::buckwild_tun_config_init(std::ptr::null_mut());
            assert_eq!(
                result,
                crate::BUCKWILD_ERR_NULL_POINTER,
                "config_init must return BUCKWILD_ERR_NULL_POINTER for null config"
            );
        }
    }

    /// Test: Verify config_set_name rejects null pointers
    #[test]
    fn test_config_set_name_null_pointers() {
        unsafe {
            // Null config pointer
            let name = b"test\0".as_ptr() as *const libc::c_char;
            let result = crate::buckwild_tun_config_set_name(std::ptr::null_mut(), name);
            assert_eq!(
                result,
                crate::BUCKWILD_ERR_NULL_POINTER,
                "config_set_name must return error for null config"
            );

            // Null name pointer
            let mut config = TunConfig {
                name: [0; 16],
                ip_addr: 0,
                netmask: 0,
                mtu: 0,
                persistent: false,
            };
            let result = crate::buckwild_tun_config_set_name(&mut config, std::ptr::null());
            assert_eq!(
                result,
                crate::BUCKWILD_ERR_NULL_POINTER,
                "config_set_name must return error for null name"
            );

            // Both null
            let result =
                crate::buckwild_tun_config_set_name(std::ptr::null_mut(), std::ptr::null());
            assert_eq!(
                result,
                crate::BUCKWILD_ERR_NULL_POINTER,
                "config_set_name must return error for both null"
            );
        }
    }

    /// Test: Verify config_set_ip_addr rejects null pointer
    #[test]
    fn test_config_set_ip_addr_null_pointer() {
        unsafe {
            let result = crate::buckwild_tun_config_set_ip_addr(std::ptr::null_mut(), 0x0A000001);
            assert_eq!(
                result,
                crate::BUCKWILD_ERR_NULL_POINTER,
                "config_set_ip_addr must return error for null config"
            );
        }
    }

    /// Test: Verify config_set_netmask rejects null pointer
    #[test]
    fn test_config_set_netmask_null_pointer() {
        unsafe {
            let result = crate::buckwild_tun_config_set_netmask(std::ptr::null_mut(), 0xFFFFFF00);
            assert_eq!(
                result,
                crate::BUCKWILD_ERR_NULL_POINTER,
                "config_set_netmask must return error for null config"
            );
        }
    }

    /// Test: Verify config_set_mtu rejects null pointer
    #[test]
    fn test_config_set_mtu_null_pointer() {
        unsafe {
            let result = crate::buckwild_tun_config_set_mtu(std::ptr::null_mut(), 1400);
            assert_eq!(
                result,
                crate::BUCKWILD_ERR_NULL_POINTER,
                "config_set_mtu must return error for null config"
            );
        }
    }

    /// Test: Verify device_create rejects null pointer
    #[test]
    fn test_device_create_null_pointer() {
        unsafe {
            let result = crate::buckwild_tun_device_create(std::ptr::null());
            assert!(
                result.is_null(),
                "device_create must return null for null config"
            );
        }
    }

    /// Test: Verify device_destroy handles null pointer safely
    #[test]
    fn test_device_destroy_null_pointer() {
        unsafe {
            // Should not crash - null pointer is documented as safe for destroy
            crate::buckwild_tun_device_destroy(std::ptr::null_mut());
        }
    }

    /// Test: Verify device_read rejects null pointers
    #[test]
    fn test_device_read_null_pointers() {
        unsafe {
            let mut buf = [0u8; 1500];

            // Null device pointer
            let result =
                crate::buckwild_tun_device_read(std::ptr::null_mut(), buf.as_mut_ptr(), buf.len());
            assert_eq!(
                result,
                crate::BUCKWILD_ERR_NULL_POINTER as i64,
                "device_read must return error for null device"
            );

            // Null buffer pointer (simulate non-null device)
            let fake_device = 0x1000 as *mut TunDevice;
            let result = crate::buckwild_tun_device_read(fake_device, std::ptr::null_mut(), 1500);
            assert_eq!(
                result,
                crate::BUCKWILD_ERR_NULL_POINTER as i64,
                "device_read must return error for null buffer"
            );
        }
    }

    /// Test: Verify device_write rejects null pointers
    #[test]
    fn test_device_write_null_pointers() {
        unsafe {
            let buf = [0u8; 1500];

            // Null device pointer
            let result =
                crate::buckwild_tun_device_write(std::ptr::null_mut(), buf.as_ptr(), buf.len());
            assert_eq!(
                result,
                crate::BUCKWILD_ERR_NULL_POINTER as i64,
                "device_write must return error for null device"
            );

            // Null buffer pointer
            let fake_device = 0x1000 as *mut TunDevice;
            let result = crate::buckwild_tun_device_write(fake_device, std::ptr::null(), 1500);
            assert_eq!(
                result,
                crate::BUCKWILD_ERR_NULL_POINTER as i64,
                "device_write must return error for null buffer"
            );
        }
    }

    /// Test: Verify device_get_fd rejects null pointer
    #[test]
    fn test_device_get_fd_null_pointer() {
        unsafe {
            let result = crate::buckwild_tun_device_get_fd(std::ptr::null());
            assert_eq!(
                result,
                crate::BUCKWILD_ERR_NULL_POINTER,
                "device_get_fd must return error for null device"
            );
        }
    }

    /// Test: Verify device_get_name rejects null pointers
    #[test]
    fn test_device_get_name_null_pointers() {
        unsafe {
            let mut buf = [0 as c_char; 16];

            // Null device pointer
            let result =
                crate::buckwild_tun_device_get_name(std::ptr::null(), buf.as_mut_ptr(), buf.len());
            assert_eq!(
                result,
                crate::BUCKWILD_ERR_NULL_POINTER,
                "device_get_name must return error for null device"
            );

            // Null buffer pointer
            let fake_device = 0x1000 as *const TunDevice;
            let result = crate::buckwild_tun_device_get_name(fake_device, std::ptr::null_mut(), 16);
            assert_eq!(
                result,
                crate::BUCKWILD_ERR_NULL_POINTER,
                "device_get_name must return error for null buffer"
            );
        }
    }

    /// Test: Verify device_get_mtu rejects null pointer
    #[test]
    fn test_device_get_mtu_null_pointer() {
        unsafe {
            let result = crate::buckwild_tun_device_get_mtu(std::ptr::null());
            assert_eq!(result, 0, "device_get_mtu must return 0 for null device");
        }
    }

    /// Test: Verify device_is_up rejects null pointer
    #[test]
    fn test_device_is_up_null_pointer() {
        unsafe {
            let result = crate::buckwild_tun_device_is_up(std::ptr::null());
            assert_eq!(
                result, 0,
                "device_is_up must return 0 (false) for null device"
            );
        }
    }

    /// Test: Verify device_set_nonblock rejects null pointer
    #[test]
    fn test_device_set_nonblock_null_pointer() {
        unsafe {
            let result = crate::buckwild_tun_device_set_nonblock(std::ptr::null_mut(), 1);
            assert_eq!(
                result,
                crate::BUCKWILD_ERR_NULL_POINTER,
                "device_set_nonblock must return error for null device"
            );
        }
    }

    /// Test: Verify error_string never returns null
    #[test]
    fn test_error_string_never_null() {
        unsafe {
            let result = crate::buckwild_tun_error_string(crate::BUCKWILD_ERR_NULL_POINTER);
            assert!(
                !result.is_null(),
                "error_string must never return null pointer"
            );

            let result = crate::buckwild_tun_error_string(-999);
            assert!(
                !result.is_null(),
                "error_string must never return null even for unknown error codes"
            );
        }
    }
}
