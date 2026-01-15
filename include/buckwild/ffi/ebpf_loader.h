/**
 * @file ebpf_loader.h
 * @brief eBPF program loader FFI for XDP/TC program lifecycle management
 *
 * This header provides C FFI bindings for loading, attaching, and managing
 * eBPF programs (XDP and TC) from userspace. It exposes the Rust eBPF loader
 * functionality to C code.
 *
 * ## Memory Ownership
 *
 * - Opaque handles (BuckwildEbpfLoader*) are owned by caller after creation
 * - Caller must call buckwild_ebpf_loader_destroy() to free
 * - String parameters (interface, path) are borrowed - caller retains ownership
 * - Map keys/values are copied - caller retains ownership of buffers
 *
 * ## Thread Safety
 *
 * - BuckwildEbpfLoader is NOT thread-safe - caller must synchronize
 * - Map operations use internal locking and are thread-safe
 *
 * FFI-SAFE: All types use C-compatible representations
 * PLATFORM: Linux only (eBPF requires Linux kernel)
 */

#ifndef BUCKWILD_FFI_EBPF_LOADER_H
#define BUCKWILD_FFI_EBPF_LOADER_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Opaque handle to eBPF loader instance
 *
 * Represents the Rust EbpfLoader struct. Must be created with
 * buckwild_ebpf_loader_create() and destroyed with
 * buckwild_ebpf_loader_destroy().
 */
typedef struct BuckwildEbpfLoader BuckwildEbpfLoader;

/**
 * eBPF program type
 */
typedef enum {
	/** XDP (eXpress Data Path) program - ingress packet processing */
	BUCKWILD_EBPF_TYPE_XDP = 0,
	/** TC (Traffic Control) egress program - egress packet processing */
	BUCKWILD_EBPF_TYPE_TC_EGRESS = 1,
	/** TC ingress program - ingress packet processing */
	BUCKWILD_EBPF_TYPE_TC_INGRESS = 2,
} BuckwildEbpfType;

/**
 * eBPF attachment mode for XDP
 */
typedef enum {
	/** SKB mode - slower, compatible with all drivers */
	BUCKWILD_XDP_MODE_SKB = 0,
	/** Native mode - faster, requires driver support */
	BUCKWILD_XDP_MODE_NATIVE = 1,
	/** Offload mode - hardware offload, requires NIC support */
	BUCKWILD_XDP_MODE_OFFLOAD = 2,
} BuckwildXdpMode;

/**
 * buckwild_ebpf_loader_create() - Create eBPF loader instance
 *
 * Creates a new eBPF loader for managing XDP and TC programs.
 * The loader must be destroyed with buckwild_ebpf_loader_destroy().
 *
 * Return: Pointer result containing loader handle or error
 *
 * Errors:
 * - BUCKWILD_ERR_OUT_OF_MEMORY: Failed to allocate loader
 * - BUCKWILD_ERR_EBPF_NOT_SUPPORTED: Platform lacks eBPF support
 */
BuckwildPtrResult buckwild_ebpf_loader_create(void);

/**
 * buckwild_ebpf_loader_destroy() - Destroy eBPF loader instance
 * @loader: Loader handle from buckwild_ebpf_loader_create()
 *
 * Frees all resources associated with the loader. After this call,
 * the loader handle is invalid and must not be used.
 *
 * If programs are still attached, they will be detached automatically.
 * If the loader pointer is NULL, this is a no-op.
 */
void buckwild_ebpf_loader_destroy(BuckwildEbpfLoader *loader);

/**
 * buckwild_ebpf_load() - Load eBPF program from file
 * @loader: Loader instance
 * @prog_type: Program type (XDP or TC)
 * @path: Path to eBPF object file (.o)
 *
 * Loads an eBPF program from a compiled object file. The file must
 * be a valid ELF object containing eBPF bytecode that passes the
 * kernel verifier.
 *
 * The program is loaded but not attached. Use buckwild_ebpf_attach()
 * to attach to a network interface.
 *
 * Return: BUCKWILD_OK on success, error code on failure
 *
 * Errors:
 * - BUCKWILD_ERR_NULL_POINTER: loader or path is NULL
 * - BUCKWILD_ERR_CONFIG_FILE_NOT_FOUND: Object file does not exist
 * - BUCKWILD_ERR_EBPF_VERIFICATION_FAILED: Kernel verifier rejected program
 * - BUCKWILD_ERR_EBPF_LOAD_FAILED: Failed to load program
 * - BUCKWILD_ERR_PERMISSION_DENIED: Insufficient privileges (needs CAP_BPF or CAP_SYS_ADMIN)
 */
BuckwildError buckwild_ebpf_load(
	BuckwildEbpfLoader *loader,
	BuckwildEbpfType prog_type,
	const char *path
);

/**
 * buckwild_ebpf_load_from_memory() - Load eBPF program from memory buffer
 * @loader: Loader instance
 * @prog_type: Program type (XDP or TC)
 * @data: Pointer to eBPF object data
 * @data_len: Length of data buffer in bytes
 *
 * Loads an eBPF program from an in-memory buffer containing a compiled
 * eBPF object file. Useful for embedded programs or programs generated
 * at runtime.
 *
 * Return: BUCKWILD_OK on success, error code on failure
 *
 * Errors:
 * - BUCKWILD_ERR_NULL_POINTER: loader or data is NULL
 * - BUCKWILD_ERR_INVALID_ARGUMENT: data_len is 0
 * - BUCKWILD_ERR_EBPF_VERIFICATION_FAILED: Kernel verifier rejected program
 * - BUCKWILD_ERR_EBPF_LOAD_FAILED: Failed to load program
 */
BuckwildError buckwild_ebpf_load_from_memory(
	BuckwildEbpfLoader *loader,
	BuckwildEbpfType prog_type,
	const uint8_t *data,
	size_t data_len
);

/**
 * buckwild_ebpf_unload() - Unload eBPF program
 * @loader: Loader instance
 * @prog_type: Program type to unload
 *
 * Unloads a previously loaded eBPF program. If the program is attached
 * to an interface, it will be detached first.
 *
 * Return: BUCKWILD_OK on success, error code on failure
 *
 * Errors:
 * - BUCKWILD_ERR_NULL_POINTER: loader is NULL
 * - BUCKWILD_ERR_EBPF_PROGRAM_NOT_FOUND: No program of this type loaded
 */
BuckwildError buckwild_ebpf_unload(
	BuckwildEbpfLoader *loader,
	BuckwildEbpfType prog_type
);

/**
 * buckwild_ebpf_attach_xdp() - Attach XDP program to interface
 * @loader: Loader instance
 * @interface: Network interface name (e.g., "eth0", "lo")
 * @mode: XDP attachment mode
 *
 * Attaches a loaded XDP program to the specified network interface.
 * The program must have been loaded with buckwild_ebpf_load() first.
 *
 * XDP modes (in order of performance):
 * - OFFLOAD: Hardware offload (requires NIC support)
 * - NATIVE: Driver-level hook (requires driver support)
 * - SKB: Generic kernel hook (works with all drivers, slower)
 *
 * If a program is already attached to another interface, it will be
 * detached first.
 *
 * Return: BUCKWILD_OK on success, error code on failure
 *
 * Errors:
 * - BUCKWILD_ERR_NULL_POINTER: loader or interface is NULL
 * - BUCKWILD_ERR_EBPF_PROGRAM_NOT_FOUND: No XDP program loaded
 * - BUCKWILD_ERR_INTERFACE_NOT_FOUND: Network interface does not exist
 * - BUCKWILD_ERR_EBPF_ATTACH_FAILED: Failed to attach to interface
 * - BUCKWILD_ERR_PERMISSION_DENIED: Insufficient privileges
 * - BUCKWILD_ERR_NOT_SUPPORTED: XDP mode not supported by driver/NIC
 */
BuckwildError buckwild_ebpf_attach_xdp(
	BuckwildEbpfLoader *loader,
	const char *interface,
	BuckwildXdpMode mode
);

/**
 * buckwild_ebpf_attach_tc() - Attach TC program to interface
 * @loader: Loader instance
 * @interface: Network interface name
 * @prog_type: TC program type (egress or ingress)
 *
 * Attaches a loaded TC program to the specified network interface.
 * The program must have been loaded with buckwild_ebpf_load() first.
 *
 * TC programs can be attached to:
 * - Egress path (BUCKWILD_EBPF_TYPE_TC_EGRESS)
 * - Ingress path (BUCKWILD_EBPF_TYPE_TC_INGRESS)
 *
 * Return: BUCKWILD_OK on success, error code on failure
 *
 * Errors:
 * - BUCKWILD_ERR_NULL_POINTER: loader or interface is NULL
 * - BUCKWILD_ERR_INVALID_ARGUMENT: prog_type is not a TC type
 * - BUCKWILD_ERR_EBPF_PROGRAM_NOT_FOUND: No TC program loaded
 * - BUCKWILD_ERR_INTERFACE_NOT_FOUND: Network interface does not exist
 * - BUCKWILD_ERR_EBPF_ATTACH_FAILED: Failed to attach to interface
 * - BUCKWILD_ERR_PERMISSION_DENIED: Insufficient privileges
 */
BuckwildError buckwild_ebpf_attach_tc(
	BuckwildEbpfLoader *loader,
	const char *interface,
	BuckwildEbpfType prog_type
);

/**
 * buckwild_ebpf_detach_xdp() - Detach XDP program from interface
 * @loader: Loader instance
 * @interface: Network interface name
 *
 * Detaches the XDP program from the specified interface. The program
 * remains loaded and can be re-attached.
 *
 * Return: BUCKWILD_OK on success, error code on failure
 *
 * Errors:
 * - BUCKWILD_ERR_NULL_POINTER: loader or interface is NULL
 * - BUCKWILD_ERR_EBPF_DETACH_FAILED: Program not attached to this interface
 */
BuckwildError buckwild_ebpf_detach_xdp(
	BuckwildEbpfLoader *loader,
	const char *interface
);

/**
 * buckwild_ebpf_detach_tc() - Detach TC program from interface
 * @loader: Loader instance
 * @interface: Network interface name
 * @prog_type: TC program type (egress or ingress)
 *
 * Detaches the TC program from the specified interface. The program
 * remains loaded and can be re-attached.
 *
 * Return: BUCKWILD_OK on success, error code on failure
 *
 * Errors:
 * - BUCKWILD_ERR_NULL_POINTER: loader or interface is NULL
 * - BUCKWILD_ERR_INVALID_ARGUMENT: prog_type is not a TC type
 * - BUCKWILD_ERR_EBPF_DETACH_FAILED: Program not attached to this interface
 */
BuckwildError buckwild_ebpf_detach_tc(
	BuckwildEbpfLoader *loader,
	const char *interface,
	BuckwildEbpfType prog_type
);

/**
 * buckwild_ebpf_map_lookup() - Look up value in eBPF map
 * @loader: Loader instance
 * @map_name: Name of the map (e.g., "port_validity_map")
 * @key: Pointer to key data
 * @key_size: Size of key in bytes
 * @value: Pointer to buffer for value data (output)
 * @value_size: Size of value buffer in bytes
 *
 * Looks up a key in an eBPF map and copies the value to the provided buffer.
 * The key and value sizes must match the map definition.
 *
 * The map must exist in one of the loaded eBPF programs.
 *
 * Return: BUCKWILD_OK on success, error code on failure
 *
 * Errors:
 * - BUCKWILD_ERR_NULL_POINTER: loader, map_name, key, or value is NULL
 * - BUCKWILD_ERR_EBPF_MAP_NOT_FOUND: No map with this name in loaded programs
 * - BUCKWILD_ERR_INVALID_ARGUMENT: key_size or value_size mismatch
 * - BUCKWILD_ERR_EBPF_MAP_OPERATION_FAILED: Key not found in map
 */
BuckwildError buckwild_ebpf_map_lookup(
	BuckwildEbpfLoader *loader,
	const char *map_name,
	const void *key,
	size_t key_size,
	void *value,
	size_t value_size
);

/**
 * buckwild_ebpf_map_update() - Update or insert value in eBPF map
 * @loader: Loader instance
 * @map_name: Name of the map
 * @key: Pointer to key data
 * @key_size: Size of key in bytes
 * @value: Pointer to value data
 * @value_size: Size of value in bytes
 * @flags: Update flags (0 for upsert, 1 for insert-only, 2 for update-only)
 *
 * Updates or inserts a key-value pair in an eBPF map.
 *
 * Flags:
 * - 0 (BPF_ANY): Create or update entry
 * - 1 (BPF_NOEXIST): Create entry only if it doesn't exist
 * - 2 (BPF_EXIST): Update entry only if it exists
 *
 * Return: BUCKWILD_OK on success, error code on failure
 *
 * Errors:
 * - BUCKWILD_ERR_NULL_POINTER: loader, map_name, key, or value is NULL
 * - BUCKWILD_ERR_EBPF_MAP_NOT_FOUND: No map with this name
 * - BUCKWILD_ERR_INVALID_ARGUMENT: Size mismatch or invalid flags
 * - BUCKWILD_ERR_EBPF_MAP_OPERATION_FAILED: Operation failed (e.g., key exists with BPF_NOEXIST)
 */
BuckwildError buckwild_ebpf_map_update(
	BuckwildEbpfLoader *loader,
	const char *map_name,
	const void *key,
	size_t key_size,
	const void *value,
	size_t value_size,
	uint64_t flags
);

/**
 * buckwild_ebpf_map_delete() - Delete entry from eBPF map
 * @loader: Loader instance
 * @map_name: Name of the map
 * @key: Pointer to key data
 * @key_size: Size of key in bytes
 *
 * Deletes a key-value pair from an eBPF map.
 *
 * Return: BUCKWILD_OK on success, error code on failure
 *
 * Errors:
 * - BUCKWILD_ERR_NULL_POINTER: loader, map_name, or key is NULL
 * - BUCKWILD_ERR_EBPF_MAP_NOT_FOUND: No map with this name
 * - BUCKWILD_ERR_INVALID_ARGUMENT: key_size mismatch
 * - BUCKWILD_ERR_EBPF_MAP_OPERATION_FAILED: Key not found
 */
BuckwildError buckwild_ebpf_map_delete(
	BuckwildEbpfLoader *loader,
	const char *map_name,
	const void *key,
	size_t key_size
);

/**
 * buckwild_ebpf_map_get_next_key() - Get next key in eBPF map (for iteration)
 * @loader: Loader instance
 * @map_name: Name of the map
 * @key: Pointer to current key (NULL to get first key)
 * @key_size: Size of key in bytes
 * @next_key: Pointer to buffer for next key (output)
 *
 * Gets the next key in an eBPF map for iteration. Pass NULL for key
 * to get the first key. When there are no more keys, returns
 * BUCKWILD_ERR_EBPF_MAP_OPERATION_FAILED.
 *
 * Usage pattern:
 *   uint32_t key, next_key;
 *   uint32_t *current = NULL;
 *   while (buckwild_ebpf_map_get_next_key(loader, "map", current, sizeof(key), &next_key) == BUCKWILD_OK) {
 *       // Process next_key
 *       key = next_key;
 *       current = &key;
 *   }
 *
 * Return: BUCKWILD_OK on success, error code on failure
 *
 * Errors:
 * - BUCKWILD_ERR_NULL_POINTER: loader, map_name, or next_key is NULL
 * - BUCKWILD_ERR_EBPF_MAP_NOT_FOUND: No map with this name
 * - BUCKWILD_ERR_EBPF_MAP_OPERATION_FAILED: No more keys (end of iteration)
 */
BuckwildError buckwild_ebpf_map_get_next_key(
	BuckwildEbpfLoader *loader,
	const char *map_name,
	const void *key,
	size_t key_size,
	void *next_key
);

/**
 * buckwild_ebpf_get_program_fd() - Get file descriptor for loaded program
 * @loader: Loader instance
 * @prog_type: Program type
 *
 * Returns the file descriptor for a loaded eBPF program. The FD can be
 * used for advanced operations like pinning or program introspection.
 *
 * The returned FD is owned by the loader and remains valid until the
 * program is unloaded or the loader is destroyed.
 *
 * Return: Result containing FD (>= 0) on success, error on failure
 *
 * Errors:
 * - BUCKWILD_ERR_NULL_POINTER: loader is NULL
 * - BUCKWILD_ERR_EBPF_PROGRAM_NOT_FOUND: No program of this type loaded
 */
BuckwildResult buckwild_ebpf_get_program_fd(
	BuckwildEbpfLoader *loader,
	BuckwildEbpfType prog_type
);

/**
 * buckwild_ebpf_get_map_fd() - Get file descriptor for map
 * @loader: Loader instance
 * @map_name: Name of the map
 *
 * Returns the file descriptor for an eBPF map. The FD can be used
 * for advanced operations like pinning or sharing with other programs.
 *
 * The returned FD is owned by the loader and remains valid until the
 * program containing the map is unloaded.
 *
 * Return: Result containing FD (>= 0) on success, error on failure
 *
 * Errors:
 * - BUCKWILD_ERR_NULL_POINTER: loader or map_name is NULL
 * - BUCKWILD_ERR_EBPF_MAP_NOT_FOUND: No map with this name
 */
BuckwildResult buckwild_ebpf_get_map_fd(
	BuckwildEbpfLoader *loader,
	const char *map_name
);

#ifdef __cplusplus
}
#endif

#endif /* BUCKWILD_FFI_EBPF_LOADER_H */
