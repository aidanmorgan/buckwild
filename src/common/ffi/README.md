# buckwild-ffi

FFI bindings for C TUN device implementation with safe Rust wrappers.

## Architecture

```
┌─────────────────────────────────────────┐
│         Rust Application Code           │
│    (daemon, routing manager, etc.)      │
└─────────────────┬───────────────────────┘
                  │
         ┌────────▼────────┐
         │  TunDeviceHandle │  ← Safe RAII wrapper
         │   (tun.rs)       │
         └────────┬─────────┘
                  │ &mut self enforces exclusive access
         ┌────────▼─────────┐
         │  Raw FFI (unsafe) │  ← extern "C" declarations
         │    (lib.rs)        │
         └────────┬──────────┘
                  │ C ABI boundary
         ┌────────▼─────────────────────┐
         │  libbuckwild_network.so      │  ← C implementation
         │  (src/common/c/network/)     │
         └──────────────────────────────┘
```

## Design Decisions

### Why FFI Instead of Pure Rust TUN

**Choice:** Use C TUN code via FFI rather than pure Rust implementation (rtnetlink).

**Why:**
- C implementation is well-tested with stable ioctl interface
- rtnetlink duplication increases maintenance burden
- FFI provides safe wrappers without code duplication
- ioctl syscall cost (~1μs) dominates FFI call overhead (~10ns)

**Rejected alternatives:**
- Pure Rust rtnetlink: Duplicates C code, increases testing surface
- External `tun` crate: Pins specific rtnetlink version causing dependency conflicts, divergent configuration from C code

### Dynamic Linking Strategy

**Choice:** Dynamic linking to `libbuckwild_network.so` instead of static linking.

**Why:**
- C TUN may need updates for kernel API changes
- Static linking requires full Rust recompilation on C changes
- Dynamic linking allows independent updates
- Runtime loading uses standard library search path

**Build verification:** `build.rs` verifies library is present at compile time to catch missing dependencies early.

### Ownership Model: Single-Owner RAII

**Design:** `TunDeviceHandle` exclusively owns `*mut TunDevice` pointer from C.

**Invariants:**
- One Rust handle per C TUN device (enforced by C returning NULL on EEXIST)
- `Drop` impl calls `buckwild_tun_device_destroy()` even on panic
- No `Clone` impl - ownership cannot be shared

**Why:** Prevents double-free (multiple `Drop` calls on same pointer) and use-after-free (accessing destroyed C object).

### Thread Safety: Send but !Sync

**Design:** `TunDeviceHandle` is `Send` but not `Sync`.

**Why Send is safe:**
- Each `TunDevice` has its own file descriptor (per-device state, not global)
- Linux kernel file descriptor operations (read/write/ioctl) are thread-safe
- Ownership is exclusive (no `Clone` impl)
- Enables use with `tokio::spawn_blocking` for async I/O

**Why NOT Sync:**
- C code doesn't provide internal synchronization for concurrent access
- All methods require `&mut self` to enforce exclusive access via borrow checker
- Prevents data races at compile time

**Implementation:** `unsafe impl Send` with safety documentation explaining the invariants.

**Enforcement:** All methods take `&mut self` to require exclusive borrow, preventing concurrent access.

### Memory Safety Guarantees

**1. FD Validation Before I/O**

**Problem:** C TUN fd can be closed externally (kernel resource limits, admin intervention).

**Solution:** `read()` and `write()` validate fd with `fcntl(F_GETFL)` before calling C code.

**Why:** Reading closed fd has undefined behavior in C; explicit check returns typed `TunError::DeviceClosed`.

**2. NULL Pointer Checks**

**Pattern:** All C FFI calls that return pointers are checked for NULL before dereferencing.

```rust
let ptr = unsafe { buckwild_tun_device_create(...) };
if ptr.is_null() {
    // Convert errno to typed error
    return Err(match errno {
        EEXIST => TunError::DeviceExists,
        _ => TunError::CreateFailed,
    });
}
```

**3. Buffer Bounds**

**Pattern:** Rust slices (`&[u8]`, `&mut [u8]`) provide length to C functions, preventing overruns.

```rust
unsafe {
    buckwild_tun_device_read(
        self.inner,
        buf.as_mut_ptr(),  // Pointer
        buf.len()          // Length - C code cannot exceed
    )
}
```

### Newtype Pattern for IP Addresses

**Design:** `TunIpAddr` and `PeerTunIp` newtypes distinguish TUN interface IPs from Docker/peer IPs.

**Problem prevented:**
- Passing peer's Docker IP (`172.30.0.x`) where TUN IP (`10.0.0.x`) expected
- Routing local TUN IP through TUN interface (creates loop)

**Why:** Type system prevents category errors that would cause runtime failures.

### Error Handling with thiserror

**Choice:** Use `thiserror` crate for error types.

**Why:**
- Derives `Error` trait boilerplate
- Provides `#[from]` for error conversion
- Consistent with project's layered error handling (design/rules.md)

**Error categories:**
- `DeviceClosed`: fd invalidated externally
- `DeviceExists`: Name collision (EEXIST)
- `InvalidName`: Validation failure before FFI call
- `IoError`: Propagated from std::io
- `FfiError`: C function returned error code

### Linking Strategy

**Dynamic Library Search:**

1. `build.rs` verifies `libbuckwild_network.so` exists at compile time
2. Runtime uses standard search path (`LD_LIBRARY_PATH`, `/usr/lib`, etc.)
3. No `rpath` - allows deployment flexibility

**Why:** Daemon may be deployed where C library is in non-standard location; standard search allows override via environment.

## Usage Patterns

### Creating TUN Device

```rust
use buckwild_ffi::{TunDeviceHandle, TunIpAddr};

let ip = TunIpAddr::new("10.0.0.1".parse()?);
let netmask = "255.255.255.0".parse()?;

// RAII: handle owns device, Drop ensures cleanup
let mut handle = TunDeviceHandle::create("bw0", ip, netmask, 1400)?;
```

### Reading Packets (Non-blocking)

```rust
let mut buf = [0u8; 2048];

match handle.read(&mut buf) {
    Ok(n) => process_packet(&buf[..n]),
    Err(TunError::IoError(e)) if e.kind() == ErrorKind::WouldBlock => {
        // No packet available - poll again later
    }
    Err(TunError::DeviceClosed) => {
        // fd invalidated - recreate device or fail
    }
    Err(e) => return Err(e),
}
```

### Writing Packets

```rust
let packet = build_ip_packet(...);

match handle.write(&packet) {
    Ok(n) => assert_eq!(n, packet.len()),  // Atomic write
    Err(TunError::DeviceClosed) => {
        // Handle fd invalidation
    }
    Err(e) => return Err(e),
}
```

### Integration with Event Loop

```rust
use mio::{Events, Interest, Poll, Token};

let mut poll = Poll::new()?;
let mut events = Events::with_capacity(128);

// Register TUN fd for read readiness
poll.registry().register(
    &mut SourceFd(&handle.fd()),
    Token(0),
    Interest::READABLE,
)?;

loop {
    poll.poll(&mut events, None)?;
    for event in &events {
        if event.token() == Token(0) {
            // TUN fd readable - call handle.read()
        }
    }
}
```

## Testing

### Unit Tests

- `test_create_device`: Verify device creation (requires CAP_NET_ADMIN)
- `test_drop_cleanup`: RAII cleanup removes device
- `test_double_create_fails`: DeviceExists error on name collision
- `test_fd_validation`: Invalid fd returns DeviceClosed error

### Integration Tests

- `test_loopback_packet`: Write then read packet
- `test_nonblocking_read`: WouldBlock on empty device

**CI Requirements:** Tests requiring CAP_NET_ADMIN run in Docker with `--cap-add=NET_ADMIN`.

## Known Limitations

### No Concurrent Access (Not Sync)

`TunDeviceHandle` is `Send` but not `Sync` - it can be moved between threads but cannot be accessed concurrently.

**Safe usage patterns:**
- ✅ Move to another thread: `tokio::spawn_blocking(move || { handle.read(...) })`
- ✅ Single-threaded async I/O: `tokio` or `async-std` with single task ownership
- ❌ Shared reference across threads: `Arc<TunDeviceHandle>` won't compile (not `Sync`)

**Workaround for shared access:** Wrap in `Arc<Mutex<TunDeviceHandle>>` if multiple threads need access (adds synchronization overhead).

### Platform: Linux Only

C TUN implementation uses Linux `ioctl(TUNSETIFF)`. macOS/BSD use different APIs.

**Future:** Could add platform-specific FFI modules (`tun_linux.rs`, `tun_macos.rs`) with common trait.

### IPv4 Only

Current implementation does not handle IPv6 packets or configuration.

**Extension point:** Add `Ipv6Addr` variants to `TunIpAddr`, update C signatures to pass AF_INET6.

## Performance

**FFI call overhead:** ~10 nanoseconds per call on modern x86_64.

**ioctl syscall cost:** ~1 microsecond per TUN read/write.

**Conclusion:** FFI overhead is negligible (1% of ioctl cost). Bottleneck is syscall boundary, not FFI.

**Measurement:** `cargo bench ffi_overhead` (requires `criterion` feature).

## Security Considerations

### Privilege Escalation

TUN device creation requires `CAP_NET_ADMIN` capability.

**Daemon strategy:**
1. Start with `CAP_NET_ADMIN`
2. Create TUN device via FFI
3. Drop `CAP_NET_ADMIN` after device created
4. Continue with minimal privileges

**Why:** Principle of least privilege - daemon does not need elevated privileges after initialization.

### FD Hijacking

If attacker closes TUN fd externally, subsequent reads/writes could target different fd (if kernel reuses fd number).

**Mitigation:** `fcntl(F_GETFL)` validation returns error instead of operating on wrong fd.

### Memory Disclosure

C TUN code does not zero buffers after read.

**Mitigation:** Rust wrapper provides fresh `&mut [u8]` slice, preventing reuse of uninitialized memory.

## References

- C TUN implementation: `src/common/c/network/`
- Design documentation: `design/architecture.md`
- Daemon integration: `src/daemon/rust/src/tun/`
