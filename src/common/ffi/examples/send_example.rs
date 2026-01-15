//! Example demonstrating that TunDeviceHandle is Send
//! and can be used with tokio::spawn_blocking

use buckwild_ffi::tun::TunDeviceHandle;

fn main() {
    // This example demonstrates compile-time verification that
    // TunDeviceHandle can be sent between threads.

    // This function requires T: Send
    fn assert_send<T: Send>(_: T) {}

    // If TunDeviceHandle were not Send, this would fail to compile
    // Note: We don't actually create a device here since that requires
    // CAP_NET_ADMIN privileges
    fn verify_send() {
        // This is a compile-time check only
        if false {
            let handle = TunDeviceHandle::create("test0", 0x0A000001, 0xFFFFFF00, 1400)
                .expect("device creation");
            assert_send(handle);
        }
    }

    verify_send();

    println!("TunDeviceHandle is Send - can be used with tokio::spawn_blocking!");

    // Example usage pattern (commented out since we don't have a real device):
    //
    // async fn use_with_tokio() {
    //     let handle = TunDeviceHandle::create("tun0", 0x0A000001, 0xFFFFFF00, 1400)
    //         .expect("device creation");
    //
    //     // Move handle into blocking task
    //     let result = tokio::task::spawn_blocking(move || {
    //         let mut buf = vec![0u8; 2048];
    //         handle.read(&mut buf)
    //     }).await.unwrap();
    //
    //     println!("Read {} bytes", result.unwrap());
    // }
}
