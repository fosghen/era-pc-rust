//! Native instruction observer for Unicorn 2.1.4. No guest code runs natively.
//! ABI is private to native_observer.py; all ranges are half-open.
use std::ffi::c_void;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Range {
    start: u64,
    end: u64,
}

type Callback = unsafe extern "C" fn(*mut c_void, u64, u32, *mut c_void) -> i32;

#[repr(C)]
pub struct Observer {
    instructions: u64,
    tail: [u64; 24],
    next: u32,
    used: u32,
    range_count: u32,
    ranges: [Range; 128],
    callback: Callback,
    callback_data: *mut c_void,
}

#[no_mangle]
pub extern "C" fn observer_size() -> usize {
    std::mem::size_of::<Observer>()
}

#[no_mangle]
pub extern "C" fn observer_abi() -> u32 {
    1
}

impl Observer {
    fn interesting(&self, address: u64) -> bool {
        let ranges = &self.ranges[..self.range_count as usize];
        let index = ranges.partition_point(|r| r.start <= address);
        index != 0 && address < ranges[index - 1].end
    }

    fn record(&mut self, address: u64) {
        self.instructions += 1;
        self.tail[self.next as usize] = address;
        self.next = (self.next + 1) % 24;
        self.used = (self.used + 1).min(24);
    }
}

/// The owner keeps a validated, exclusively executing Observer alive until the
/// hook is removed. Python may inspect it from a callback on this same thread.
/// Never retain a Rust reference across that callback (FFI reentrancy).
#[no_mangle]
pub unsafe extern "C" fn observer_hook(
    engine: *mut c_void,
    address: u64,
    size: u32,
    data: *mut c_void,
) {
    let ptr = data.cast::<Observer>();
    let interesting = unsafe { (&*ptr).interesting(address) };
    if interesting {
        let callback = unsafe { (*ptr).callback };
        let callback_data = unsafe { (*ptr).callback_data };
        if unsafe { callback(engine, address, size, callback_data) } != 1 {
            return;
        }
    }
    unsafe { (&mut *ptr).record(address) };
}
