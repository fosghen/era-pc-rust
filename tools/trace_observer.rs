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
    2
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

type MemoryCallback = unsafe extern "C" fn(*mut c_void, i32, u64, i32, i64, *mut c_void);

#[repr(C)]
pub struct MemoryFilter {
    accesses: u64,
    forwarded: u64,
    range_count: u32,
    overlap: u32,
    ranges: [Range; 128],
    callback: MemoryCallback,
    callback_data: *mut c_void,
}

#[no_mangle]
pub extern "C" fn memory_filter_size() -> usize {
    std::mem::size_of::<MemoryFilter>()
}

impl MemoryFilter {
    fn relevant(&self, address: u64, size: i32) -> bool {
        let ranges = &self.ranges[..self.range_count as usize];
        if self.overlap == 0 {
            let index = ranges.partition_point(|r| r.start <= address);
            return index != 0 && address < ranges[index - 1].end;
        }
        // Forward unexpected sizes, rather than hide an event from the guard.
        if size <= 0 {
            return true;
        }
        let end = address.saturating_add(size as u64);
        let index = ranges.partition_point(|r| r.start < end);
        index != 0 && address < ranges[index - 1].end
    }
}

/// # Safety
/// `data` must reference a validated MemoryFilter kept alive until hook removal.
/// Its disjoint, sorted ranges may change only while emulation is stopped or
/// inside a synchronous Python API callback. No Rust borrow spans a callback.
#[no_mangle]
pub unsafe extern "C" fn memory_filter_hook(
    engine: *mut c_void,
    kind: i32,
    address: u64,
    size: i32,
    value: i64,
    data: *mut c_void,
) {
    let ptr = data.cast::<MemoryFilter>();
    unsafe { (*ptr).accesses += 1 };
    if unsafe { (&*ptr).relevant(address, size) } {
        unsafe { (*ptr).forwarded += 1 };
        let callback = unsafe { (*ptr).callback };
        let callback_data = unsafe { (*ptr).callback_data };
        unsafe { callback(engine, kind, address, size, value, callback_data) };
    }
}
