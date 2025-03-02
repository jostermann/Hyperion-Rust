use std::ffi::c_void;
use std::ptr::copy;

pub unsafe fn copy_memory_from<U, T>(src: *const T, dest: *mut U, size: usize) {
    let destination: *mut c_void = dest as *mut c_void;
    let source: *const c_void = src as *const c_void;
    copy(source as *const u8, destination as *mut u8, size);
}

pub unsafe fn copy_memory_to<U, T>(dest: *mut T, src: *const U, size: usize) {
    let destination: *mut c_void = dest as *mut c_void;
    let source: *const c_void = src as *const c_void;
    copy(source as *const u8, destination as *mut u8, size);
}
