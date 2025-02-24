use std::ffi::c_void;

use libc::memcpy;

pub unsafe fn copy_memory_from<U, T>(src: *const T, dest: *mut U, size: usize) {
    let destination: *mut c_void = dest as *mut c_void;
    let source: *const c_void = src as *const c_void;
    memcpy(destination, source, size);
}

pub unsafe fn copy_memory_to<U, T>(dest: *mut T, src: *const U, size: usize) {
    let dest: *mut c_void = dest as *mut c_void;
    let src: *const c_void = src as *const c_void;
    memcpy(dest, src, size);
}
