pub mod hyperion;
pub mod memorymanager;

use crate::hyperion::api::{bootstrap, delete, get, initialize_globals, put, range, shutdown, shutdown_hyperion};
use crate::hyperion::components::container::RootContainerArray;
use crate::hyperion::components::node::NodeValue;
use libc::{c_int, c_uchar, c_ushort};
use std::ptr::NonNull;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::Ordering::SeqCst;

#[no_mangle]
pub extern "C" fn trie_init() -> *mut RootContainerArray {
    initialize_globals();
    let array = Box::new(bootstrap());
    Box::into_raw(array)
}

#[no_mangle]
pub extern "C" fn trie_insert(ctx: *mut RootContainerArray, key: *const c_uchar, key_len: c_ushort, value: *mut NodeValue) -> c_int {
    unsafe { put(&mut *ctx, key as *mut u8, key_len, NonNull::new(value)) as c_int }
}

#[no_mangle]
pub extern "C" fn trie_read(ctx: *mut RootContainerArray, key: *const c_uchar, key_len: c_ushort, mut value: *mut NodeValue) -> c_int {
    let mut node_val = NodeValue { value: 0 };
    let mut node_val_ptr = &mut node_val as *mut NodeValue;
    let ret = unsafe { get(&mut *ctx, key as *mut u8, key_len, &mut node_val_ptr) };
    value = node_val_ptr;
    //println!("Rust read: return value {}", unsafe { *value });
    ret as c_int
}

#[no_mangle]
pub extern "C" fn trie_delete(ctx: *mut RootContainerArray, key: *const c_uchar, key_len: c_ushort) -> c_int {
    unsafe { delete(&mut *ctx, key as *mut u8, key_len) as c_int }
}

static RANGE_QUERY_COUNTER: AtomicI32 = AtomicI32::new(0);

#[allow(unused_variables)]
fn range_callback(key: *mut u8, key_len: u16, value: *mut u8) -> bool {
    RANGE_QUERY_COUNTER.fetch_add(1, SeqCst);
    true
}

#[no_mangle]
pub extern "C" fn trie_scan(ctx: *mut RootContainerArray, key: *const c_uchar, key_len: c_ushort) -> c_int {
    RANGE_QUERY_COUNTER.store(0, SeqCst);
    let ret = unsafe { range(&mut *ctx, key as *mut u8, key_len, range_callback) };
    ret as c_int
}

#[no_mangle]
pub extern "C" fn trie_shutdown() {
    shutdown_hyperion();
}
