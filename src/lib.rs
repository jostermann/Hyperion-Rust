pub mod hyperion;
pub mod memorymanager;

use std::mem::forget;
use crate::hyperion::api::{bootstrap, delete, get, initialize_globals, put, range, shutdown_hyperion};
use crate::hyperion::components::container::RootContainerArray;
use crate::hyperion::components::node::NodeValue;
use libc::{c_int, c_uchar, c_ushort};
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::Ordering::SeqCst;
use spin::mutex::Mutex;

#[no_mangle]
pub extern "C" fn trie_init() -> *mut RootContainerArray {
    initialize_globals();
    let array = bootstrap(None);
    Arc::into_raw(array) as *mut RootContainerArray
}

#[no_mangle]
pub extern "C" fn trie_insert(ctx: *mut RootContainerArray, key: *const c_uchar, key_len: c_ushort, value: *mut NodeValue) -> c_int {
    let arc = unsafe { Arc::from_raw(ctx as *const Mutex<RootContainerArray>) };
    let result = put(&arc, key as *mut u8, key_len, NonNull::new(value)) as c_int;
    forget(arc.clone());
    result
}

#[no_mangle]
pub extern "C" fn trie_read(ctx: *mut RootContainerArray, key: *const c_uchar, key_len: c_ushort, mut value: *mut NodeValue) -> c_int {
    let mut node_val = NodeValue { value: 0 };
    let mut node_val_ptr = &mut node_val as *mut NodeValue;
    let arc = unsafe { Arc::from_raw(ctx as *const Mutex<RootContainerArray>) };
    let ret = get(&arc, key as *mut u8, key_len, &mut node_val_ptr);
    value = node_val_ptr;
    forget(arc.clone());
    //println!("Rust read: return value {}", unsafe { *value });
    ret as c_int
}

#[no_mangle]
pub extern "C" fn trie_delete(ctx: *mut RootContainerArray, key: *const c_uchar, key_len: c_ushort) -> c_int {
    let arc = unsafe { Arc::from_raw(ctx as *const Mutex<RootContainerArray>) };
    let ret = delete(&arc, key as *mut u8, key_len) as c_int;
    forget(arc.clone());
    ret
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
    let arc = unsafe { Arc::from_raw(ctx as *const Mutex<RootContainerArray>) };
    let ret = range(&arc, key as *mut u8, key_len, range_callback);
    forget(arc.clone());
    ret as c_int
}

#[no_mangle]
pub extern "C" fn trie_shutdown() {
    shutdown_hyperion();
}
