pub mod hyperion;
pub mod memorymanager;

use crate::hyperion::api::{bootstrap, delete, get, put, range, shutdown_hyperion};
use crate::hyperion::components::container::RootContainerArray;
use crate::hyperion::components::node::NodeValue;
use libc::{c_long, c_uchar, c_ushort};
use once_cell::sync::OnceCell;
use spin::mutex::Mutex;
use std::mem::forget;
use std::ptr::NonNull;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::Arc;
use std::time::Instant;
use crate::hyperion::components::return_codes::ReturnCode::GetFailureNoNode;

static GLOBAL_CONTAINER: OnceCell<Arc<Mutex<RootContainerArray>>> = OnceCell::new();

#[no_mangle]
pub extern "C" fn trie_init() -> *mut RootContainerArray {
    let array = bootstrap(Option::from("hyperion statistics"));
    let raw_ptr = Arc::into_raw(array.clone()) as *mut RootContainerArray;
    GLOBAL_CONTAINER.set(array).ok();
    raw_ptr
}

#[no_mangle]
pub extern "C" fn trie_insert(ctx: *mut RootContainerArray, key: *const c_uchar, key_len: c_ushort, value: *mut NodeValue) -> c_long {
    let arc = unsafe { Arc::from_raw(ctx as *const Mutex<RootContainerArray>) };
    let node_value = NonNull::new(value);
    let start = Instant::now();
    put(&arc, key as *mut u8, key_len, node_value);
    let stop = Instant::now();
    let duration = stop.duration_since(start).as_nanos();
    forget(arc.clone());
    duration as c_long
}

#[no_mangle]
pub extern "C" fn trie_read(ctx: *mut RootContainerArray, key: *const c_uchar, key_len: c_ushort, mut value: *mut NodeValue) -> c_long {
    let mut node_val = NodeValue { value: 0 };
    let mut node_val_ptr = &mut node_val as *mut NodeValue;
    let arc = unsafe { Arc::from_raw(ctx as *const Mutex<RootContainerArray>) };
    let start = Instant::now();
    let ret = get(&arc, key as *mut u8, key_len, &mut node_val_ptr);
    if ret == GetFailureNoNode {
        eprintln!("Read failed");
    }
    let stop = Instant::now();
    let duration = stop.duration_since(start).as_nanos();
    value = node_val_ptr;
    forget(arc.clone());
    duration as c_long
}

#[no_mangle]
pub extern "C" fn trie_delete(ctx: *mut RootContainerArray, key: *const c_uchar, key_len: c_ushort) -> c_long {
    let arc = unsafe { Arc::from_raw(ctx as *const Mutex<RootContainerArray>) };
    let start = Instant::now();
    delete(&arc, key as *mut u8, key_len);
    let stop = Instant::now();
    let duration = stop.duration_since(start).as_nanos();
    forget(arc.clone());
    duration as c_long
}

static RANGE_QUERY_COUNTER: AtomicI32 = AtomicI32::new(0);

#[allow(unused_variables)]
fn range_callback(key: *mut u8, key_len: u16, value: *mut u8) -> bool {
    RANGE_QUERY_COUNTER.fetch_add(1, SeqCst);
    true
}

#[no_mangle]
pub extern "C" fn trie_scan(ctx: *mut RootContainerArray, key: *const c_uchar, key_len: c_ushort) -> c_long {
    RANGE_QUERY_COUNTER.store(0, SeqCst);
    let arc = unsafe { Arc::from_raw(ctx as *const Mutex<RootContainerArray>) };
    let start = Instant::now();
    range(&arc, key as *mut u8, key_len, range_callback);
    let stop = Instant::now();
    let duration = stop.duration_since(start).as_nanos();
    forget(arc.clone());
    duration as c_long
}

#[no_mangle]
pub extern "C" fn trie_shutdown(ctx: *mut RootContainerArray) {
    shutdown_hyperion();
    let _ = unsafe { Arc::from_raw(ctx as *const Mutex<RootContainerArray>) };
}
