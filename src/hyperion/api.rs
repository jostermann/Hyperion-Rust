use crate::hyperion::components::container::initialize_container;
use crate::hyperion::components::container::{RootContainerArray, RootContainerEntry, RootContainerStats, ROOT_NODES};
use crate::hyperion::components::node::NodeValue;
use crate::hyperion::components::return_codes::ReturnCode;
use crate::hyperion::internals::atomic_pointer::AtomicArena;
pub use crate::hyperion::internals::core::log_to_file;
use crate::hyperion::internals::core::{int_get, int_put, int_range, remove, HyperionCallback, GLOBAL_CONFIG};
use crate::hyperion::preprocessor::key_preprocessor::{
    preprocess_english_language_memory, preprocess_english_language_performance, preprocess_uniform_keys_mt, preprocess_uniform_keys_st,
    PreprocessCallbackInterface, Preprocessor,
};
use crate::memorymanager::api::{get_next_arena, initialize, memory_manager_statistics, teardown};
use once_cell::sync::Lazy;
use spin::mutex::Mutex;
use parking_lot::RwLock;
use std::ptr::NonNull;
use std::sync::Arc;
use crate::hyperion::monitor::{join_monitor_deamon, spawn_monitor_deamon};

static PREPROCESS_CB: Lazy<RwLock<PreprocessCallbackInterface>> = Lazy::new(|| RwLock::new(preprocess_uniform_keys_st));

pub fn initialize_globals() {
    GLOBAL_CONFIG.write().header.set_initialized(1);
    GLOBAL_CONFIG.write().header.set_thread_keep_alive(true);
    GLOBAL_CONFIG.write().header.set_container_size_increment(32);
    GLOBAL_CONFIG.write().header.set_container_embedding_high_watermark(144);
    GLOBAL_CONFIG.write().num_writes_million = 0;
    GLOBAL_CONFIG.write().num_reads_million = 0;
    GLOBAL_CONFIG.write().header.set_io_threads(1);
    GLOBAL_CONFIG.write().container_embedding_limit = 32768;
    GLOBAL_CONFIG.write().header.set_preprocessor_strategy(Preprocessor::None);
    GLOBAL_CONFIG.write().top_level_successor_threshold = 1;
}

pub fn bootstrap(logfile_prefix: Option<&str>) -> Arc<Mutex<RootContainerArray>> {
    if GLOBAL_CONFIG.read().header.initialized() == 0 {
        initialize_globals();
    }
    initialize();
    assert!(size_of::<RootContainerEntry>() <= 64);

    let root_container_array = Arc::new(Mutex::new(RootContainerArray {
        root_container_entries: [const { None }; ROOT_NODES],
    }));

    for i in 0..ROOT_NODES {
        root_container_array.lock().root_container_entries[i] = Some(Arc::new(Mutex::new(RootContainerEntry {
            stats: RootContainerStats {
                puts: 0,
                gets: 0,
                range_queries: 0,
                updates: 0,
                range_queries_leaves: 0,
            },
            arena: None,
            hyperion_pointer: None,
            preprocessor: Preprocessor::None,
        })));
    }

    match GLOBAL_CONFIG.read().header.preprocessor_strategy() {
        Preprocessor::None => {},
        Preprocessor::UniformKeyDistributionSingleThread => {
            *PREPROCESS_CB.write() = preprocess_uniform_keys_st;
            activate_ppp();
        },
        Preprocessor::UniformKeyDistributionMultiThread => {
            *PREPROCESS_CB.write() = preprocess_uniform_keys_mt;
            activate_ppp();
        },
        Preprocessor::EnglishLanguageDataMemory => {
            *PREPROCESS_CB.write() = preprocess_english_language_memory;
            activate_ppp();
        },
        Preprocessor::EnglishLanguageDataPerformance => {
            *PREPROCESS_CB.write() = preprocess_english_language_performance;
            activate_ppp();
        },
    }

    if let Some(prefix) = logfile_prefix {
        spawn_monitor_deamon(Arc::clone(&root_container_array), prefix);
    }

    root_container_array
}

pub fn shutdown_hyperion() {
    GLOBAL_CONFIG.write().header.set_thread_keep_alive(false);
    join_monitor_deamon();
    memory_manager_statistics();
    teardown();
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn get_root_container_entry(root_container_array: &Arc<Mutex<RootContainerArray>>, key: *const u8) -> Arc<Mutex<RootContainerEntry>> {
    let index = if ROOT_NODES == 1 {
        0
    }
    else {
        unsafe { *key as usize }
    };

    let mut array_guard = root_container_array.lock();
    {
        let mut entry_guard = array_guard.root_container_entries[index].as_mut().unwrap().lock();

        if entry_guard.arena.is_none() {
            entry_guard.arena = Some(AtomicArena::new_from_pointer(get_next_arena()));

            if let Some(ref mut arena) = entry_guard.arena {
                entry_guard.hyperion_pointer = Some(initialize_container(arena.get()));
            }
        }
    }

    array_guard.root_container_entries[index].as_ref().unwrap().clone()
}

type PutRef = fn(&Arc<Mutex<RootContainerArray>>, *mut u8, u16, Option<NonNull<NodeValue>>) -> ReturnCode;
type GetRef = fn(&Arc<Mutex<RootContainerArray>>, *mut u8, u16, &mut *mut NodeValue) -> ReturnCode;
type DelRef = fn(&Arc<Mutex<RootContainerArray>>, *mut u8, u16) -> ReturnCode;

static PUT_REF_CB: Lazy<RwLock<PutRef>> = Lazy::new(|| RwLock::new(put_no_ppp));
static GET_REF_CB: Lazy<RwLock<GetRef>> = Lazy::new(|| RwLock::new(get_no_pp));
static DELETE_REF_CB: Lazy<RwLock<DelRef>> = Lazy::new(|| RwLock::new(delete_no_ppp));

const PPP_TMP_MEMORY: usize = 4096;

fn activate_ppp() {
    *PUT_REF_CB.write() = put_with_ppp;
    *GET_REF_CB.write() = get_with_pp;
    *DELETE_REF_CB.write() = delete_with_ppp;
}

fn put_no_ppp(root_container_array: &Arc<Mutex<RootContainerArray>>, key: *mut u8, key_len: u16, input_value: Option<NonNull<NodeValue>>) -> ReturnCode {
    let root_container_entry = get_root_container_entry(root_container_array, key);
    int_put(root_container_entry, key, key_len, input_value)
}

fn put_with_ppp(root_container_array: &Arc<Mutex<RootContainerArray>>, key: *mut u8, key_len: u16, input_value: Option<NonNull<NodeValue>>) -> ReturnCode {
    let root_container_entry = get_root_container_entry(root_container_array, key);
    let mut destination = [0u8; PPP_TMP_MEMORY];
    let mut len = key_len;
    PREPROCESS_CB.read()(key, &mut len, destination.as_mut_ptr());
    int_put(root_container_entry, destination.as_mut_ptr(), len, input_value)
}

fn get_no_pp(root_container_array: &Arc<Mutex<RootContainerArray>>, key: *mut u8, key_len: u16, return_value: &mut *mut NodeValue) -> ReturnCode {
    let root_container_entry = get_root_container_entry(root_container_array, key);
    int_get(root_container_entry, key, key_len, *return_value)
}

fn get_with_pp(root_container_array: &Arc<Mutex<RootContainerArray>>, key: *mut u8, key_len: u16, return_value: &mut *mut NodeValue) -> ReturnCode {
    let root_container_entry = get_root_container_entry(root_container_array, key);
    let mut destination = [0u8; PPP_TMP_MEMORY];
    let mut len = key_len;
    PREPROCESS_CB.read()(key, &mut len, destination.as_mut_ptr());
    int_get(root_container_entry, destination.as_mut_ptr(), len, *return_value)
}

pub fn delete_no_ppp(root_container_array: &Arc<Mutex<RootContainerArray>>, key: *mut u8, key_len: u16) -> ReturnCode {
    let root_container_entry = get_root_container_entry(root_container_array, key);
    remove(root_container_entry, key, key_len)
}

pub fn delete_with_ppp(root_container_array: &Arc<Mutex<RootContainerArray>>, key: *mut u8, key_len: u16) -> ReturnCode {
    let root_container_entry = get_root_container_entry(root_container_array, key);
    let mut destination = [0u8; PPP_TMP_MEMORY];
    let mut len = key_len;
    PREPROCESS_CB.read()(key, &mut len, destination.as_mut_ptr());
    remove(root_container_entry, destination.as_mut_ptr(), len)
}

pub fn put(root_container_array: &Arc<Mutex<RootContainerArray>>, key: *mut u8, key_len: u16, input_value: Option<NonNull<NodeValue>>) -> ReturnCode {
    PUT_REF_CB.read()(root_container_array, key, key_len, input_value)
}

pub fn get(root_container_array: &Arc<Mutex<RootContainerArray>>, key: *mut u8, key_len: u16, return_value: &mut *mut NodeValue) -> ReturnCode {
    GET_REF_CB.read()(root_container_array, key, key_len, return_value)
}

pub fn delete(root_container_array: &Arc<Mutex<RootContainerArray>>, key: *mut u8, key_len: u16) -> ReturnCode {
    DELETE_REF_CB.read()(root_container_array, key, key_len)
}

pub fn range(root_container_array: &Arc<Mutex<RootContainerArray>>, key: *mut u8, key_len: u16, cb: HyperionCallback) -> ReturnCode {
    let root_container_entry = get_root_container_entry(root_container_array, key);
    int_range(root_container_entry, key, key_len, cb)
}
