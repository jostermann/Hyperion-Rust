use crate::hyperion::components::container::{RootContainerArray, RootContainerEntry, RootContainerEntryInner, RootContainerStats, ROOT_NODES};
use crate::hyperion::components::node::NodeValue;
use crate::hyperion::components::return_codes::ReturnCode;
use crate::hyperion::internals::atomic_pointer::initialize_container;
use crate::hyperion::internals::core::{int_get, int_put, GLOBAL_CONFIG};
use crate::memorymanager::api::{get_next_arena, initialize, teardown};
use once_cell::sync::Lazy;
use spin::mutex::Mutex;
use spin::RwLock;
pub use crate::hyperion::internals::core::log_to_file;

pub fn initialize_globals() {
    GLOBAL_CONFIG.write().header.set_initialized(1);
    GLOBAL_CONFIG.write().header.set_thread_keep_alive(1);
    GLOBAL_CONFIG.write().header.set_container_size_increment(32);
    GLOBAL_CONFIG.write().header.set_container_embedding_high_watermark(144);
    GLOBAL_CONFIG.write().num_writes_million = 0;
    GLOBAL_CONFIG.write().num_reads_million = 0;
    GLOBAL_CONFIG.write().header.set_io_threads(1);
    GLOBAL_CONFIG.write().container_embedding_limit = 32768;
    //GLOBAL_CONFIG.write().; // TODO key_ppp_strategy
    GLOBAL_CONFIG.write().top_level_successor_threshold = 1;
}

pub fn bootstrap() -> RootContainerArray {
    if GLOBAL_CONFIG.read().header.initialized() == 0 {
        initialize_globals();
    }
    initialize();
    assert!(size_of::<RootContainerEntry>() <= 64);

    let mut root_container_array = RootContainerArray {
        root_container_entries: [None; ROOT_NODES],
    };

    for i in 0..ROOT_NODES {
        root_container_array.root_container_entries[i] = Some(
            RootContainerEntry {
                inner: Mutex::new(RootContainerEntryInner {
                    stats: RootContainerStats {
                        puts: 0,
                        gets: 0,
                        range_queries: 0,
                        updates: 0,
                        range_queries_leaves: 0
                    },
                    arena: None,
                    hyperion_pointer: None,
                })
            }
        );
    }
    root_container_array
}

pub fn clear_test() {
    teardown();
}

pub fn get_root_container_entry(root_container_array: &mut RootContainerArray, key: *const u8, key_len: u16) -> &mut RootContainerEntry {
    let root_container_entry = if ROOT_NODES == 1 {
        root_container_array.root_container_entries[0].as_mut().unwrap()
    }
    else {
        unsafe { root_container_array.root_container_entries.as_mut_ptr().add((*(key)) as usize).as_mut().unwrap().as_mut().unwrap() }
    };
    {
        let mut data = root_container_entry.inner.lock();

        if data.arena.is_none() {
            data.arena = Some(get_next_arena());

            if let Some(ref mut arena) = data.arena {
                data.hyperion_pointer = Some(initialize_container(*arena));
            }
        }
    }
    root_container_entry
}

type PutRef = fn(&mut RootContainerArray, *mut u8, u16, Option<*mut NodeValue>) -> ReturnCode;
type GetRef = fn(&mut RootContainerArray, *mut u8, u16, &mut *mut NodeValue) -> ReturnCode;

static PUT_REF_CB: Lazy<RwLock<PutRef>> = Lazy::new(|| RwLock::new(put_no_ppp));
static GET_REF_CB: Lazy<RwLock<GetRef>> = Lazy::new(|| RwLock::new(get_no_pp));

fn put_no_ppp(root_container_array: &mut RootContainerArray, key: *mut u8, key_len: u16, input_value: Option<*mut NodeValue>) -> ReturnCode {
    let root_container_entry = get_root_container_entry(root_container_array, key, key_len);
    let mut entry = root_container_entry.inner.lock();
    int_put(&mut entry, key, key_len, input_value)
}

fn get_no_pp(root_container_array: &mut RootContainerArray, key: *mut u8, key_len: u16, return_value: &mut *mut NodeValue) -> ReturnCode {
    let root_container_entry = get_root_container_entry(root_container_array, key, key_len);
    let mut entry = root_container_entry.inner.lock();
    int_get(&mut entry, key, key_len, *return_value)
}

pub fn put(root_container_array: &mut RootContainerArray, key: *mut u8, key_len: u16, input_value: Option<*mut NodeValue>) -> ReturnCode {
    PUT_REF_CB.read()(root_container_array, key, key_len, input_value)
}

pub fn get(root_container_array: &mut RootContainerArray, key: *mut u8, key_len: u16, return_value: &mut *mut NodeValue) -> ReturnCode {
    GET_REF_CB.read()(root_container_array, key, key_len, return_value)
}

