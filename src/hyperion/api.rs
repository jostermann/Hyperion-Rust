use spin::mutex::Mutex;
use crate::hyperion::components::container::{RootContainerArray, RootContainerEntry, RootContainerEntryInner, RootContainerStats, ROOT_NODES};
use crate::hyperion::internals::atomic_pointer::initialize_container;
use crate::hyperion::internals::core::{get_global_cfg, GlobalConfiguration, GLOBAL_CONFIG};
use crate::memorymanager::api::{get_next_arena, initialize};

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
                        updates: 0
                    },
                    arena: None,
                    hyperion_pointer: None,
                })
            }
        );
    }
    root_container_array
}

pub fn get_root_container_entry<'a>(root_container_array: &'a mut RootContainerArray, key: *const u8, key_len: u16) -> &'a mut RootContainerEntry {
    let mut root_container_entry = if ROOT_NODES == 1 {
        root_container_array.root_container_entries[0].as_mut().unwrap()
    }
    else {
        unsafe { root_container_array.root_container_entries.as_mut_ptr().add((*(key)) as usize).as_mut().unwrap().as_mut().unwrap() }
    };
    {
        let mut data = root_container_entry.inner.lock();

        if data.arena.is_none() {
            data.arena = unsafe { Some(Box::from_raw(get_next_arena())) };
            data.hyperion_pointer = Some(initialize_container(data.arena.as_mut().unwrap().as_mut()));
        }
    }
    root_container_entry
}
