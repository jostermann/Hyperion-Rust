use crate::hyperion::components::container::RootContainerArray;
use crate::hyperion::internals::core::GLOBAL_CONFIG;
use crate::memorymanager::api::{
    get_compressed_total, get_memory_stats, get_reset_compressed_bytes, get_reset_decompressed_bytes, get_reset_original_compressed,
    get_reset_original_decompressed, get_reset_trimmed_chunks,
};
use chrono::Local;
use once_cell::sync::OnceCell;
use spin::mutex::Mutex;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{env, thread};

const VERSION: &str = "v1.28.2";
const MONITOR_INTERVAL_SEC: u64 = 1;
const MONITOR_FLUSH_COUNT: i32 = 10;
static FLUSH_COUNT: AtomicI32 = AtomicI32::new(0);

pub struct MonitorState {
    logfile_path: PathBuf,
    thread_handle: Option<thread::JoinHandle<()>>,
}

pub static MONITOR_STATE: OnceCell<Arc<Mutex<MonitorState>>> = OnceCell::new();

pub fn spawn_monitor_deamon(root_container_array: Arc<Mutex<RootContainerArray>>, logfile_prefix: &str) {
    let log_path = initialize_logfile(logfile_prefix);
    let monitor_state = Arc::new(Mutex::new(MonitorState {
        logfile_path: log_path.clone(),
        thread_handle: None,
    }));

    let handle = thread::Builder::new()
        .name("monitor_deamon".to_string())
        .spawn(move || monitor_deamon(root_container_array, &log_path))
        .expect("Failed to spawn monitor thread");

    monitor_state.lock().thread_handle = Some(handle);
    MONITOR_STATE.set(monitor_state).ok();
}

pub fn initialize_logfile(prefix: &str) -> PathBuf {
    let now = Local::now();
    let time_str = now.format("-%y%m%dT%H%M%S-").to_string();
    let cwd = env::current_dir().expect("Could not get current working directory");
    let filename = format!("{prefix}-{VERSION}{time_str}.txt");
    cwd.join(filename)
}

pub fn join_monitor_deamon() {
    if let Some(state_arc) = MONITOR_STATE.get() {
        let mut state = state_arc.lock();
        if let Some(handle) = state.thread_handle.take() {
            handle.join().expect("Failed to join monitor thread");
        }
    }
}

pub fn monitor_deamon(root_container_array: Arc<Mutex<RootContainerArray>>, logfile_prefix: &PathBuf) {
    let file = File::create(logfile_prefix).expect("Failed to create log file");
    let mut writer = BufWriter::new(file);

    writeln!(
        writer,
        "Time;Treesize-[Bil];Put/s[k];Get/s[k];Upd/s[k];RQ;VMsize[GiB];Bytes/Key];Trimmed;Comp[kb];Decomp[kb];AbsCompr[mb];OrigComp[kb];OrigDecp[kb];memrate;RQleaves"
    ).unwrap();

    let mut total_puts = 0u64;
    let mut total_gets = 0u64;
    let mut total_updates = 0u64;
    let mut current_puts = 0u64;
    let mut current_gets = 0u64;
    let mut current_updates = 0u64;
    let mut current_rangequeries = 0i64;
    let mut rq_leaves = 0u64;
    let mut memory_settings = get_memory_stats(true);
    let mut last_time = SystemTime::now();

    while GLOBAL_CONFIG.read().header.thread_keep_alive() {
        current_puts = 0;
        current_gets = 0;
        current_updates = 0;
        current_rangequeries = 0;
        rq_leaves = 0;

        thread::sleep(Duration::from_millis(50));

        let current_time = SystemTime::now();

        if current_time.duration_since(last_time).unwrap().as_secs() == 0 {
            continue;
        }
        last_time = current_time;

        if FLUSH_COUNT.load(Relaxed) <= 0 || memory_settings.read().vm_size > 1022361600 {
            writer.flush().unwrap();
            FLUSH_COUNT.store(MONITOR_FLUSH_COUNT, Relaxed);
        }
        let _ = FLUSH_COUNT.fetch_sub(1, Relaxed);

        memory_settings = get_memory_stats(true);

        {
            let mut array_guard = root_container_array.lock();

            for i in 0..array_guard.root_container_entries.len() {
                let mut entry_guard = array_guard.root_container_entries[i].as_mut().unwrap().lock();
                current_puts += entry_guard.stats.puts as u64;
                entry_guard.stats.puts = 0;
                current_gets += entry_guard.stats.gets as u64;
                entry_guard.stats.gets = 0;
                current_updates += entry_guard.stats.updates as u64;
                entry_guard.stats.updates = 0;
                current_rangequeries += entry_guard.stats.range_queries as i64;
                entry_guard.stats.range_queries = 0;
                rq_leaves += entry_guard.stats.range_queries_leaves as u64;
                entry_guard.stats.range_queries_leaves = 0;
            }
        }

        total_puts += current_puts;
        total_gets += current_gets;
        total_updates += current_updates;
        let puts_per_second: f64 = current_puts as f64 / MONITOR_INTERVAL_SEC as f64;
        let gets_per_second: f64 = current_gets as f64 / MONITOR_INTERVAL_SEC as f64;
        let updates_per_second: f64 = current_updates as f64 / MONITOR_INTERVAL_SEC as f64;
        let bytes_per_key: f64 = memory_settings.read().vm_size as f64 * 1024.0 / total_puts as f64;

        let _ = writeln!(
            writer,
            "\n{};{:9.3};{:9.3};{:9.3};{:9.3};{:6};{:9.3};{:7.3};{:7};{:7};{:7};{:7};{:7};{:5};{:2.3};{:7}",
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            total_puts as f64 / 1_000_000_000.0,
            puts_per_second / 1_000.0,
            gets_per_second / 1_000.0,
            updates_per_second / 1_000.0,
            current_rangequeries,
            memory_settings.read().vm_size as f64 / 1_048_576.0,
            bytes_per_key,
            get_reset_trimmed_chunks(),
            get_reset_compressed_bytes() / 1024,
            get_reset_decompressed_bytes() / 1024,
            get_compressed_total() / 1_048_576,
            get_reset_original_compressed() / 1024,
            get_reset_original_decompressed() / 1024,
            memory_settings.read().sys_rate,
            rq_leaves
        );
    }
    writer.flush().unwrap();
}
