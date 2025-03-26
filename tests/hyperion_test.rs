use std::fs::File;
use hyperion_rust::hyperion::api::{bootstrap, clear_test, get, get_root_container_entry, log_to_file, put, range};
use hyperion_rust::hyperion::components::container::initialize_container;
use hyperion_rust::hyperion::components::container::Container;
use hyperion_rust::hyperion::components::node::NodeValue;
use hyperion_rust::hyperion::components::return_codes::ReturnCode::OK;
use hyperion_rust::hyperion::internals::core::put_debug;
use hyperion_rust::memorymanager::api::get_pointer;
use lazy_static::lazy_static;
use std::intrinsics::copy_nonoverlapping;
use std::io;
use std::io::{BufRead, BufReader};
use std::ptr::{read_unaligned, write_unaligned};
use std::sync::atomic::AtomicI32;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Mutex;

lazy_static! {
    static ref TEST_MUTEX: Mutex<()> = Mutex::new(());
}

#[test]
fn test_initialize_container_001() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let mut root_container_array = bootstrap();
    let key: &str = "00";
    let rce = get_root_container_entry(&mut root_container_array, key.as_ptr(), 2);
    let mut data = rce.inner.lock();
    assert_eq!(data.hyperion_pointer.as_mut().unwrap().superbin_id(), 1);
    assert_eq!(data.hyperion_pointer.as_mut().unwrap().metabin_id(), 0);
    assert_eq!(data.hyperion_pointer.as_mut().unwrap().bin_id(), 0);
    assert_eq!(data.hyperion_pointer.as_mut().unwrap().chunk_id(), 0);

    let hyp_ptr = initialize_container(data.arena.as_mut().unwrap().get());
    assert_eq!(hyp_ptr.superbin_id(), 1);
    assert_eq!(hyp_ptr.metabin_id(), 0);
    assert_eq!(hyp_ptr.bin_id(), 0);
    assert_eq!(hyp_ptr.chunk_id(), 1);
    clear_test();
}

#[test]
fn test_container_jumptable_01() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let mut val: [u8; 2] = [0, 0];
    let mut root_container_array = bootstrap();
    let rce = get_root_container_entry(&mut root_container_array, "00".as_ptr(), 2);
    let mut data = rce.inner.lock();

    for i in 0..10 {
        val[0] = i;
        put_debug(data.arena.as_mut().unwrap().get(), data.hyperion_pointer.as_mut().unwrap(), &mut val[0], 2, None);
    }

    let container = get_pointer(data.arena.as_mut().unwrap().get(), data.hyperion_pointer.as_mut().unwrap(), 0, val[0]) as *mut Container;
    assert_eq!(unsafe { (*container).jump_table() }, 0);
    clear_test();
}

#[test]
fn test_container_split_01() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let elements = 256;
    let limit = 103;
    let mut node_value = NodeValue { value: 0 };
    let mut val: [u8; 128] = [0; 128];
    let mut root_container_array = bootstrap();

    for i in 100..limit {
        for j in 0..elements {
            node_value.value = i + j;
            val[3] = i as u8;
            val[2] = j as u8;
            log_to_file(&format!("i: {}, j: {}", i, j));
            put(&mut root_container_array, val.as_mut_ptr(), 4, Some(&mut node_value));
        }
    }

    let mut p_ret = &mut node_value as *mut NodeValue;

    for i in 100..limit {
        for j in 0..elements {
            val[3] = i as u8;
            val[2] = j as u8;
            log_to_file(&format!("i: {}, j: {}", i, j));
            assert_eq!(get(&mut root_container_array, val.as_mut_ptr(), 4, &mut p_ret), OK);
            assert_eq!(unsafe { (*p_ret).value }, i + j);
        }
    }
    clear_test();
}

#[test]
fn test_container_split_02() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let elements = 256;
    let limit = 106;
    let mut node_value = NodeValue { value: 0 };
    let mut val: [u8; 128] = [0; 128];
    let mut root_container_array = bootstrap();

    for i in 100..limit {
        for j in 0..elements {
            node_value.value = i + j;
            val[3] = i as u8;
            val[2] = j as u8;
            log_to_file(&format!("i: {}, j: {}", i, j));
            put(&mut root_container_array, val.as_mut_ptr(), 4, Some(&mut node_value));
        }
    }

    let mut p_ret = &mut node_value as *mut NodeValue;

    for i in 100..limit {
        for j in 0..elements {
            val[3] = i as u8;
            val[2] = j as u8;
            assert_eq!(get(&mut root_container_array, val.as_mut_ptr(), 4, &mut p_ret), OK);
            assert_eq!(unsafe { (*p_ret).value }, i + j);
        }
    }
    clear_test();
}

#[test]
fn test_container_split_03() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let elements = 256;
    let limit = 116;
    let mut node_value = NodeValue { value: 0 };
    let mut val: [u8; 128] = [0; 128];
    let mut root_container_array = bootstrap();

    for i in 100..limit {
        for j in 0..elements {
            node_value.value = i + j;
            val[3] = i as u8;
            val[2] = j as u8;
            log_to_file(&format!("i: {}, j: {}", i, j));
            put(&mut root_container_array, val.as_mut_ptr(), 4, Some(&mut node_value));
        }
    }

    let mut p_ret = &mut node_value as *mut NodeValue;

    for i in 100..limit {
        for j in 0..elements {
            val[3] = i as u8;
            val[2] = j as u8;
            assert_eq!(get(&mut root_container_array, val.as_mut_ptr(), 4, &mut p_ret), OK);
            assert_eq!(unsafe { (*p_ret).value }, i + j);
        }
    }
    clear_test();
}

#[test]
fn test_container_split_04() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let elements = 256;
    let limit = 200;
    let mut node_value = NodeValue { value: 0 };
    let mut val: [u8; 128] = [0; 128];
    let mut root_container_array = bootstrap();

    for i in 100..limit {
        for j in 0..elements {
            node_value.value = i + j;
            val[3] = i as u8;
            val[2] = j as u8;
            log_to_file(&format!("i: {}, j: {}", i, j));
            put(&mut root_container_array, val.as_mut_ptr(), 4, Some(&mut node_value));
        }
    }

    let mut p_ret = &mut node_value as *mut NodeValue;

    for i in 100..limit {
        for j in 0..elements {
            val[3] = i as u8;
            val[2] = j as u8;
            log_to_file(&format!("i: {}, j: {}", i, j));
            assert_eq!(get(&mut root_container_array, val.as_mut_ptr(), 4, &mut p_ret), OK);
            assert_eq!(unsafe { (*p_ret).value }, i + j);
        }
    }
    clear_test();
}

#[test]
fn test_container_split_05() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let elements = 256;
    let limit = 109;
    let mut node_value = NodeValue { value: 0 };
    let mut val: [u8; 128] = [0; 128];
    let mut root_container_array = bootstrap();

    for i in 0..limit {
        for j in 0..elements {
            node_value.value = i + j;
            val[3] = i as u8;
            val[2] = j as u8;
            log_to_file(&format!("i: {}, j: {}", i, j));
            put(&mut root_container_array, val.as_mut_ptr(), 4, Some(&mut node_value));
        }
    }

    let mut p_ret = &mut node_value as *mut NodeValue;

    for i in 0..limit {
        for j in 0..elements {
            val[3] = i as u8;
            val[2] = j as u8;
            log_to_file(&format!("i: {}, j: {}", i, j));
            assert_eq!(get(&mut root_container_array, val.as_mut_ptr(), 4, &mut p_ret), OK);
            assert_eq!(unsafe { (*p_ret).value }, i + j);
        }
    }
    clear_test();
}

#[test]
fn test_container_split_06() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let elements = 25000;
    let mut node_value = NodeValue { value: 0 };
    let mut val: [u8; 128] = [0; 128];
    let mut root_container_array = bootstrap();
    let base_seed1: i32 = rand::random_range(0..=65535);
    let base_seed2: i32 = rand::random_range(0..=65535);
    println!("base1: {}, base2: {}", base_seed1, base_seed2);
    let mut seed1 = base_seed1;
    let mut seed2 = base_seed2;

    let dest = unsafe { (val.as_mut_ptr() as *mut u16).add(1) };
    unsafe {
        *dest = 0;
    }

    for i in 0..elements {
        unsafe {
            let current_value = *dest;
            *dest = (seed2.wrapping_mul(current_value as i32).wrapping_add(seed1) % 65536) as u16;
            node_value.value = *dest as u64;
        }
        log_to_file(&format!("i: {}", i));
        put(&mut root_container_array, val.as_mut_ptr(), 4, Some(&mut node_value));
    }

    let mut p_ret = &mut node_value as *mut NodeValue;
    unsafe {
        *dest = 0;
    }
    seed1 = base_seed1;
    seed2 = base_seed2;

    for i in 0..elements {
        unsafe {
            let current_value = *dest;
            *dest = (seed2.wrapping_mul(current_value as i32).wrapping_add(seed1) % 65536) as u16;
        }
        log_to_file(&format!("i: {}", i));
        let return_code = get(&mut root_container_array, val.as_mut_ptr(), 4, &mut p_ret);

        assert_eq!(return_code, OK);
        assert_eq!(unsafe { (*p_ret).value }, unsafe { *dest as u64 });
    }
    clear_test();
}

#[test]
fn test_container_split_06b() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let elements = 4506;
    let mut node_value = NodeValue { value: 0 };
    let mut val: [u8; 128] = [0; 128];
    let mut root_container_array = bootstrap();
    let base_seed1: i32 = 26948;
    let base_seed2: i32 = 39085;
    let mut seed1 = base_seed1;
    let mut seed2 = base_seed2;

    let dest = unsafe { (val.as_mut_ptr() as *mut u16).add(1) };
    unsafe {
        *dest = 0;
    }

    for i in 0..elements {
        unsafe {
            let current_value = *dest;
            *dest = (seed2.wrapping_mul(current_value as i32).wrapping_add(seed1) % 65536) as u16;
            node_value.value = *dest as u64;
        }
        log_to_file(&format!("i: {}", i));
        put(&mut root_container_array, val.as_mut_ptr(), 4, Some(&mut node_value));
    }

    let mut p_ret = &mut node_value as *mut NodeValue;
    unsafe {
        *dest = 0;
    }
    seed1 = base_seed1;
    seed2 = base_seed2;

    for i in 0..elements {
        unsafe {
            let current_value = *dest;
            *dest = (seed2.wrapping_mul(current_value as i32).wrapping_add(seed1) % 65536) as u16;
        }
        log_to_file(&format!("i: {}", i));
        let return_code = get(&mut root_container_array, val.as_mut_ptr(), 4, &mut p_ret);

        assert_eq!(return_code, OK);
        assert_eq!(unsafe { (*p_ret).value }, unsafe { *dest as u64 });
    }
    clear_test();
}

static RANGE_QUERY_COUNTER: AtomicI32 = AtomicI32::new(0);

#[allow(unused_variables)]
fn range_callback(key: *mut u8, key_len: u16, value: *mut u8) -> bool {
    RANGE_QUERY_COUNTER.fetch_add(1, Relaxed);
    true
}

#[test]
fn test_container_split_07() {
    let _lock = TEST_MUTEX.lock().unwrap();
    RANGE_QUERY_COUNTER.store(0, Relaxed);
    let elements = 65000;
    let mut node_value = NodeValue {
        value: 0
    };
    let mut val: [u8; 16] = [0; 16];
    let mut root_container_array = bootstrap();
    let dest = unsafe { val.as_mut_ptr().add(2) as *mut u16 };
    unsafe { *dest = 0; }

    for i in 0..elements {
        unsafe {
            *dest = i;
            node_value.value = *dest as u64;
            copy_nonoverlapping(dest, val.as_mut_ptr().add(4) as *mut u16, 1);
        }
        log_to_file(&format!("i: {}", i));
        put(&mut root_container_array, val.as_mut_ptr(), 8, Some(&mut node_value));
    }


    let mut p_ret = &mut node_value as *mut NodeValue;

    for i in 0..elements {
        unsafe {
            *dest = i;
            copy_nonoverlapping(dest, (val.as_mut_ptr() as *mut u16).add(2), 1);
        }
        log_to_file(&format!("i: {}", i));
        let return_code = get(&mut root_container_array, val.as_mut_ptr(), 8, &mut p_ret);

        assert_eq!(return_code, OK);
        assert_eq!(unsafe { (*p_ret).value }, unsafe { *dest as u64 });
    }
    val = [0; 16];

    assert_eq!(range(&mut root_container_array, val.as_mut_ptr(), 1, range_callback), OK);
    assert_eq!(RANGE_QUERY_COUNTER.load(Relaxed), elements as i32);
    clear_test();
}

#[test]
fn test_container_split_08() {
    let _lock = TEST_MUTEX.lock().unwrap();
    RANGE_QUERY_COUNTER.store(0, Relaxed);
    let elements: u32 = 100000;
    let mut node_value = NodeValue {
        value: 0
    };
    let mut val: [u8; 16] = [0; 16];
    let mut root_container_array = bootstrap();
    let dest = unsafe { val.as_mut_ptr().add(2) as *mut u16 };
    unsafe { *dest = 0; }

    for i in 0..elements {
        unsafe {
            *dest = i as u16;
            node_value.value = *dest as u64;
            copy_nonoverlapping(dest, val.as_mut_ptr().add(4) as *mut u16, 1);
        }
        log_to_file(&format!("i: {}", i));
        put(&mut root_container_array, val.as_mut_ptr(), 8, Some(&mut node_value));
    }


    let mut p_ret = &mut node_value as *mut NodeValue;

    for i in 0..elements {
        unsafe {
            *dest = i as u16;
            copy_nonoverlapping(dest, (val.as_mut_ptr() as *mut u16).add(2), 1);
        }
        log_to_file(&format!("i: {}", i));
        let return_code = get(&mut root_container_array, val.as_mut_ptr(), 8, &mut p_ret);

        assert_eq!(return_code, OK);
        assert_eq!(unsafe { (*p_ret).value }, unsafe { *dest as u64 });
    }
    clear_test();
}

#[test]
fn ycsb() -> Result<(), io::Error> {
    let _lock = TEST_MUTEX.lock().unwrap();
    let mut root_container_array = bootstrap();

    let file = File::open("kv_input.txt")?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        if let Some((key, value_str)) = line.split_once(',') {
            let value: u64 = value_str.parse().unwrap();
            let mut key_bytes = key.as_bytes();
            let mut val = NodeValue { value };
            unsafe {
                put(&mut root_container_array, key_bytes.as_ptr() as *mut u8, key_bytes.len() as u16, Some(&mut val));
            }
        }
    }
    clear_test();
    Ok(())
}

#[test]
#[ignore]
fn test_container_split_09() {
    let _lock = TEST_MUTEX.lock().unwrap();
    let base_seed1: i32 = 16530;//rand::random_range(0..32767);
    let base_seed2: i32 = 21062;//rand::random_range(0..32767);
    println!("base1: {}, base2: {}", base_seed1, base_seed2);
    let seed1 = base_seed1;
    let mut seed2 = base_seed2;

    let mut node_value = NodeValue {
        value: 0
    };
    let mut val: [u8; 8] = [0; 8];
    let dest = unsafe { val.as_mut_ptr().add(2) as *mut i32 };

    for elements in (2000..65536).step_by(2000) {
        eprintln!("Elements: {}", elements);
        RANGE_QUERY_COUNTER.store(0, Relaxed);
        val.fill(0);
        let mut root_container_array = bootstrap();

        for i in 0..elements {
            node_value.value = val[1] as u64;

            for j in 0..elements {
                unsafe {  write_unaligned(dest, seed2.wrapping_mul(read_unaligned(dest)).wrapping_add(seed1)); }
                log_to_file(&format!("i: {}, j: {}", i, j));
                put(&mut root_container_array, val.as_mut_ptr(), 8, Some(&mut node_value));
            }
        }

        let mut p_ret = &mut node_value as *mut NodeValue;
        val.fill(0);

        for i in 0..elements {
            node_value.value = val[1] as u64;

            for j in 0..elements {
                unsafe {  write_unaligned(dest, seed2.wrapping_mul(read_unaligned(dest)).wrapping_add(seed1)); }
                log_to_file(&format!("i: {}, j: {}", i, j));
                let ret = get(&mut root_container_array, val.as_mut_ptr(), 8, &mut p_ret);
                assert_eq!(ret, OK);
                assert_eq!(unsafe { (*p_ret).value }, val[1] as u64);
            }
        }

    }
    clear_test();
}