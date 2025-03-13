use hyperion_rust::hyperion::api::{bootstrap, clear_test, get, get_root_container_entry, log_to_file, put};
use hyperion_rust::hyperion::components::container::Container;
use hyperion_rust::hyperion::components::node::NodeValue;
use hyperion_rust::hyperion::components::return_codes::ReturnCode::OK;
use hyperion_rust::hyperion::internals::atomic_pointer::initialize_container;
use hyperion_rust::hyperion::internals::core::put_debug;
use hyperion_rust::memorymanager::api::get_pointer;

#[test]
fn test_initialize_container_001() {
    let mut root_container_array = bootstrap();
    let mut key: &str = "00";
    let rce = get_root_container_entry(&mut root_container_array, key.as_ptr(), 2);
    let mut data = rce.inner.lock();
    assert_eq!(data.hyperion_pointer.as_mut().unwrap().superbin_id(), 1);
    assert_eq!(data.hyperion_pointer.as_mut().unwrap().metabin_id(), 0);
    assert_eq!(data.hyperion_pointer.as_mut().unwrap().bin_id(), 0);
    assert_eq!(data.hyperion_pointer.as_mut().unwrap().chunk_id(), 0);

    let hyp_ptr = initialize_container(data.arena.unwrap());
    assert_eq!(hyp_ptr.superbin_id(), 1);
    assert_eq!(hyp_ptr.metabin_id(), 0);
    assert_eq!(hyp_ptr.bin_id(), 0);
    assert_eq!(hyp_ptr.chunk_id(), 1);
}

#[test]
fn test_container_jumptable_01 () {
    let mut val: [u8; 2] = [0, 0];
    let mut root_container_array = bootstrap();
    let rce = get_root_container_entry(&mut root_container_array, "00".as_ptr(), 2);
    let mut data = rce.inner.lock();

    for i in 0..10 {
        val[0] = i;
        put_debug(data.arena.unwrap(), data.hyperion_pointer.as_mut().unwrap(), &mut val[0], 2, None);
    }


    let container = get_pointer(data.arena.unwrap(), data.hyperion_pointer.as_mut().unwrap(), 0, val[0]) as *mut Container;
    assert_eq!(unsafe { (*container).jump_table() }, 0);
    clear_test();
}

#[test]
fn test_container_split_01 () {
    //unsafe { backtrace_on_stack_overflow::enable() };
    let elements = 256;
    let limit = 103;
    let mut node_value = NodeValue {
        v: 0
    };
    let mut val: [u8; 128] = [0; 128];
    let mut root_container_array = bootstrap();

    for i in 100..limit {
        for j in 0..elements {
            node_value.v = i + j;
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
            assert_eq!(unsafe { (*p_ret).v }, i + j);
        }
    }
    clear_test();
}

#[test]
fn test_container_split_02() {
    let elements = 256;
    let limit = 106;
    let mut node_value = NodeValue {
        v: 0
    };
    let mut val: [u8; 128] = [0; 128];
    let mut root_container_array = bootstrap();

    for i in 100..limit {
        for j in 0..elements {
            node_value.v = i + j;
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
            assert_eq!(unsafe { (*p_ret).v }, i + j);
        }
    }
    clear_test();
}

#[test]
fn test_container_split_03() {
    let elements = 256;
    let limit = 116;
    let mut node_value = NodeValue {
        v: 0
    };
    let mut val: [u8; 128] = [0; 128];
    let mut root_container_array = bootstrap();

    for i in 100..limit {
        for j in 0..elements {
            node_value.v = i + j;
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
            assert_eq!(unsafe { (*p_ret).v }, i + j);
        }
    }
    clear_test();
}

#[test]
fn test_container_split_04() {
    let elements = 256;
    let limit = 200;
    let mut node_value = NodeValue {
        v: 0
    };
    let mut val: [u8; 128] = [0; 128];
    let mut root_container_array = bootstrap();

    for i in 100..limit {
        for j in 0..elements {
            node_value.v = i + j;
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
            assert_eq!(unsafe { (*p_ret).v }, i + j);
        }
    }
    clear_test();
}

#[test]
fn test_container_split_05() {
    let elements = 256;
    let limit = 109;
    let mut node_value = NodeValue {
        v: 0
    };
    let mut val: [u8; 128] = [0; 128];
    let mut root_container_array = bootstrap();

    for i in 0..limit {
        for j in 0..elements {
            node_value.v = i + j;
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
            assert_eq!(unsafe { (*p_ret).v }, i + j);
        }
    }
    clear_test();
}

use rand::Rng;

#[test]
fn test_container_split_06() {
    let elements = 25000;
    let mut node_value = NodeValue {
        v: 0
    };
    let mut val: [u8; 128] = [0; 128];
    let mut root_container_array = bootstrap();
    let base_seed1: i32 = rand::random_range(0..=65535);
    let base_seed2: i32 = rand::random_range(0..=65535);
    println!("base1: {}, base2: {}", base_seed1, base_seed2);
    let mut seed1 = base_seed1;
    let mut seed2 = base_seed2;

    let dest = unsafe { (val.as_mut_ptr() as *mut u16).add(1) };
    unsafe { *dest = 0; }

    for i in 0..elements {
        unsafe {
            let current_value = *dest;
            *dest = (seed2.wrapping_mul(current_value as i32).wrapping_add(seed1) % 65536) as u16;
            node_value.v = *dest as u64;
        }
        log_to_file(&format!("i: {}", i));
        put(&mut root_container_array, val.as_mut_ptr(), 4, Some(&mut node_value));
    }


    let mut p_ret = &mut node_value as *mut NodeValue;
    unsafe { *dest = 0; }
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
        assert_eq!(unsafe { (*p_ret).v }, unsafe { *dest as u64 });
    }
    clear_test();
}

#[test]
fn test_container_split_06b() {
    let elements = 4506;
    let mut node_value = NodeValue {
        v: 0
    };
    let mut val: [u8; 128] = [0; 128];
    let mut root_container_array = bootstrap();
    let base_seed1: i32 = 26948;
    let base_seed2: i32 = 39085;
    let mut seed1 = base_seed1;
    let mut seed2 = base_seed2;

    let dest = unsafe { (val.as_mut_ptr() as *mut u16).add(1) };
    unsafe { *dest = 0; }

    for i in 0..elements {
        unsafe {
            let current_value = *dest;
            *dest = (seed2.wrapping_mul(current_value as i32).wrapping_add(seed1) % 65536) as u16;
            node_value.v = *dest as u64;
        }
        log_to_file(&format!("i: {}", i));
        put(&mut root_container_array, val.as_mut_ptr(), 4, Some(&mut node_value));
    }


    let mut p_ret = &mut node_value as *mut NodeValue;
    unsafe { *dest = 0; }
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
        assert_eq!(unsafe { (*p_ret).v }, unsafe { *dest as u64 });
    }
    clear_test();
}

#[test]
fn test_container_split_07() {

}