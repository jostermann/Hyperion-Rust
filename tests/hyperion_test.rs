use std::fmt::format;
use hyperion_rust::hyperion::api::{bootstrap, get, get_root_container_entry, put};
use hyperion_rust::hyperion::components::container::Container;
use hyperion_rust::hyperion::components::node::NodeValue;
use hyperion_rust::hyperion::internals::atomic_pointer::initialize_container;
use hyperion_rust::hyperion::internals::core::put_debug;
use hyperion_rust::memorymanager::api::get_pointer;
use std::fs::OpenOptions;
use std::io::Write;
use hyperion_rust::hyperion::components::return_codes::ReturnCode::OK;

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
}

const LOG: bool = true;
pub fn log_to_file(msg: &str) {
    if !LOG { return; }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("debug.log")
        .unwrap();
    writeln!(file, "{}", msg).unwrap();
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
            log_to_file(&format!("i: {}, j: {}", i, j));
            assert_eq!(get(&mut root_container_array, val.as_mut_ptr(), 4, &mut p_ret), OK);
            assert_eq!(unsafe { (*p_ret).v }, i + j);
        }
    }
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
            log_to_file(&format!("i: {}, j: {}", i, j));
            assert_eq!(get(&mut root_container_array, val.as_mut_ptr(), 4, &mut p_ret), OK);
            assert_eq!(unsafe { (*p_ret).v }, i + j);
        }
    }
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
}