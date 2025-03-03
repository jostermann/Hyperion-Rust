use hyperion_rust::hyperion::api::{bootstrap, get_root_container_entry};
use hyperion_rust::hyperion::components::container::Container;
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

    let hyp_ptr = initialize_container(data.arena.as_mut().unwrap().as_mut());
    assert_eq!(hyp_ptr.superbin_id(), 1);
    assert_eq!(hyp_ptr.metabin_id(), 0);
    assert_eq!(hyp_ptr.bin_id(), 0);
    assert_eq!(hyp_ptr.chunk_id(), 1);
}

/*#[test]
fn test_container_jumptable_01 () {
    let mut val: [u8; 2] = [0, 0];
    let mut root_container_array = bootstrap();
    let rce = get_root_container_entry(&mut root_container_array, "00".as_ptr(), 2);
    let mut data = rce.inner.lock();
    let mut arena = data.arena.take().unwrap();

    for i in 0..10 {
        val[0] = i;
        put_debug(arena.as_mut(), data.hyperion_pointer.as_mut().unwrap(), &mut val[0], 2, None);
    }

    let container =
        get_pointer(arena.as_mut(), data.hyperion_pointer.as_mut().unwrap(), 0, val[0]) as *mut Container;
    assert_eq!(unsafe { (*container).jump_table() }, 0);

    val[0] = 16;
    put_debug(arena.as_mut(), data.hyperion_pointer.as_mut().unwrap(), &mut val[0], 2, None);
    val[0] = 17;
    put_debug(arena.as_mut(), data.hyperion_pointer.as_mut().unwrap(), &mut val[0], 2, None);
    val[0] = 18;
    put_debug(arena.as_mut(), data.hyperion_pointer.as_mut().unwrap(), &mut val[0], 2, None);

    let container2 =
        get_pointer(arena.as_mut(), data.hyperion_pointer.as_mut().unwrap(), 0, val[0]) as *mut Container;
    assert!(unsafe { (*container2).jump_table() > 0 });
}*/

