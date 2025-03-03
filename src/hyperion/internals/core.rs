use crate::hyperion::components::container::{get_container_head_size, shift_container, Container, EmbeddedContainer, RootContainerEntry, CONTAINER_MAX_EMBEDDED_DEPTH};
use crate::hyperion::components::operation_context::ContainerValidTypes::ContainerValid;
use crate::hyperion::components::operation_context::JumpStates::{JumpPoint1, JumpPoint2, NoJump};
use crate::hyperion::components::context::{ContainerTraversalContext, ContainerTraversalHeader, EmbeddedTraversalContext, JumpContext, OperationCommand, RangeQueryContext, TraversalContext, TraversalType};
use crate::hyperion::components::operation_context::OperationContextHeader;
use crate::hyperion::components::jump_table::TOPLEVEL_NODE_JUMP_HWM;
use crate::hyperion::components::node::NodeType::{Invalid, LeafNodeWithValue};
use crate::hyperion::components::node::{get_sub_node_key, get_top_node_key, Node, NodeValue};
use crate::hyperion::components::node_header::{as_sub_node, as_sub_node_mut, as_top_node, as_top_node_mut, compare_path_compressed_node, delete_node, get_child_container_nomod, get_jump_value, get_node_value, get_offset_child_container, get_offset_jump, get_offset_sub_node, get_offset_top_node, get_successor, use_sub_node_jump_table, NodeHeader};
use crate::hyperion::components::return_codes::ReturnCode;
use crate::hyperion::components::return_codes::ReturnCode::{GetFailureNoNode, UnknownOperation, OK};
use crate::hyperion::components::sub_node::ChildLinkType;
use crate::hyperion::components::sub_node::ChildLinkType::PathCompressed;
use crate::hyperion::components::top_node::TopNode;
use crate::hyperion::internals::atomic_pointer::{AtomicChar, AtomicPointer, Atomicu8, CONTAINER_SIZE_TYPE_0};
use crate::hyperion::preprocessor::key_preprocessor::KeyProcessingIDs;
use crate::memorymanager::api::{free, get_chained_pointer, get_pointer, is_chained_pointer, malloc, malloc_chained, reallocate, register_chained_memory, Arena, HyperionPointer, CONTAINER_MAX_SPLITS, CONTAINER_SPLIT_BITS};
use bitfield_struct::bitfield;
use libc::{calloc, malloc_info, memcmp, size_t, tm};
use std::cmp::Ordering;
use std::ffi::c_void;
use std::mem::needs_drop;
use std::ptr::{copy, copy_nonoverlapping, null, null_mut, write_bytes, NonNull};
use std::sync::Mutex;
use crate::hyperion::components::context::OperationCommand::Put;
use crate::hyperion::components::operation_context::{insert_jump, insert_top_level_jumptable, new_expand, scan_put, scan_put_embedded, scan_put_single, ContainerValidTypes, OperationContext};

pub const CONTAINER_SPLIT_THRESHOLD_A: usize = 12288;
pub const CONTAINER_SPLIT_THRESHOLD_B: usize = 65536;
pub type HyperionCallback = fn(key: &mut u8, key_len: u16, value: *mut c_void) -> bool;

#[bitfield(u64, order = Msb)]
pub struct GlobalConfigurationHeader {
    #[bits(1)]
    pub initialized: u8,
    #[bits(1)]
    pub thread_keep_alive: u8,
    #[bits(2)]
    pub preprocessor_strategy: KeyProcessingIDs,
    #[bits(8)]
    pub container_size_increment: u8,
    #[bits(16)]
    pub io_threads: u16,
    #[bits(32)]
    pub container_embedding_high_watermark: u32,
    #[bits(4)]
    __: u8
}

pub struct GlobalConfiguration {
    pub header: GlobalConfigurationHeader,
    pub top_level_successor_threshold: u32,
    pub container_embedding_limit: u32,
    pub num_writes_million: i64,
    pub num_reads_million: i64
}

pub static GLOBAL_CONFIG: Lazy<RwLock<GlobalConfiguration>> = Lazy::new(|| RwLock::new(GlobalConfiguration {
    header: GlobalConfigurationHeader::new()
        .with_initialized(0)
        .with_thread_keep_alive(0)
        .with_preprocessor_strategy(KeyProcessingIDs::None)
        .with_container_size_increment(32)
        .with_io_threads(1)
        .with_container_embedding_high_watermark(0),
    top_level_successor_threshold: 0,
    container_embedding_limit: 0,
    num_writes_million: 0,
    num_reads_million: 0
}));

pub fn get_global_cfg() -> *mut GlobalConfiguration {
    GLOBAL_CONFIG.as_mut_ptr()
}

pub fn initialize_ejected_container(arena: &mut Arena, required_size: u32) -> HyperionPointer {
    let container_size_increment = GLOBAL_CONFIG.read().header.container_size_increment();
    let null_ptr: *const c_void = null();
    let target_size: usize = (((required_size as usize - CONTAINER_SIZE_TYPE_0 + size_of_val(&null_ptr)) / container_size_increment as usize) + 1) * container_size_increment as usize + CONTAINER_SIZE_TYPE_0;
    let mut pointer: HyperionPointer = malloc(arena, target_size);
    let container: &mut Container = unsafe { (get_pointer(arena, &mut pointer, 1, 0) as *mut Container).as_mut().unwrap() };
    container.set_size(target_size as u32);
    container.set_free_size_left((target_size - container.get_container_head_size() as usize) as u32);
    pointer
}

pub fn split_container(ocx: &mut OperationContext) -> bool {
    let roundup_factor = 32;

    if ocx.get_root_container().jump_table() == 0 {
        if ocx.get_root_container().split_delay() < 3 {
            let current_value = ocx.get_root_container().split_delay();
            ocx.get_root_container().set_split_delay(current_value + 1);
        }
        return false;
    }

    let jumptable_entry = ocx.get_root_container().get_jump_table_pointer();
    let jumptable_size = ocx.get_root_container().get_jump_table_entry_count();
    let key_max = unsafe {
        (*(jumptable_entry.add(jumptable_size as usize + 1))).key()
    };

    let mut ctx: ContainerTraversalContext = ContainerTraversalContext {
        header: ContainerTraversalHeader::default(),
        last_top_char_seen: 0,
        last_sub_char_seen: 0,
        current_container_offset: ocx.get_root_container().get_container_head_size() + ocx.get_root_container().get_jump_table_size(),
        safe_offset: 0,
        first_char: 0,
        second_char: 0,
    };

    ctx.header.set_last_top_char_set(true);
    let p_first = unsafe {
        (ocx.get_root_container_pointer() as *mut c_void).add(ctx.current_container_offset as usize) as *mut Node
    };

    let left_init_char = unsafe { (*p_first).stored_value };

    let same_category = (key_max >> (8 - CONTAINER_SPLIT_BITS)) - (left_init_char >> (8 - CONTAINER_SPLIT_BITS));
    let diff = key_max - left_init_char;

    let mut node_cache = Node {
        header: NodeHeader::new_top_node(TopNode::default()),
        stored_value: 0,
    };

    let mut p_successor = NonNull::new(&mut node_cache as *mut Node);
    assert!(diff > 0);

    if same_category == 0 || diff < (256 / CONTAINER_MAX_SPLITS) as u8 {
        if ocx.get_root_container().split_delay() < 3 {
            let current_value = ocx.get_root_container().split_delay();
            ocx.get_root_container().set_split_delay(current_value);
        }
        return false;
    }

    let mut right_init_char = unsafe {
        (((*(jumptable_entry.add(jumptable_size as usize / 2))).key() as u16 >> (8 - CONTAINER_SPLIT_BITS)) + 1) * (256 / CONTAINER_MAX_SPLITS) as u16
    };

    if right_init_char > key_max as u16 {
        right_init_char -= 256 / CONTAINER_MAX_SPLITS as u16;
    }

    if right_init_char < unsafe { (*jumptable_entry).key() as u16 } {
        if ocx.get_root_container().split_delay() < 3 {
            let current_value = ocx.get_root_container().split_delay();
            ocx.get_root_container().set_split_delay(current_value);
        }
        return false;
    }

    ctx.header.set_last_top_char_set(true);
    ctx.last_top_char_seen = ocx.get_root_container().use_jumptable_2((right_init_char - 1) as u8, &mut ctx.current_container_offset);
    let mut node_head = unsafe { (ocx.get_root_container_pointer() as *mut char).add(ctx.current_container_offset as usize) as *mut NodeHeader };
    let mut skipped = 0;
    let mut previous: *mut NodeHeader = null_mut();

    while (ctx.last_top_char_seen as u16) < right_init_char {
        skipped = get_successor(node_head, &mut p_successor, ocx, &mut ctx);
        if skipped == 0 {
            break;
        }
        ctx.current_container_offset += skipped as i32;
        previous = node_head;
        node_head = unsafe { &mut (*(p_successor.unwrap().as_ptr())).header as *mut NodeHeader };
        assert_eq!(as_top_node(node_head).container_type(), 0);
        ctx.last_top_char_seen = get_top_node_key(node_head as *mut Node, &mut ctx);
        if (ctx.last_top_char_seen as u16) >= right_init_char {
            break;
        }
        ocx.jump_context.as_mut().unwrap().top_node_key = ctx.last_top_char_seen as i32;
    }

    if previous.is_null() {
        if ocx.get_root_container().split_delay() < 3 {
            let current_value = ocx.get_root_container().split_delay();
            ocx.get_root_container().set_split_delay(current_value);
        }
        return false;
    }

    let basic_head_size = ocx.get_root_container().get_container_head_size();
    let old_container_head = basic_head_size + ocx.get_root_container().get_jump_table_size();
    let mut data_size = ctx.current_container_offset - old_container_head;
    let mut second_size = ocx.get_root_container().size() as i32 - (ctx.current_container_offset + ocx.get_root_container().free_bytes() as i32);
    if data_size < 3072 || second_size < 3072 {
        if ocx.get_root_container().split_delay() < 3 {
            let current_value = ocx.get_root_container().split_delay();
            ocx.get_root_container().set_split_delay(current_value);
        }
        return false;
    }

    let mut chain_head: HyperionPointer;
    let left_data: *mut c_void;
    let mut src = unsafe {
        (ocx.get_root_container_pointer() as *mut c_void).add(old_container_head as usize)
    };
    let required_left = (ctx.current_container_offset - old_container_head) + get_container_head_size();
    let target_size_left = ((required_left / roundup_factor) + 2) * roundup_factor;
    let malloc_size_left = target_size_left + 128;
    let is_chain = is_chained_pointer(ocx.arena.as_mut().unwrap().as_mut(), &mut ocx.embedded_traversal_context.as_mut().unwrap().root_container_pointer);

    if is_chain {
        chain_head = *ocx.embedded_traversal_context.as_mut().unwrap().root_container_pointer;
        left_data = unsafe { calloc(malloc_size_left as size_t, 1) };
    }
    else {
        chain_head = malloc_chained(ocx.arena.as_mut().unwrap().as_mut(), malloc_size_left as usize, 1);
        left_data = get_chained_pointer(ocx.arena.as_mut().unwrap().as_mut(), &mut chain_head, left_init_char, false, malloc_size_left as usize);
    }

    let left_target = unsafe { left_data.add(basic_head_size as usize) };
    let left_head = left_data as *mut Container;

    unsafe {
        copy_nonoverlapping(src as *mut u8, left_target as *mut u8, data_size as usize);
    }
    unsafe { (*left_head).set_size(target_size_left as u32) };

    unsafe {
        if as_top_node(previous).jump_successor_present() {
            let previous_offset = (previous as *mut c_void).offset_from(src);
            let new_previous = left_target.add(previous_offset as usize) as *mut NodeHeader;
            let succ_jump = (new_previous as *mut c_void).add(get_offset_jump(new_previous));
            let jump_size = *(succ_jump as *mut u16);
            let shift_amount = jump_size as usize - (size_of::<u16>() + get_offset_jump(new_previous));
            copy(succ_jump.add(size_of::<u16>()) as *mut u8, succ_jump as *mut u8, shift_amount);
            write_bytes(succ_jump.add(shift_amount) as *mut u8, 0, size_of::<u16>());
            data_size -= size_of::<u16>() as i32;
            as_top_node_mut(new_previous).set_jump_successor_present(false);
        }

        (*left_head).set_jump_table(0);
        (*left_head).set_free_bytes((target_size_left - (data_size + (*left_head).get_container_head_size())) as u8);
    }

    let overallocated_left = malloc_size_left - target_size_left;

    let required_right = second_size + get_container_head_size();
    let target_size_right = ((required_right / roundup_factor) + 1) * roundup_factor;
    let malloc_size_right = target_size_right + 256;

    let right_data = if is_chain {
        unsafe { calloc(malloc_size_right as size_t, 1) }
    }
    else {
        get_chained_pointer(ocx.arena.as_mut().unwrap().as_mut(), &mut chain_head, right_init_char as u8, true, malloc_size_right as usize)
    };

    let right_head = right_data as *mut Container;
    unsafe {
        (*right_head).set_size(target_size_right as u32);
        (*right_head).set_jump_table(0);
        (*right_head).set_free_bytes((target_size_right - (second_size + (*right_head).get_container_head_size())) as u8);
    }
    let overallcoated_right = malloc_size_right - target_size_right;
    unsafe {
        let mut right_target = (right_head as *mut c_void).add((*right_head).get_container_head_size() as usize);
        src = (ocx.get_root_container_pointer() as *mut c_void).add(ctx.current_container_offset as usize);
        let node = src as *mut Node;
        assert_ne!(as_top_node(&mut (*node).header as *mut NodeHeader).type_flag(), Invalid);

        if as_top_node(&mut (*node).header as *mut NodeHeader).delta() == 0 {
            (*node).stored_value = ctx.last_top_char_seen;
            copy_nonoverlapping(node as *mut u8, right_target as *mut u8, second_size as usize);
        }
        else {
            as_top_node_mut(&mut (*node).header as *mut NodeHeader).set_delta(0);
            let target_node = right_target as *mut Node;
            copy_nonoverlapping(node as *mut u8, target_node as *mut u8, 1);
            (*target_node).stored_value = ctx.last_top_char_seen;

            right_target = right_target.add(2);
            src = src.add(1);
            second_size -= 1;
            (*right_head).set_free_bytes((*right_head).free_bytes() - 1);

            if as_top_node(&mut (*node).header as *mut NodeHeader).jump_successor_present() {
                let p_sj = src as *mut u16;
                *p_sj += 1;
            }
            copy_nonoverlapping(src as *mut u8, right_target as *mut u8, second_size as usize);
        }
    }

    if is_chain {
        register_chained_memory(ocx.arena.as_mut().unwrap().as_mut(), &mut ocx.embedded_traversal_context.as_mut().unwrap().root_container_pointer, left_init_char, left_data, target_size_left as usize, false, overallocated_left);
        register_chained_memory(ocx.arena.as_mut().unwrap().as_mut(), &mut ocx.embedded_traversal_context.as_mut().unwrap().root_container_pointer, right_init_char as u8, right_data, target_size_right as usize, true, overallcoated_right);
    }
    else {
        free(ocx.arena.as_mut().unwrap().as_mut(), &mut ocx.embedded_traversal_context.as_mut().unwrap().root_container_pointer);
    }

    let mut tmp_ctx = ContainerTraversalContext {
        header: ContainerTraversalHeader::default(),
        last_top_char_seen: 0,
        last_sub_char_seen: 0,
        current_container_offset: 0,
        safe_offset: 0,
        first_char: left_init_char,
        second_char: 0,
    };

    let arena_ptr = ocx.arena.as_mut().unwrap().as_mut() as *mut Arena;

    let mut tmp_ocx = OperationContext {
        header: OperationContextHeader::default(),
        chained_pointer_hook: tmp_ctx.first_char,
        key_len_left: 0,
        key: None,
        jump_context: None,
        root_container_entry: None,
        embedded_traversal_context: Some(EmbeddedTraversalContext {
            root_container: unsafe { Box::from_raw(get_chained_pointer(ocx.arena.as_mut().unwrap().as_mut(), &mut chain_head, tmp_ctx.first_char, false, 0) as *mut Container) },
            next_embedded_container: None,
            embedded_stack: None,
            next_embedded_container_offset: 0,
            embedded_container_depth: 0,
            root_container_pointer: unsafe { Box::from_raw(&mut chain_head as *mut HyperionPointer) },
        }),
        jump_table_sub_context: None,
        next_container_pointer: None,
        arena: unsafe { Some(Box::from_raw(arena_ptr)) },
        path_compressed_ejection_context: None,
        return_value: None,
        input_value: None,
        container_injection_context: None,
    };
    insert_top_level_jumptable(&mut tmp_ocx, &mut tmp_ctx);

    let mut tmp_ctx = ContainerTraversalContext {
        header: ContainerTraversalHeader::default(),
        last_top_char_seen: 0,
        last_sub_char_seen: 0,
        current_container_offset: 0,
        safe_offset: 0,
        first_char: right_init_char as u8,
        second_char: 0,
    };

    let mut tmp_ocx = OperationContext {
        header: OperationContextHeader::default(),
        chained_pointer_hook: tmp_ctx.first_char,
        key_len_left: 0,
        key: None,
        jump_context: None,
        root_container_entry: None,
        embedded_traversal_context: Some(EmbeddedTraversalContext {
            root_container: unsafe { Box::from_raw(get_chained_pointer(ocx.arena.as_mut().unwrap().as_mut(), &mut chain_head, tmp_ctx.first_char, false, 0) as *mut Container) },
            next_embedded_container: None,
            embedded_stack: None,
            next_embedded_container_offset: 0,
            embedded_container_depth: 0,
            root_container_pointer: unsafe { Box::from_raw(&mut chain_head as *mut HyperionPointer) },
        }),
        jump_table_sub_context: None,
        next_container_pointer: None,
        arena: unsafe { Some(Box::from_raw(arena_ptr)) },
        path_compressed_ejection_context: None,
        return_value: None,
        input_value: None,
        container_injection_context: None,
    };
    insert_top_level_jumptable(&mut tmp_ocx, &mut tmp_ctx);
    ocx.next_container_pointer = Some(Box::new(chain_head));
    ocx.header.set_next_container_valid(ContainerValid);
    true
}

pub fn scan_meta_embedded(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, mut node_head_ptr: &mut Option<NonNull<NodeHeader>>) -> ReturnCode {
    let switch_condition: TraversalType = ctx.as_combined_header();
    let mut key;

    while ctx.current_container_offset < (ocx.get_next_embedded_container().size() as i32) {
        let node_head = unsafe {
            (ocx.get_next_embedded_container_pointer() as *mut c_void).add(ctx.current_container_offset as usize) as *mut NodeHeader
        };
        ctx.header.set_node_type(if as_top_node(node_head).type_flag() == Invalid { 0 } else { 1 });
        ctx.header.set_container_type(as_top_node(node_head).container_type());

        match switch_condition {
            TraversalType::FilledOneCharTopNode => {
                key = get_top_node_key(node_head as *mut Node, ctx);
                match key.cmp(&ctx.first_char) {
                    Ordering::Less => {
                        ctx.current_container_offset += get_offset_top_node(node_head) as i32;
                        ctx.header.set_last_top_char_set(true);
                        ctx.last_top_char_seen = key;
                        continue;
                    }
                    Ordering::Equal => {
                        *node_head_ptr = NonNull::new(node_head);
                        return OK;
                    }
                    Ordering::Greater => {
                        return GetFailureNoNode;
                    }
                }
            }
            TraversalType::FilledTwoCharTopNode => {
                key = get_top_node_key(node_head as *mut Node, ctx);
                match key.cmp(&ctx.first_char) {
                    Ordering::Less => {
                        ctx.current_container_offset += get_offset_top_node(node_head) as i32;
                        ctx.header.set_last_top_char_set(true);
                        ctx.last_top_char_seen = key;
                        continue;
                    }
                    Ordering::Equal => {
                        ctx.current_container_offset += get_offset_top_node(node_head) as i32;
                        ctx.header.set_in_first_char_scope(true);
                        continue;
                    }
                    Ordering::Greater => {
                        return GetFailureNoNode;
                    }
                }
            }
            TraversalType::FilledOneCharSubNode | TraversalType::FilledTwoCharSubNode => {
                ctx.current_container_offset += get_offset_sub_node(node_head) as i32;
                continue;
            }
            TraversalType::FilledTwoCharSubNodeInFirstCharScope => {
                key = get_top_node_key(node_head as *mut Node, ctx);
                if key < ctx.second_char {
                    ctx.current_container_offset += get_offset_sub_node(node_head) as i32;
                    ctx.header.set_last_sub_char_set(true);
                    ctx.last_sub_char_seen = key;
                    continue;
                }

                if key == ctx.second_char {
                    if ctx.header.end_operation() {
                        *node_head_ptr = NonNull::new(node_head);
                        return OK;
                    }

                    match as_sub_node(node_head).child_container() {
                        PathCompressed => {
                            if !compare_path_compressed_node(node_head, ocx) {
                                ocx.header.set_pathcompressed_child(true);
                                ctx.header.set_end_operation(true);
                                *node_head_ptr = NonNull::new(node_head);
                                return OK;
                            }
                        }
                        ChildLinkType::None => {
                            return GetFailureNoNode;
                        }
                        _ => {
                            let mut next_container_pointer = ocx.next_container_pointer.take();
                            let ret = get_child_container_nomod(node_head, &mut next_container_pointer, ocx, ctx);
                            ocx.next_container_pointer = next_container_pointer;
                            return ret;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    GetFailureNoNode
}

fn scan_meta_phase2(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, mut node_head_ptr: &mut Option<NonNull<NodeHeader>>, destination: u8) -> ReturnCode {
    let mut jump_point = NoJump;
    ctx.last_sub_char_seen = destination;
    let mut node_head = unsafe {
        (ocx.get_root_container_pointer() as *mut char).add(ctx.current_container_offset as usize) as *mut NodeHeader
    };
    if !ctx.header.last_sub_char_set() {
        if as_top_node(node_head).container_type() == 0 {
            return GetFailureNoNode;
        }
        ctx.last_sub_char_seen = get_sub_node_key(node_head as *mut Node, ctx, false);
    }

    loop {
        match jump_point {
            JumpPoint1 => {
                if ctx.safe_offset <= ctx.current_container_offset {
                    return GetFailureNoNode;
                }
                if as_top_node(node_head).container_type() == 0 {
                    return GetFailureNoNode;
                }
                ctx.last_sub_char_seen = get_sub_node_key(node_head as *mut Node, ctx, true);
                jump_point = NoJump;
                continue;
            }
            NoJump => {
                match ctx.last_sub_char_seen.cmp(&ctx.second_char) {
                    Ordering::Less => {
                        ctx.current_container_offset += get_offset_sub_node(node_head) as i32;
                        node_head = unsafe { (ocx.get_root_container_pointer() as *mut char).add(ctx.current_container_offset as usize) as *mut NodeHeader };
                        jump_point = JumpPoint1;
                        continue;
                    }
                    Ordering::Equal => {
                        if ctx.header.end_operation() {
                            *node_head_ptr = NonNull::new(node_head);
                            return OK;
                        }

                        return match as_sub_node(node_head).child_container() {
                            PathCompressed => {
                                if compare_path_compressed_node(node_head, ocx) {
                                    ocx.header.set_pathcompressed_child(true);
                                    ctx.header.set_end_operation(true);
                                    *node_head_ptr = NonNull::new(node_head);
                                    return OK;
                                }
                                GetFailureNoNode
                            }
                            ChildLinkType::None => {
                                GetFailureNoNode
                            }
                            _ => {
                                let mut next_container_pointer = ocx.next_container_pointer.take();
                                let ret = get_child_container_nomod(node_head, &mut next_container_pointer, ocx, ctx);
                                ocx.next_container_pointer = next_container_pointer;
                                ret
                            }
                        }
                    }
                    Ordering::Greater => {
                        return GetFailureNoNode;
                    }
                }
            }
            _ => { break; }
        }
    }
    GetFailureNoNode
}

fn scan_meta_single(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, mut node_head_ptr: &mut Option<NonNull<NodeHeader>>) -> ReturnCode {
    let mut node_head = null_mut();
    let mut key = 0;
    let mut jump_point = NoJump;
    ctx.safe_offset = ocx.get_root_container().size() as i32 - ocx.get_root_container().free_bytes() as i32;

    if ocx.get_root_container().jump_table() == 0 {
        ctx.current_container_offset = ocx.get_root_container().get_container_head_size();
    }
    else {
        key = ocx.get_root_container().use_jumptable_2(ctx.first_char, &mut ctx.current_container_offset);
        node_head = unsafe { (ocx.get_root_container_pointer() as *mut char).add(ctx.current_container_offset as usize) as *mut NodeHeader };

        if key != 0 {
            jump_point = JumpPoint1;
        }
    }

    loop {
        match jump_point {
            NoJump => {
                jump_point = NoJump;
                if ctx.safe_offset <= ctx.current_container_offset {
                    return GetFailureNoNode;
                }
                node_head = unsafe { (ocx.get_root_container_pointer() as *mut char).add(ctx.current_container_offset as usize) as *mut NodeHeader };

                if as_top_node(node_head).container_type() == 0 {
                    jump_point = JumpPoint1;
                    key = get_top_node_key(node_head as *mut Node, ctx);
                    continue;
                }
                ctx.current_container_offset += get_offset_sub_node(node_head) as i32;
            }
            JumpPoint1 => {
                jump_point = NoJump;
                match key.cmp(&ctx.first_char) {
                    Ordering::Less => {
                        if as_top_node(node_head).jump_successor_present() {
                            ctx.current_container_offset += get_jump_value(node_head) as i32;
                        }
                        else {
                            ctx.current_container_offset += get_offset_top_node(node_head) as i32;
                        }
                        ctx.header.set_last_top_char_set(true);
                        ctx.last_top_char_seen = key;
                    }
                    Ordering::Equal => {
                        *node_head_ptr = NonNull::new(node_head);
                        return OK;
                    }
                    Ordering::Greater => {
                        return GetFailureNoNode;
                    }
                }
            }
            _ => {}
        }
    }
}

fn scan_meta(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, node_head_ptr: &mut Option<NonNull<NodeHeader>>) -> ReturnCode {
    let mut node_head = null_mut();
    let mut topnodes_seen = TOPLEVEL_NODE_JUMP_HWM;
    let mut jump_point = NoJump;
    ctx.safe_offset = ocx.get_root_container().size() as i32 - ocx.get_root_container().free_bytes() as i32;

    if ocx.get_root_container().jump_table() == 0 {
        ctx.current_container_offset = ocx.get_root_container().get_container_head_size();
    }
    else {
        ocx.jump_context.as_mut().unwrap().top_node_key = ocx.get_root_container().use_jumptable_2(ctx.first_char, &mut ctx.current_container_offset) as i32;

        if ocx.jump_context.as_mut().unwrap().top_node_key != 0 {
            node_head = unsafe { (ocx.get_root_container_pointer() as *mut char).add(ctx.current_container_offset as usize) as *mut NodeHeader };
            jump_point = JumpPoint2;
        }
    }

    if jump_point != JumpPoint2 {
        node_head = unsafe { (ocx.get_root_container_pointer() as *mut char).add(ctx.current_container_offset as usize) as *mut NodeHeader };
        jump_point = JumpPoint1;
    }

    loop {
        match jump_point {
            NoJump => {
                if ctx.safe_offset <= ctx.current_container_offset {
                    return GetFailureNoNode;
                }

                if as_top_node(node_head).container_type() == 0 {
                    jump_point = JumpPoint2;
                    continue;
                }
                else {
                    ocx.jump_context.as_mut().unwrap().sub_nodes_seen = 0;

                    loop {
                        ctx.current_container_offset += get_offset_sub_node(node_head) as i32;
                        node_head = unsafe { (ocx.get_root_container_pointer() as *mut char).add(ctx.current_container_offset as usize) as *mut NodeHeader };
                        ocx.jump_context.as_mut().unwrap().sub_nodes_seen += 1;
                        if ctx.safe_offset <= ctx.current_container_offset {
                            return GetFailureNoNode;
                        }
                        if as_top_node(node_head).container_type() != 1 {
                            break;
                        }
                    }

                    if ocx.jump_context.as_mut().unwrap().sub_nodes_seen > (GLOBAL_CONFIG.read().top_level_successor_threshold as i32) {
                        ocx.jump_table_sub_context.as_mut().unwrap().top_node = None;
                        node_head = new_expand(ocx, ctx, size_of::<u16>() as u32);
                        assert_eq!(as_top_node(node_head).container_type(), 0);
                        let jump_value = unsafe {
                            ((node_head as *mut c_void).offset_from(ocx.get_root_container_pointer() as *mut c_void) as u16)
                                - ocx.jump_context.as_mut().unwrap().top_node_predecessor_offset_absolute as u16
                        };
                        node_head = insert_jump(ocx, ctx, jump_value);
                    }
                }
            }
            JumpPoint2 => {
                jump_point = NoJump;
                ocx.jump_context.as_mut().unwrap().top_node_key = get_top_node_key(node_head as *mut Node, ctx) as i32;
                topnodes_seen -= 1;

                if topnodes_seen == 0 && (ocx.get_root_container().size() > (CONTAINER_SIZE_TYPE_0 as u32 * 4)) {
                    ocx.flush_jump_table_sub_context();
                    insert_top_level_jumptable(ocx, ctx);
                    ctx.flush();
                    ocx.flush_jump_context();
                    return scan_meta(ocx, ctx, node_head_ptr);
                }

                jump_point = JumpPoint1;
                continue;
            }
            JumpPoint1 => {
                jump_point = NoJump;
                match ocx.jump_context.as_mut().unwrap().top_node_key.cmp(&(ctx.first_char as i32)) {
                    Ordering::Less => {
                        ocx.jump_context.as_mut().unwrap().top_node_predecessor_offset_absolute = ctx.current_container_offset;
                        ocx.jump_context.as_mut().unwrap().predecessor = unsafe { Some(Box::from_raw(node_head.as_mut().unwrap() as *mut NodeHeader)) };
                        ctx.header.set_last_top_char_set(true);
                        ctx.last_top_char_seen = ocx.jump_context.as_mut().unwrap().top_node_key as u8;

                        if as_top_node(node_head).jump_successor_present() {
                            ctx.current_container_offset += get_jump_value(node_head) as i32;
                            node_head = unsafe { (ocx.get_root_container_pointer() as *mut char).add(ctx.current_container_offset as usize) as *mut NodeHeader };
                            jump_point = JumpPoint2;
                            continue;
                        }
                        ctx.current_container_offset += get_offset_top_node(node_head) as i32;
                        node_head = unsafe { (ocx.get_root_container_pointer() as *mut char).add(ctx.current_container_offset as usize) as *mut NodeHeader };
                    }
                    Ordering::Equal => {
                        if as_top_node(node_head).jump_successor_present() {
                            let destination = use_sub_node_jump_table(node_head, ctx);
                            return scan_meta_phase2(ocx, ctx, node_head_ptr, destination);
                        }
                        ctx.current_container_offset += get_offset_top_node(node_head)  as i32;
                        return scan_meta_phase2(ocx, ctx, node_head_ptr, 0);
                    }
                    Ordering::Greater => {
                        return GetFailureNoNode;
                    }
                }
            }
        }
    }
}

type ScanMetaFunction = fn(&mut OperationContext, &mut ContainerTraversalContext, &mut Option<NonNull<NodeHeader>>) -> ReturnCode;
type ScanPutFunction = fn(&mut OperationContext, &mut ContainerTraversalContext) -> ReturnCode;

pub fn traverse_tree(ocx: &mut OperationContext) -> ReturnCode {
    let mut ctx = ContainerTraversalContext {
        header: ContainerTraversalHeader::default(),
        last_top_char_seen: 0,
        last_sub_char_seen: 0,
        current_container_offset: 0,
        safe_offset: 0,
        first_char: 0,
        second_char: 0,
    };
    let mut node_head: Option<NonNull<NodeHeader>> = None;
    let mut scan_meta_cb: ScanMetaFunction = scan_meta;
    let mut scan_put_cb: ScanPutFunction = scan_put;

    loop {
        ctx = ContainerTraversalContext {
            header: ContainerTraversalHeader::default(),
            last_top_char_seen: 0,
            last_sub_char_seen: 0,
            current_container_offset: 0,
            safe_offset: 0,
            first_char: *(ocx.key.as_mut().unwrap().borrow_mut()),
            second_char: unsafe { *(ocx.key.as_mut().unwrap().get().add(1)) },
        };

        ctx.header.set_two_chars(true);

        if ocx.key_len_left <= 2 {
            ctx.header.set_end_operation(true);
            if ocx.key_len_left == 1 {
                ctx.header.set_two_chars(false);
                scan_meta_cb = scan_meta_single;
                scan_put_cb = scan_put_single;
            }
        }

        if ocx.header.next_container_valid() == ContainerValid {
            let mut emb_ctx = ocx.embedded_traversal_context.take().unwrap();
            emb_ctx.root_container = unsafe {
                Box::from_raw(get_pointer(ocx.arena.as_mut().unwrap().as_mut(), ocx.next_container_pointer.as_mut().unwrap().as_mut(), 0, ctx.first_char) as *mut Container)
            };
            ocx.embedded_traversal_context = Some(emb_ctx);
            ocx.header.set_next_container_valid(ContainerValid);
            ocx.embedded_traversal_context.as_mut().unwrap().root_container_pointer = Box::new(*(ocx.next_container_pointer.as_mut().unwrap().as_mut()));

            match ocx.header.command() {
                OperationCommand::Get => {
                    ocx.chained_pointer_hook = ctx.first_char;
                    ocx.embedded_traversal_context.as_mut().unwrap().next_embedded_container_offset = 0;
                    let return_code = scan_meta_cb(ocx, &mut ctx, &mut node_head);
                    if return_code != OK {
                        return return_code;
                    }
                    if ctx.header.end_operation() {
                        return get_node_value(node_head.unwrap().as_ptr(), ocx);
                    }
                    ocx.embedded_traversal_context.as_mut().unwrap().next_embedded_container_offset += ctx.current_container_offset;
                    break;
                }
                OperationCommand::Put => {
                    ocx.chained_pointer_hook = ctx.first_char;
                    ocx.embedded_traversal_context.as_mut().unwrap().next_embedded_container_offset = 0;
                    ocx.flush_jump_table_sub_context();
                    ocx.flush_jump_context();

                    if (ocx.get_root_container().size() as usize) >= (CONTAINER_SPLIT_THRESHOLD_A + CONTAINER_SPLIT_THRESHOLD_B * ocx.get_root_container().split_delay() as usize)
                        && split_container(ocx) {
                        continue;
                    }
                    ctx.current_container_offset = ocx.get_root_container().get_container_head_size();
                    let return_code = scan_put_cb(ocx, &mut ctx);
                    assert_eq!(return_code, OK);

                    if (ocx.get_root_container().size() as usize) <= 2 * CONTAINER_SIZE_TYPE_0 && ocx.header.next_container_valid() == ContainerValid {
                        if ocx.container_injection_context.as_mut().unwrap().root_container.is_some() && ((ocx.get_root_container().size() as i32 + ocx.container_injection_context.as_mut().unwrap().root_container.as_mut().unwrap().size() as i32) < (GLOBAL_CONFIG.read().container_embedding_limit as i32)) {
                            inject_container(ocx);
                            ocx.container_injection_context.as_mut().unwrap().root_container = None;
                            ocx.container_injection_context.as_mut().unwrap().container_pointer = None;
                        }
                    }
                    else {
                        ocx.container_injection_context.as_mut().unwrap().root_container = None;
                        ocx.container_injection_context.as_mut().unwrap().container_pointer = None;
                    }
                    break;
                }
                OperationCommand::Delete => {
                    ocx.embedded_traversal_context.as_mut().unwrap().next_embedded_container_offset = 0;
                    ocx.flush_jump_table_sub_context();
                    ocx.flush_jump_context();
                    let return_code = scan_meta_cb(ocx, &mut ctx, &mut node_head);
                    if return_code != OK {
                        return return_code;
                    }
                    if ctx.header.end_operation() {
                        return delete_node(node_head.unwrap().as_ptr(), ocx, &mut ctx);
                    }
                    ocx.embedded_traversal_context.as_mut().unwrap().next_embedded_container_offset += ctx.current_container_offset;
                    break;
                }
                _ => {}
            }
        }
        else {
            ocx.header.set_next_container_valid(ContainerValidTypes::Invalid);

            match ocx.header.command() {
                 OperationCommand::Put => {
                     ctx.current_container_offset = size_of::<EmbeddedContainer>() as i32;
                     let return_code = scan_put_embedded(ocx, &mut ctx);
                     if return_code != OK {
                         return return_code;
                     }
                     ocx.embedded_traversal_context.as_mut().unwrap().next_embedded_container_offset += ctx.current_container_offset;
                     break;
                }
                OperationCommand::Get => {
                    ctx.current_container_offset = size_of::<EmbeddedContainer>() as i32;
                    let return_code = scan_meta_embedded(ocx, &mut ctx, &mut node_head);
                    if return_code != OK {
                        return return_code;
                    }
                    if ctx.header.end_operation() {
                        return get_node_value(node_head.unwrap().as_ptr(), ocx);
                    }
                    ocx.embedded_traversal_context.as_mut().unwrap().next_embedded_container_offset += ctx.current_container_offset;
                    break;
                }
                OperationCommand::Delete => {
                    ctx.current_container_offset = size_of::<EmbeddedContainer>() as i32;
                    let return_code = scan_meta_embedded(ocx, &mut ctx, &mut node_head);
                    if return_code != OK {
                        return return_code;
                    }
                    if ctx.header.end_operation() {
                        return delete_node(node_head.unwrap().as_ptr(), ocx, &mut ctx);
                    }
                    ocx.embedded_traversal_context.as_mut().unwrap().next_embedded_container_offset += ctx.current_container_offset;
                    break;
                }
                _ => {}
            }
        }

        ocx.key.as_mut().unwrap().add(2);
        ocx.key_len_left -= 2;

        if ocx.header.next_container_valid() != ContainerValidTypes::Invalid {
            break;
        }
    }
    OK
}

pub fn inject_container(ocx: &mut OperationContext) {
    let mut ctx = ContainerTraversalContext {
        header: ContainerTraversalHeader::default(),
        last_top_char_seen: 0,
        last_sub_char_seen: 0,
        current_container_offset: 0,
        safe_offset: 0,
        first_char: 0,
        second_char: 0,
    };

    let mut embedded_stack: [Option<*mut EmbeddedContainer>; CONTAINER_MAX_EMBEDDED_DEPTH] = [None; CONTAINER_MAX_EMBEDDED_DEPTH];
    let mut econ_end_stack: [i32; CONTAINER_MAX_EMBEDDED_DEPTH] = [0; CONTAINER_MAX_EMBEDDED_DEPTH];
    let mut emb_stack_counter = 0;

    let mut target_ptr;
    let mut toplevel_offset = 0;

    ctx.current_container_offset = ocx.get_root_container().get_container_head_size() + ocx.get_injection_context().root_container.as_mut().unwrap().get_jump_table_size();

    let mut node_head = unsafe {
        (ocx.get_root_container_pointer() as *mut c_void).add(ctx.current_container_offset as usize) as *mut NodeHeader
    };

    let mut offset_of_next_cotainer_ptr = if ocx.header.next_container_valid() != ContainerValidTypes::Invalid {
        unsafe { (ocx.next_container_pointer.as_mut().unwrap().as_mut() as *mut HyperionPointer as *mut c_void).offset_from(ocx.get_root_container_pointer() as *mut c_void) }
    }
    else {
        0
    };

    let mut top_node_succ_jump = null_mut();
    let mut ctx_emb = ContainerTraversalContext {
        header: ContainerTraversalHeader::default(),
        last_top_char_seen: 0,
        last_sub_char_seen: 0,
        current_container_offset: 0,
        safe_offset: 0,
        first_char: 0,
        second_char: 0,
    };

    let offset_head = ocx.get_root_container().get_container_head_size() + ocx.get_root_container().get_jump_table_size();
    let size_injection = ocx.get_root_container().size() as i32 + (ocx.get_root_container().free_bytes() as i32 + offset_head);

    let cache = unsafe { libc::malloc(size_injection as size_t) };
    let mut tmp_cache = cache;
    ctx_emb.current_container_offset += offset_head;
    let mut tmp_offset = ctx_emb.current_container_offset;

    let mut embed_node;

    let mut to_copy = unsafe { (ocx.get_root_container_pointer() as *mut c_void).add(ctx_emb.current_container_offset as usize) as *mut NodeHeader };
    let mut diff = 0;
    let mut copied = 0;

    while ctx_emb.current_container_offset < (ocx.get_root_container().size() as i32) {
        embed_node = unsafe { (ocx.get_root_container_pointer() as *mut c_void).add(ctx_emb.current_container_offset as usize) as *mut NodeHeader };

        if as_top_node(embed_node).type_flag() == Invalid {
            break;
        }

        if as_sub_node(embed_node).container_type() == 0 {
            assert!(!as_top_node(embed_node).jump_table_present());
            if as_top_node(embed_node).jump_successor_present() {
                diff = ctx_emb.current_container_offset - tmp_offset;
                unsafe { copy_nonoverlapping(to_copy as *mut u8, tmp_cache as *mut u8, diff as usize); }
                copied += diff;
                tmp_offset = ctx_emb.current_container_offset;
                unsafe { to_copy = to_copy.add(diff as usize) };
                // copied previous nodes
                // now copy node with jump data
                diff = get_offset_jump(embed_node) as i32;
                unsafe { copy_nonoverlapping(to_copy as *mut u8, tmp_cache as *mut u8, diff as usize); }
                copied += diff;
                top_node_succ_jump = tmp_cache as *mut NodeHeader;
                as_top_node_mut(top_node_succ_jump).set_jump_successor_present(false);
                unsafe { tmp_cache = tmp_cache.add(diff as usize); }
                diff += size_of::<u16>() as i32;
                tmp_offset += diff;
                unsafe { to_copy = to_copy.add(diff as usize); }

                if ctx_emb.current_container_offset < (offset_of_next_cotainer_ptr as i32) {
                    offset_of_next_cotainer_ptr -= size_of::<u16>() as isize;
                }

                if as_top_node(top_node_succ_jump).type_flag() == LeafNodeWithValue {
                    diff = size_of::<NodeValue>() as i32;
                    unsafe { copy_nonoverlapping(to_copy as *mut u8, tmp_cache as *mut u8, diff as usize); }
                    copied += diff;
                    unsafe { tmp_cache = tmp_cache.add(diff as usize); }
                    tmp_offset += diff;
                    unsafe { to_copy = to_copy.add(diff as usize); }
                }
            }
            ctx_emb.current_container_offset += get_offset_sub_node(embed_node) as i32;
        }
        else {
            ctx_emb.current_container_offset += get_offset_sub_node(embed_node) as i32;
        }
    }

    diff = ctx_emb.current_container_offset - tmp_offset;
    unsafe { copy_nonoverlapping(to_copy as *mut u8, tmp_cache as *mut u8, diff as usize); }
    copied += diff;
    unsafe { tmp_cache = tmp_cache.add(diff as usize); }
    unsafe { to_copy = to_copy.add(diff as usize); }
    let total_injection_size = copied + size_of::<EmbeddedContainer>() as i32;
    let mut jump_point = NoJump;

    'outer_loop: while (ocx.get_injection_context().root_container.as_mut().unwrap().size() as i32) > ctx.current_container_offset {
        match jump_point {
            NoJump => {
                node_head = unsafe { ocx.get_injection_root_container_pointer().add(ctx.current_container_offset as usize) as *mut NodeHeader };

                if as_top_node(node_head).type_flag() == Invalid {
                    break;
                }

                if as_top_node(node_head).container_type() == 0 {
                    // TOP-Node
                    if as_top_node(node_head).jump_successor_present() {
                        toplevel_offset = ctx.current_container_offset;
                    }
                    else {
                        toplevel_offset = 0;
                    }
                    assert!(!as_top_node(node_head).jump_table_present());
                    ctx.current_container_offset += get_offset_top_node(node_head) as i32;
                }
                else {
                    // SUB-Node
                    match as_sub_node(node_head).child_container() {
                        ChildLinkType::Link => {
                            target_ptr = unsafe {
                                (node_head as *mut c_void).add(get_offset_child_container(node_head)) as *mut HyperionPointer
                            };

                            if unsafe { memcmp(target_ptr as *mut c_void, ocx.embedded_traversal_context.as_mut().unwrap().root_container_pointer.as_mut() as *mut HyperionPointer as *mut c_void, size_of::<HyperionPointer>() as size_t) == 0 } {
                                return perform_container_injection(ocx, &mut ctx, total_injection_size, target_ptr, cache, copied, (offset_of_next_cotainer_ptr as i32) - offset_head, toplevel_offset, top_node_succ_jump);
                            }
                        }
                        ChildLinkType::PathCompressed => {
                            let offset_child_container = get_offset_child_container(node_head);
                            let mut p_e_stack = unsafe { (node_head as *mut c_void).add(offset_child_container) as *mut EmbeddedContainer };
                            embedded_stack[0] = Some(p_e_stack);
                            econ_end_stack[0] = unsafe { (*p_e_stack).size() as i32 } + ctx.current_container_offset + offset_child_container as i32;
                            emb_stack_counter = 0;

                            let mut tmp_node;
                            ctx.current_container_offset += (offset_child_container + size_of::<EmbeddedContainer>()) as i32;

                            while (ocx.get_injection_context().root_container.as_mut().unwrap().size() as i32) > ctx.current_container_offset {
                                if emb_stack_counter > 0 {
                                    while econ_end_stack[emb_stack_counter - 1] == ctx.current_container_offset {
                                        emb_stack_counter -= 1;
                                        if emb_stack_counter == 0 {
                                            break;
                                        }
                                    }
                                }

                                if emb_stack_counter == 0 {
                                    jump_point = NoJump;
                                    continue 'outer_loop;
                                }

                                tmp_node = unsafe {
                                    (ocx.get_injection_root_container_pointer() as *mut c_void).add(ctx.current_container_offset as usize) as *mut NodeHeader
                                };
                                assert_ne!(as_top_node(tmp_node).type_flag(), Invalid);

                                if as_top_node(tmp_node).container_type() == 0 {
                                    ctx.current_container_offset += get_offset_top_node(tmp_node) as i32;
                                }
                                else {
                                    match as_sub_node(tmp_node).child_container() {
                                        ChildLinkType::EmbeddedContainer => {
                                            let emb_offset = get_offset_child_container(tmp_node);
                                            p_e_stack = unsafe { (tmp_node as *mut c_void).add(emb_offset) as *mut EmbeddedContainer };
                                            ctx.current_container_offset += emb_offset as i32;
                                            embedded_stack[emb_stack_counter] = Some(p_e_stack);
                                            econ_end_stack[emb_stack_counter] = unsafe { (*p_e_stack).size() as i32 } + ctx.current_container_offset;
                                            emb_stack_counter += 1;
                                            ctx.current_container_offset += size_of::<EmbeddedContainer>() as i32;
                                            continue 'outer_loop;
                                        }
                                        ChildLinkType::Link => {
                                            target_ptr = unsafe {
                                                (tmp_node as *mut c_void).add(get_offset_child_container(tmp_node)) as *mut HyperionPointer
                                            };

                                            if unsafe { memcmp(target_ptr as *mut c_void, ocx.embedded_traversal_context.as_mut().unwrap().root_container_pointer.as_mut() as *mut HyperionPointer as *mut c_void, size_of::<HyperionPointer>() as size_t) == 0 } {
                                                return perform_container_injection(ocx, &mut ctx, total_injection_size, target_ptr, cache, copied, (offset_of_next_cotainer_ptr as i32) - offset_head, toplevel_offset, top_node_succ_jump);
                                            }
                                        }
                                        _ => {
                                            ctx.current_container_offset += get_offset_sub_node(node_head) as i32;
                                        }
                                    }
                                }
                            }
                            jump_point = JumpPoint1;
                            continue;
                        }
                        _ => {
                            ctx.current_container_offset += get_offset_sub_node(node_head) as i32;
                        }
                    }
                }
            }
            JumpPoint1 => unsafe {
                jump_point = NoJump;
                libc::free(cache);
            }
            _ => { return; }
        }
    }
}

pub fn perform_container_injection(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, total_injection_size: i32, mut target_ptr: *mut HyperionPointer, cache: *mut c_void, copied: i32, next_container_fix: i32, toplevel_offset: i32, mut topnode_succ_jump: *mut NodeHeader) {
    let mut node_head = unsafe {
        (ocx.get_injection_root_container_pointer() as *mut c_void).add(ctx.current_container_offset as usize) as *mut NodeHeader
    };

    let mut safe_to_free: HyperionPointer = ocx.embedded_traversal_context.as_mut().unwrap().root_container_pointer.as_mut().clone();
    let base_container_delta = total_injection_size - size_of::<HyperionPointer>() as i32;

    if base_container_delta > (ocx.get_injection_context().root_container.as_mut().unwrap().free_bytes() as i32) {
        ocx.flush_jump_context();
        ocx.flush_jump_table_sub_context();
        assert!(ocx.path_compressed_ejection_context.is_none());

        let old_free = ocx.get_injection_context().root_container.as_mut().unwrap().free_bytes() as i32;
        let mut new_size = (((ocx.get_injection_context().root_container.as_mut().unwrap().free_bytes() as i32) + base_container_delta - old_free) / CONTAINER_SIZE_TYPE_0 as i32) * CONTAINER_SIZE_TYPE_0 as i32;

        if new_size <= ((ocx.get_injection_context().root_container.as_mut().unwrap().free_bytes() as i32) + base_container_delta - old_free) {
            new_size += CONTAINER_SIZE_TYPE_0 as i32;
        }

        let delta = new_size - ocx.get_injection_context().root_container.as_mut().unwrap().size() as i32;
        let mut injection_ctx = ocx.container_injection_context.take().unwrap();
        injection_ctx.container_pointer = Some(Box::new(
            reallocate(ocx.arena.as_mut().unwrap().as_mut(), &mut injection_ctx.container_pointer.as_mut().unwrap().as_mut(), new_size as usize, ocx.chained_pointer_hook)
        ));
        unsafe {
           injection_ctx.root_container = Some(Box::from_raw(
               get_pointer(ocx.arena.as_mut().unwrap().as_mut(), &mut injection_ctx.container_pointer.as_mut().unwrap().as_mut(), 1, ocx.chained_pointer_hook) as *mut Container
           ));
        }
        ocx.container_injection_context = Some(injection_ctx);
        node_head = unsafe { (ocx.get_injection_root_container_pointer() as *mut c_void).add(ctx.current_container_offset as usize) as *mut NodeHeader };
        assert!(as_top_node(node_head).jump_successor_present());
        assert_ne!(as_top_node(node_head).type_flag(), Invalid);
        target_ptr = unsafe {
            (node_head as *mut c_void).add(get_offset_child_container(node_head)) as *mut HyperionPointer
        };
        ocx.get_injection_context().root_container.as_mut().unwrap().set_size(new_size as u32);
        ocx.get_injection_context().root_container.as_mut().unwrap().set_free_bytes((delta + old_free) as u8);
        ocx.get_injection_context().root_container.as_mut().unwrap().set_split_delay(0);
    }

    let shift_start = unsafe {
        (target_ptr as *mut c_void).add(size_of::<HyperionPointer>())
    };
    let offset = unsafe { shift_start.offset_from(ocx.get_injection_root_container_pointer() as *mut c_void) };
    let tail = ocx.get_injection_context().root_container.as_mut().unwrap().size() as i32 - offset as i32 + ocx.get_injection_context().root_container.as_mut().unwrap().free_bytes() as i32;
    unsafe { shift_container(shift_start, base_container_delta as usize, tail as usize); }

    let target = target_ptr as *mut EmbeddedContainer;
    unsafe {
        (*target).set_size(total_injection_size as u8);
        copy_nonoverlapping(cache as *mut u8, (target as *mut c_void).add(size_of::<EmbeddedContainer>()) as *mut u8, copied as usize);
    }
    let size_left = ocx.get_injection_context().root_container.as_mut().unwrap().size() - base_container_delta as u32;
    ocx.get_root_container().set_free_size_left(size_left);

    as_sub_node_mut(node_head).set_child_container(ChildLinkType::EmbeddedContainer);

    ocx.next_container_pointer = unsafe {
        Some(Box::from_raw((target as *mut c_void).add(size_of::<EmbeddedContainer>() + next_container_fix as usize) as *mut HyperionPointer))
    };
    free(ocx.arena.as_mut().unwrap().as_mut(), &mut safe_to_free);

    if toplevel_offset != 0 {
        topnode_succ_jump = unsafe {
            (ocx.get_injection_root_container_pointer() as *mut c_void).add(toplevel_offset as usize) as *mut NodeHeader
        };
        let jump_val = unsafe {
            (topnode_succ_jump as *mut c_void).add(get_offset_jump(topnode_succ_jump)) as *mut u16
        };
        unsafe { *jump_val += base_container_delta as u16; }
    }

    if ocx.get_injection_context().root_container.as_mut().unwrap().jump_table() > 0 {
        let mut injection_ctx = ocx.container_injection_context.take().unwrap();
        ocx.embedded_traversal_context.as_mut().unwrap().root_container = Box::new(injection_ctx.root_container.as_mut().unwrap().as_mut().clone());
        ocx.embedded_traversal_context.as_mut().unwrap().root_container_pointer = Box::new(injection_ctx.container_pointer.as_mut().unwrap().as_mut().clone());
        ocx.container_injection_context = Some(injection_ctx);
        insert_top_level_jumptable(ocx, ctx);
    }
    unsafe { libc::free(cache); }
}

struct TrieStats {
    pub num_internal_nodes: i64,
    pub num_embedded_container: i64,
    pub num_delta_encoded: i64,
    pub path_compressed: [i64; 128],
    pub delta_enc: [i64; 256],
    pub top_jumps: [i64; 8],
    pub cont_splitting_increment: [i64; 4],
    pub sub_successor: i64,
    pub sub_jumptable: i64
}

use once_cell::sync::Lazy;
use spin::RwLock;

static TRIESTATS: Lazy<RwLock<TrieStats>> = Lazy::new(|| RwLock::new(TrieStats {
    num_internal_nodes: 0,
    num_embedded_container: 0,
    num_delta_encoded: 0,
    path_compressed: [0; 128],
    delta_enc: [0; 256],
    top_jumps: [0; 8],
    cont_splitting_increment: [0; 4],
    sub_successor: 0,
    sub_jumptable: 0,
}));

pub fn get_trie_stats() -> *mut TrieStats {
    TRIESTATS.as_mut_ptr()
}

pub fn stats_container(container: *mut Container) {
    #[cfg(feature = "triestats")] {
        unsafe {
            TRIESTATS.write().top_jumps[(*container).jump_table() as usize] += 1;
            TRIESTATS.write().cont_splitting_increment[(*container).split_delay() as usize] += 1;
        }
    }
}

pub fn initialize_operation_context(ocx: &mut OperationContext, operation_command: OperationCommand, root_container_entry: &mut RootContainerEntry, key: &mut u8, key_len: u16) {
    ocx.header.set_command(operation_command);
    ocx.header.set_next_container_valid(ContainerValid);
    ocx.root_container_entry = unsafe { Some(Box::from_raw(root_container_entry as *mut RootContainerEntry)) };
    ocx.arena = unsafe { Some(Box::from_raw(root_container_entry.inner.lock().arena.as_mut().unwrap().as_mut() as *mut Arena)) };
    ocx.next_container_pointer = unsafe { Some(Box::from_raw(&mut root_container_entry.inner.lock().hyperion_pointer.unwrap() as *mut HyperionPointer)) };
    ocx.key = Some(AtomicChar::new_from_pointer(key as *mut u8));
    ocx.key_len_left = key_len as i32;
}

pub fn put_debug(arena: &mut Arena, container_pointer: &mut HyperionPointer, key: &mut u8, key_len: u32, node_value: Option<Box<NodeValue>>) -> ReturnCode {
    let mut operation_context: OperationContext = OperationContext {
        header: OperationContextHeader::default(),
        chained_pointer_hook: 0,
        key_len_left: key_len as i32,
        key: Some(AtomicChar::new_from_pointer(key as *mut u8)),
        jump_context: Some(JumpContext::default()),
        root_container_entry: None,
        embedded_traversal_context: Some(EmbeddedTraversalContext::default()),
        jump_table_sub_context: None,
        next_container_pointer: unsafe { Some(Box::from_raw(container_pointer as *mut HyperionPointer)) },
        arena: unsafe { Some(Box::from_raw(arena as *mut Arena)) },
        path_compressed_ejection_context: None,
        return_value: None,
        input_value: node_value,
        container_injection_context: None,
    };
    operation_context.header.set_command(Put);
    operation_context.header.set_next_container_valid(ContainerValid);
    traverse_tree(&mut operation_context)
}

pub fn range(root_container_entry: &mut RootContainerEntry, key: &mut u8, key_len: u16, hyperion_callback: HyperionCallback) -> ReturnCode {
    let tmp_key: [u8; 4096] = [0; 4096];
    let mut rqc: RangeQueryContext = RangeQueryContext {
        key_begin: unsafe { Box::from_raw(key as *mut u8) },
        current_key: Box::new(tmp_key[0]),
        arena: unsafe { Box::from_raw(root_container_entry.inner.lock().arena.as_mut().unwrap().as_mut() as *mut Arena) },
        current_stack_depth: 0,
        current_key_offset: 0,
        key_len,
        do_report: 0,
        stack: [None; 128],
    };
    rqc.stack[0] = Some(TraversalContext {
        offset: 0,
        hyperion_pointer: root_container_entry.inner.lock().hyperion_pointer.unwrap()
    });

    todo!()
}



