use crate::hyperion::components::container::{
    get_container_head_size, get_container_link_size, shift_container, update_space_usage, wrap_shift_container, Container, ContainerLink,
    EmbeddedContainer, CONTAINER_MAX_EMBEDDED_DEPTH, CONTAINER_MAX_FREESIZE,
};
use crate::hyperion::components::context::OperationCommand::Put;
use crate::hyperion::components::context::{
    ContainerTraversalContext, JumpContext, PathCompressedEjectionContext, RangeQueryContext, KEY_DELTA_STATES,
};
use crate::hyperion::components::jump_table::{TopNodeJumpTable, SUBLEVEL_JUMPTABLE_ENTRIES, SUBLEVEL_JUMPTABLE_SHIFTBITS};
use crate::hyperion::components::node::NodeType::{InnerNode, Invalid, LeafNodeEmpty, LeafNodeWithValue};
use crate::hyperion::components::node::{get_sub_node_key, set_nodes_key2, update_successor_key, Node, NodeType, NodeValue};
use crate::hyperion::components::node_header::EmbedLinkCommands::{
    CreateEmbeddedContainer, CreateLinkToContainer, CreatePathCompressedNode, TransformPathCompressedNode,
};
use crate::hyperion::components::operation_context::ContainerValidTypes::{ContainerValid, EmbeddedContainerValid};
use crate::hyperion::components::operation_context::{
    meta_expand, new_expand, new_expand_embedded, safe_sub_node_jump_table_context, ContainerValidTypes, OperationContext,
};
use crate::hyperion::components::return_codes::ReturnCode;
use crate::hyperion::components::return_codes::ReturnCode::{ChildContainerMissing, GetFailureNoLeaf, OK};
use crate::hyperion::components::sub_node::ChildLinkType::{Link, PathCompressed};
use crate::hyperion::components::sub_node::{ChildLinkType, SubNode};
use crate::hyperion::components::top_node::TopNode;
use crate::hyperion::internals::atomic_pointer::{initialize_container, AtomicEmbContainer};
use crate::hyperion::internals::core::{initialize_ejected_container, log_to_file, GlobalConfiguration, HyperionCallback, GLOBAL_CONFIG};
use crate::hyperion::internals::errors::{
    ERR_EMPTY_EMB_STACK, ERR_EMPTY_EMB_STACK_POS, ERR_NO_ARENA, ERR_NO_CAST_MUT_REF, ERR_NO_CAST_REF, ERR_NO_INPUT_VALUE, ERR_NO_KEY,
    ERR_NO_NEXT_CONTAINER, ERR_NO_NODE_VALUE, ERR_NO_POINTER, ERR_NO_RETURN_VALUE, ERR_NO_SUCCESSOR,
};
use crate::memorymanager::api::{get_pointer, reallocate, HyperionPointer};
use bitfield_struct::bitfield;
use libc::{memcmp, size_t};
use std::cmp::Ordering;
use std::ffi::c_void;
use std::ptr::{copy, copy_nonoverlapping, null_mut, read_unaligned, write_bytes, write_unaligned};

#[repr(C)]
#[derive(Clone, Copy)]
union NodeUnion {
    pub top_node: TopNode,
    pub sub_node: SubNode,
}

#[repr(C)]
pub struct NodeHeader {
    header: NodeUnion,
}

impl NodeHeader {
    pub fn deep_copy(&mut self) -> NodeHeader {
        let node = as_top_node(self as *mut NodeHeader);

        if node.is_top_node() {
            NodeHeader {
                header: NodeUnion { top_node: *node },
            }
        } else {
            NodeHeader {
                header: NodeUnion {
                    sub_node: *as_sub_node(self as *mut NodeHeader),
                },
            }
        }
    }

    pub fn new_top_node(top_node: TopNode) -> Self {
        NodeHeader {
            header: NodeUnion { top_node },
        }
    }

    pub fn new_sub_node(sub_node: SubNode) -> Self {
        NodeHeader {
            header: NodeUnion { sub_node },
        }
    }
}

pub fn as_raw_compressed(node_head: *mut NodeHeader) -> *const PathCompressedNodeHeader {
    unsafe { node_head.add(get_offset_child_container(node_head)) as *const PathCompressedNodeHeader }
}

pub fn as_raw_compressed_mut(node_head: *mut NodeHeader) -> *mut PathCompressedNodeHeader {
    unsafe { node_head.add(get_offset_child_container(node_head)) as *mut PathCompressedNodeHeader }
}

pub fn as_path_compressed<'a>(node_head: *mut NodeHeader) -> &'a PathCompressedNodeHeader {
    unsafe { as_raw_compressed(node_head).as_ref().expect(ERR_NO_CAST_REF) }
}

pub fn as_path_compressed_mut<'a>(node_head: *mut NodeHeader) -> &'a mut PathCompressedNodeHeader {
    unsafe { as_raw_compressed_mut(node_head).as_mut().expect(ERR_NO_CAST_MUT_REF) }
}

pub fn as_raw_embedded(node_head: *mut NodeHeader, offset: usize) -> *const EmbeddedContainer {
    unsafe { node_head.add(offset) as *const EmbeddedContainer }
}

pub fn as_top_node_mut<'a>(node_head: *mut NodeHeader) -> &'a mut TopNode {
    unsafe { &mut (*node_head).header.top_node }
}

pub fn as_top_node<'a>(node_head: *mut NodeHeader) -> &'a TopNode {
    unsafe { &((*node_head).header.top_node) }
}

pub fn as_sub_node_mut<'a>(node_head: *mut NodeHeader) -> &'a mut SubNode {
    unsafe { &mut (*node_head).header.sub_node }
}

pub fn as_sub_node<'a>(node_head: *mut NodeHeader) -> &'a SubNode {
    unsafe { &(*node_head).header.sub_node }
}

pub fn get_jump_overhead(node_head: *mut NodeHeader) -> u8 {
    as_top_node(node_head).jump_successor_present() as u8 * size_of::<u16>() as u8
        + as_top_node(node_head).jump_table_present() as u8 * size_of::<TopNodeJumpTable>() as u8
}

pub fn get_leaf_size(node_head: *mut NodeHeader) -> usize {
    match as_top_node(node_head).type_flag() {
        LeafNodeWithValue => size_of::<NodeValue>(),
        _ => 0,
    }
}

pub fn get_offset_child_container(node_head: *mut NodeHeader) -> usize {
    if as_top_node(node_head).delta() == 0 {
        return size_of::<NodeHeader>() + 1 + get_leaf_size(node_head);
    }
    size_of::<NodeHeader>() + get_leaf_size(node_head)
}

pub fn get_child_link_size(node_head: *mut NodeHeader) -> usize {
    match as_sub_node(node_head).child_container() {
        ChildLinkType::None => 0,
        Link => size_of::<ContainerLink>(),
        ChildLinkType::EmbeddedContainer => unsafe { (*(as_raw_embedded(node_head, get_offset_child_container(node_head)))).size() as usize },
        PathCompressed => unsafe { (*(as_raw_compressed(node_head))).size() as usize },
    }
}

pub fn get_offset(node_head: *mut NodeHeader) -> usize {
    if as_top_node(node_head).container_type() == 0 {
        return get_offset_top_node(node_head);
    }
    get_offset_sub_node(node_head)
}

pub fn get_offset_top_node(node_head: *mut NodeHeader) -> usize {
    if !as_top_node(node_head).has_delta() {
        get_offset_top_node_nondelta(node_head)
    } else {
        get_offset_top_node_delta(node_head)
    }
}

pub fn get_offset_top_node_delta(node_head: *mut NodeHeader) -> usize {
    size_of::<NodeHeader>() + get_jump_overhead(node_head) as usize + get_leaf_size(node_head)
}

pub fn get_offset_top_node_nondelta(node_head: *mut NodeHeader) -> usize {
    get_offset_top_node_delta(node_head) + 1
}

pub fn get_offset_sub_node(node_head: *mut NodeHeader) -> usize {
    let base_size = size_of::<NodeHeader>() + get_leaf_size(node_head) + get_child_link_size(node_head);
    if as_top_node(node_head).delta() == 0 {
        return base_size + 1;
    }
    base_size
}

pub fn get_offset_sub_node_delta(node_head: *mut NodeHeader) -> usize {
    size_of::<NodeHeader>() + get_jump_overhead(node_head) as usize + get_child_link_size(node_head)
}

pub fn get_offset_node_value(node_head: *mut NodeHeader) -> usize {
    let base_size: usize = size_of::<NodeHeader>();
    if as_top_node(node_head).is_top_node() {
        return base_size + get_jump_overhead(node_head) as usize;
    }
    if !as_top_node(node_head).has_delta() {
        base_size + 1
    } else {
        base_size
    }
}

pub fn get_offset_jump(node_head: *mut NodeHeader) -> usize {
    if as_top_node(node_head).delta() == 0 {
        return size_of::<NodeHeader>() + 1;
    }
    size_of::<NodeHeader>()
}

pub fn get_jump_value(node_head: *mut NodeHeader) -> u16 {
    unsafe {
        let target: *mut u8 = (node_head as *mut u8).add(get_offset_jump(node_head));
        read_unaligned(target as *const u16)
    }
}

pub fn get_offset_jump_table(node_head: *mut NodeHeader) -> u16 {
    get_offset_jump(node_head) as u16 + as_top_node(node_head).jump_successor_present() as u16 * size_of::<u16>() as u16
}

fn get_node_value_pc(node_head: *mut NodeHeader, ocx: &mut OperationContext) -> ReturnCode {
    let pc_head: &PathCompressedNodeHeader = as_path_compressed(node_head);
    if pc_head.value_present() {
        unsafe {
            copy_nonoverlapping(
                pc_head.as_raw_char().add(size_of::<PathCompressedNodeHeader>()),
                ocx.return_value.expect(ERR_NO_RETURN_VALUE) as *mut u8,
                size_of::<NodeValue>(),
            );
        }
    }
    ocx.header.set_operation_done(true);
    OK
}

pub fn get_node_value(node_head: *mut NodeHeader, ocx: &mut OperationContext) -> ReturnCode {
    if ocx.header.pathcompressed_child() {
        return get_node_value_pc(node_head, ocx);
    }

    let top_node_type: NodeType = as_top_node(node_head).type_flag();

    if top_node_type == InnerNode || top_node_type == Invalid {
        return GetFailureNoLeaf;
    }

    if top_node_type == LeafNodeWithValue {
        unsafe {
            copy_nonoverlapping(
                (node_head as *mut u8).add(get_offset_node_value(node_head)),
                ocx.return_value.expect(ERR_NO_RETURN_VALUE) as *mut u8,
                size_of::<NodeValue>(),
            );
        }
    }

    ocx.header.set_operation_done(true);
    OK
}

pub fn set_node_value(node_head: *mut NodeHeader, ocx: &mut OperationContext) -> ReturnCode {
    if let Some(input_value) = ocx.input_value {
        let top_node: &mut TopNode = as_top_node_mut(node_head);
        if top_node.type_flag() == Invalid || top_node.type_flag() == InnerNode {
            ocx.header.set_performed_put(true);
        }

        unsafe {
            let offset: usize = get_offset_node_value(node_head);
            let target: *mut u8 = (node_head as *mut u8).add(offset);
            copy_nonoverlapping(input_value as *mut u8, target, size_of::<NodeValue>());
        }
        as_top_node_mut(node_head).set_type_flag(LeafNodeWithValue);
    } else {
        as_top_node_mut(node_head).set_type_flag(LeafNodeEmpty);
    }

    ocx.header.set_operation_done(true);
    OK
}

pub fn register_jump_context(node_head: *mut NodeHeader, ctx: &mut ContainerTraversalContext, ocx: &mut OperationContext) {
    log_to_file("register_jump_context");
    let jump_context: &mut JumpContext = ocx.get_jump_context_mut();
    if as_top_node(node_head).jump_successor_present() {
        jump_context.predecessor = Some(node_head);
        jump_context.sub_nodes_seen = 0;
        jump_context.top_node_predecessor_offset_absolute = ctx.current_container_offset;
    } else {
        jump_context.predecessor = None;
    }
}

pub fn call_top_node(node_head: *mut NodeHeader, rqc: &mut RangeQueryContext, hyperion_callback: HyperionCallback) -> bool {
    match as_top_node(node_head).type_flag() {
        LeafNodeEmpty => hyperion_callback(rqc.current_key, rqc.current_key_offset + 1, null_mut()),
        LeafNodeWithValue => unsafe {
            hyperion_callback(rqc.current_key, rqc.current_key_offset + 1, (node_head as *mut u8).add(get_offset_node_value(node_head)))
        },
        Invalid | InnerNode => true,
    }
}

pub fn call_sub_node(node_head: *mut NodeHeader, range_query_context: &mut RangeQueryContext, hyperion_callback: HyperionCallback) -> bool {
    match as_sub_node(node_head).type_flag() {
        LeafNodeEmpty => hyperion_callback(range_query_context.current_key, range_query_context.current_key_offset + 2, null_mut()),
        LeafNodeWithValue => unsafe {
            hyperion_callback(
                range_query_context.current_key,
                range_query_context.current_key_offset + 2,
                (node_head as *mut u8).add(get_offset_node_value(node_head)),
            )
        },
        Invalid | InnerNode => true,
    }
}

pub fn compare_path_compressed_node(node_head: *mut NodeHeader, ocx: &mut OperationContext) -> bool {
    log_to_file("compare_path_compressed_node");
    let pc_header: &PathCompressedNodeHeader = unsafe { as_raw_compressed(node_head).as_ref().expect(ERR_NO_CAST_REF) };

    let overhead: usize = size_of::<PathCompressedNodeHeader>() + pc_header.value_present() as usize * size_of::<NodeValue>();
    let key_len: u8 = pc_header.size() - overhead as u8;

    if ocx.key_len_left - 2 != key_len as i32 {
        return true;
    }

    let op_key: *mut u8 = unsafe { ocx.key.expect(ERR_NO_KEY).add(2) };
    unsafe {
        let key: *const PathCompressedNodeHeader = (pc_header as *const PathCompressedNodeHeader).add(overhead);
        memcmp(op_key as *mut c_void, key as *mut c_void, key_len as size_t) == 0
    }
}

pub fn use_sub_node_jump_table(node_head: *mut NodeHeader, ctx: &mut ContainerTraversalContext) -> u8 {
    log_to_file("use_sub_node_jump_table");
    let jump_class = ctx.second_char >> SUBLEVEL_JUMPTABLE_SHIFTBITS;

    if jump_class > 0 {
        let jump_table_pointer: *mut u16 = unsafe { (node_head as *mut u8).add(get_offset_jump_table(node_head) as usize) } as *mut u16;
        ctx.current_container_offset +=
            get_offset(node_head) as i32 + unsafe { read_unaligned(jump_table_pointer.add((jump_class - 1) as usize)) } as i32;
        return jump_class << SUBLEVEL_JUMPTABLE_SHIFTBITS;
    }

    ctx.current_container_offset += get_offset(node_head) as i32;
    0
}

pub fn safe_path_compressed_context(node_head: *mut NodeHeader, ocx: &mut OperationContext) {
    let pc_node: *mut PathCompressedNodeHeader = as_raw_compressed_mut(node_head);
    let pc_ctx: &mut PathCompressedEjectionContext = ocx.path_compressed_ejection_context.get_or_insert(PathCompressedEjectionContext::default());
    let pc_size: usize = unsafe { (*pc_node).size() as usize };
    let offset: usize = size_of::<PathCompressedNodeHeader>();
    let value_size: usize = size_of::<NodeValue>();
    log_to_file(&format!("safe_path_compressed_context: {}, {}", pc_size, offset));

    unsafe {
        let source: *const u8 = (pc_node as *const u8).add(offset + if (*pc_node).value_present() { value_size } else { 0 });
        let destination: *mut u8 = pc_ctx.partial_key.as_mut_ptr();
        let len: usize = pc_size - (offset + if (*pc_node).value_present() { value_size } else { 0 });
        copy_nonoverlapping(source, destination, len);

        if (*pc_node).value_present() {
            copy_nonoverlapping((pc_node as *const u8).add(offset), &mut pc_ctx.node_value as *mut NodeValue as *mut u8, value_size);
        }

        copy_nonoverlapping(
            pc_node as *const u8,
            &mut pc_ctx.path_compressed_node_header as *mut PathCompressedNodeHeader as *mut u8,
            size_of::<PathCompressedNodeHeader>(),
        );
    }
    pc_ctx.pec_valid = true;
}

pub fn delete_node(node_head: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) -> ReturnCode {
    let size_deleted: i16 = if as_top_node(node_head).type_flag() == LeafNodeWithValue {
        size_of::<NodeValue>() as i16
    } else {
        0
    };

    unsafe {
        let container: *mut Container = ocx.get_root_container_pointer();
        let dest: *mut u8 = (node_head as *mut u8).add(get_offset_node_value(node_head));
        let src: *mut u8 = dest.add(size_of::<NodeValue>());
        let remaining_length = (*container).size() as usize - ((*container).free_bytes() as usize + src.offset_from(container as *mut u8) as usize);

        copy(src, dest, remaining_length);
    }
    as_top_node_mut(node_head).set_type_flag(InnerNode);
    update_space_usage(0 - size_deleted, ocx, ctx);
    OK
}

pub fn update_path_compressed_node(mut node: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) -> *mut NodeHeader {
    log_to_file("update_path_compressed_node");
    let input_value: *mut NodeValue = ocx.input_value.expect(ERR_NO_NODE_VALUE);
    let mut pc_node: *mut PathCompressedNodeHeader = as_raw_compressed_mut(node);
    let mut value: *mut u8 = unsafe { (pc_node as *mut u8).add(size_of::<PathCompressedNodeHeader>()) };

    if unsafe { *pc_node }.value_present() {
        node = new_expand(ocx, ctx, size_of::<NodeValue>() as u32);
        unsafe {
            wrap_shift_container(ocx.get_root_container_pointer(), value, size_of::<NodeValue>());
        }
        update_space_usage(size_of::<NodeValue>() as i16, ocx, ctx);
        pc_node = as_path_compressed_mut(node);
        value = unsafe { (pc_node as *mut u8).add(size_of::<PathCompressedNodeHeader>()) };
    }

    unsafe {
        copy_nonoverlapping(value, input_value as *mut u8, size_of::<NodeValue>());
        (*pc_node).set_value_present(true);
    }

    node
}

fn get_embedded_container_info(ocx: &mut OperationContext) -> (usize, u32, u32, u8, *mut u8, *mut u8) {
    let emb_container: &mut AtomicEmbContainer =
        ocx.embedded_traversal_context.embedded_stack.as_mut().expect(ERR_EMPTY_EMB_STACK)[0].as_mut().expect(ERR_EMPTY_EMB_STACK_POS);

    let offset: usize = unsafe { emb_container.get_as_mut_memory().offset_from(ocx.embedded_traversal_context.root_container as *mut u8) as usize };
    let size: u32 = unsafe { (*emb_container.get()).size() as u32 };
    let source: *mut u8 = unsafe { emb_container.get_as_mut_memory().add(size_of::<EmbeddedContainer>()) };
    let shift_src: *mut u8 = unsafe { emb_container.get_as_mut_memory().add(size as usize) };
    assert!(ocx.get_root_container().size() > size);

    (offset, size, ocx.get_root_container().size(), ocx.get_root_container().free_bytes(), source, shift_src)
}

fn create_new_container(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, source: *mut u8, size: u32) -> HyperionPointer {
    let mut container_ptr: HyperionPointer = initialize_ejected_container(ocx.get_arena(), size);
    let new_container: *mut Container = get_pointer(ocx.arena.expect(ERR_NO_ARENA), &mut container_ptr, 1, ctx.first_char) as *mut Container;

    unsafe {
        let target: *mut u8 = (new_container as *mut u8).add(get_container_head_size() as usize);
        copy_nonoverlapping(source, target, size as usize - size_of::<EmbeddedContainer>());
        (*new_container).set_free_size_left((*new_container).free_bytes() as u32 - (size - size_of::<EmbeddedContainer>() as u32));
    }

    container_ptr
}

fn link_to_new_container(node_head: *mut NodeHeader, container_ptr: HyperionPointer) {
    as_sub_node_mut(node_head).set_child_container(Link);
    unsafe {
        let link_ptr: *mut ContainerLink = (node_head as *mut u8).add(get_offset_child_container(node_head)) as *mut ContainerLink;
        (*link_ptr).ptr = container_ptr;
    }
}

fn shift_memory_after_ejection(
    node_head: *mut NodeHeader, ocx: &mut OperationContext, embedded_offset: usize, embedded_size: u32, shift_src_ptr: *mut u8, root_size: u32,
    free_bytes: u8,
) {
    let remaining_size = root_size as usize - (embedded_size as usize + embedded_offset + free_bytes as usize);
    ocx.embedded_traversal_context.embedded_container_depth = 0;

    if remaining_size > 0 {
        unsafe {
            let shift_dest: *mut u8 = (node_head as *mut u8).add(get_offset(node_head));
            copy(shift_src_ptr, shift_dest, remaining_size);
        }
    }
}

fn adjust_container_space(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, embedded_size: u32, root_size: u32) -> (i32, i32) {
    let delta: i32 = -(embedded_size as i32 - get_container_link_size() as i32);
    log_to_file(&format!("delta: {}", delta));
    let new_free_size_left: i32 = ocx.get_root_container().free_bytes() as i32 - delta;
    update_space_usage(delta as i16, ocx, ctx);

    assert!(root_size as i32 > new_free_size_left);

    unsafe {
        let free_space_ptr: *mut u8 = (ocx.get_root_container_pointer() as *mut u8).add(root_size as usize - new_free_size_left as usize);
        write_bytes(free_space_ptr, 0, new_free_size_left as usize);
    }
    (delta, new_free_size_left)
}

fn resize_root_container(ocx: &mut OperationContext, delta: i32, root_size: u32, free_bytes: u8, new_free_size_left: i32) {
    let container_increment = GLOBAL_CONFIG.read().header.container_size_increment() as i32;

    if new_free_size_left > CONTAINER_MAX_FREESIZE as i32 {
        let used_space: i32 = root_size as i32 - (free_bytes as i32 - delta);

        assert!(used_space > 0);

        let target_size: u32 = ((used_space + container_increment - 1) / container_increment) as u32 * container_increment as u32;
        let new_free_size: u32 = (free_bytes as i32 - delta) as u32 % container_increment as u32;

        log_to_file(&format!("target_size: {}", target_size));

        assert_eq!(ocx.embedded_traversal_context.embedded_container_depth, 0);

        unsafe {
            *ocx.embedded_traversal_context.root_container_pointer = reallocate(
                ocx.arena.expect(ERR_NO_ARENA),
                ocx.embedded_traversal_context.root_container_pointer,
                target_size as usize,
                ocx.chained_pointer_hook,
            );
        }

        ocx.embedded_traversal_context.root_container =
            get_pointer(ocx.arena.expect(ERR_NO_ARENA), ocx.embedded_traversal_context.root_container_pointer, 1, ocx.chained_pointer_hook)
                as *mut Container;

        ocx.get_root_container().set_free_size_left(new_free_size);
        ocx.get_root_container().set_size(target_size);
    }
}

pub fn eject_container(mut node_head: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) {
    log_to_file("eject_container");
    assert!(ocx.embedded_traversal_context.embedded_container_depth > 0);
    node_head = meta_expand(ocx, ctx, get_container_link_size() as u32);

    let (embedded_offset, embedded_size, root_size, free_bytes, source, shift_src) = get_embedded_container_info(ocx);
    log_to_file(&format!("offset: {}, size: {}, root_size: {}, free_bytes: {}", embedded_offset, embedded_size, root_size, free_bytes));
    let container_ptr: HyperionPointer = create_new_container(ocx, ctx, source, embedded_size);

    link_to_new_container(node_head, container_ptr);
    shift_memory_after_ejection(node_head, ocx, embedded_offset, embedded_size, shift_src, root_size, free_bytes);
    let (delta, new_free_size_left) = adjust_container_space(ocx, ctx, embedded_size, root_size);
    resize_root_container(ocx, delta, root_size, free_bytes, new_free_size_left);
}

pub fn add_embedded_container(mut node: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) {
    log_to_file("add_embedded_container");
    ocx.header.set_next_container_valid(EmbeddedContainerValid);
    let offset_child_container: usize = get_offset_child_container(node);
    node = new_expand_embedded(ocx, ctx, size_of::<EmbeddedContainer>() as u32);

    let _ = ocx.embedded_traversal_context.next_embedded_container.take().expect(ERR_NO_NEXT_CONTAINER);
    let base_ptr: *mut u8 = node as *mut u8;
    let next_embedded_ptr = unsafe { base_ptr.add(offset_child_container) as *mut EmbeddedContainer };

    unsafe {
        wrap_shift_container(ocx.get_root_container_pointer(), next_embedded_ptr as *mut u8, size_of::<EmbeddedContainer>());
    }

    ctx.current_container_offset += offset_child_container as i32;
    as_sub_node_mut(node).set_child_container(ChildLinkType::EmbeddedContainer);
    safe_sub_node_jump_table_context(ocx, ctx);
    ocx.embedded_traversal_context.embedded_stack.as_mut().expect(ERR_EMPTY_EMB_STACK)
        [ocx.embedded_traversal_context.embedded_container_depth as usize] = Some(AtomicEmbContainer::new_from_pointer(next_embedded_ptr));
    ocx.embedded_traversal_context.embedded_container_depth += 1;
    ocx.next_container_pointer = None;
    ocx.embedded_traversal_context.next_embedded_container = Some(next_embedded_ptr);
    update_space_usage(size_of::<EmbeddedContainer>() as i16, ocx, ctx);

    unsafe {
        let base_ptr: *mut u8 = node as *mut u8;
        ocx.embedded_traversal_context.next_embedded_container = Some(base_ptr.add(offset_child_container) as *mut EmbeddedContainer);

        if let Some(next_embedded_container) = ocx.embedded_traversal_context.next_embedded_container.take() {
            wrap_shift_container(ocx.get_root_container_pointer(), next_embedded_container as *mut u8, size_of::<EmbeddedContainer>());
            ocx.embedded_traversal_context.next_embedded_container = Some(next_embedded_container);
        } else {
            panic!("{}", ERR_NO_NEXT_CONTAINER)
        }
    }
}

pub enum EmbedLinkCommands {
    CreateLinkToContainer,
    CreatePathCompressedNode,
    CreateEmbeddedContainer,
    TransformPathCompressedNode,
}

pub fn embed_or_link_child(mut node_head: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) -> *mut NodeHeader {
    let mut switch_condition: EmbedLinkCommands = CreateLinkToContainer;
    let required_size_for_path_compression =
        size_of::<PathCompressedNodeHeader>() as i32 + ocx.key_len_left - 2 + ocx.input_value.map_or(0, |_| size_of::<NodeValue>()) as i32;
    let container_limit: i32 = GLOBAL_CONFIG.read().container_embedding_limit as i32;

    if as_sub_node(node_head).child_container() == PathCompressed {
        switch_condition = TransformPathCompressedNode;
    } else if ocx.get_root_container().size() as i32 + required_size_for_path_compression < container_limit {
        if ocx.embedded_traversal_context.embedded_container_depth == 0 {
            switch_condition = if required_size_for_path_compression < 128 {
                CreatePathCompressedNode
            } else {
                CreateEmbeddedContainer
            };
        } else if ocx.embedded_traversal_context.embedded_container_depth < CONTAINER_MAX_EMBEDDED_DEPTH as i32 {
            let embedded_size = ocx.embedded_traversal_context.embedded_stack.as_mut().expect(ERR_EMPTY_EMB_STACK)[0]
                .as_mut()
                .expect(ERR_EMPTY_EMB_STACK_POS)
                .borrow_mut()
                .size() as i32;

            if embedded_size + required_size_for_path_compression < container_limit && required_size_for_path_compression < 128 {
                switch_condition = CreatePathCompressedNode;
            } else if embedded_size < container_limit {
                switch_condition = CreateEmbeddedContainer;
            }
        }
    } else if as_sub_node(node_head).child_container() == ChildLinkType::None
        && required_size_for_path_compression < 16
        && ((ocx.get_root_container().size() as i32) < (2 * container_limit))
    {
        switch_condition = CreatePathCompressedNode;
    }

    match switch_condition {
        TransformPathCompressedNode => {
            log_to_file("TransformPathCompressedNode");
            transform_pc_node(node_head, ocx, ctx);
            node_head = unsafe { (ocx.embedded_traversal_context.root_container as *mut NodeHeader).add(ctx.current_container_offset as usize) };
        },
        CreateEmbeddedContainer => {
            log_to_file("CreateEmbeddedContainer");
            assert_eq!(as_sub_node(node_head).child_container(), ChildLinkType::None);
            add_embedded_container(node_head, ocx, ctx);
            node_head = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset as usize) as *mut NodeHeader };
        },
        CreatePathCompressedNode => {
            log_to_file("CreatePathCompressedNode");
            let offset: usize = get_offset_child_container(node_head);
            if (ocx.get_root_container().free_bytes() as i32) < required_size_for_path_compression {
                node_head = meta_expand(ocx, ctx, required_size_for_path_compression as u32);
            }

            unsafe {
                let target: *mut PathCompressedNodeHeader = (node_head as *mut u8).add(offset) as *mut PathCompressedNodeHeader;
                wrap_shift_container(ocx.get_root_container_pointer(), target as *mut u8, required_size_for_path_compression as usize);
                (*target).set_size(required_size_for_path_compression as u8);
                let mut target_partial_key: *mut u8 = (target as *mut u8).add(size_of::<PathCompressedNodeHeader>());

                if let Some(ref mut input_value) = ocx.input_value {
                    (*target).set_value_present(true);
                    copy_nonoverlapping(*input_value as *mut u8, target_partial_key, size_of::<NodeValue>());
                    target_partial_key = target_partial_key.add(size_of::<NodeValue>());
                } else {
                    panic!("{}", ERR_NO_INPUT_VALUE)
                }

                copy_nonoverlapping(ocx.key.expect(ERR_NO_KEY).add(2), target_partial_key, (ocx.key_len_left - 2) as usize);
                as_sub_node_mut(node_head).set_child_container(PathCompressed);
            }

            update_space_usage(required_size_for_path_compression as i16, ocx, ctx);
            ocx.header.set_next_container_valid(ContainerValidTypes::Invalid);
            ocx.header.set_operation_done(true);
            ocx.header.set_performed_put(true);
        },
        CreateLinkToContainer => {
            log_to_file("CreateLinkToContainer");
            if (ocx.get_root_container().free_bytes() as usize) < get_container_link_size() {
                node_head = meta_expand(ocx, ctx, get_container_link_size() as u32);
            }

            unsafe {
                let target: *mut u8 = (node_head as *mut u8).add(get_offset_child_container(node_head));
                wrap_shift_container(ocx.get_root_container_pointer(), target, get_container_link_size());
                let new_link: *mut ContainerLink = target as *mut ContainerLink;
                (*new_link).ptr = initialize_container(ocx.arena.expect(ERR_NO_ARENA));
                ocx.next_container_pointer = Some(&mut (*new_link).ptr as *mut HyperionPointer);
                as_sub_node_mut(node_head).set_child_container(Link);
            }
            ocx.header.set_next_container_valid(ContainerValid);
            update_space_usage(get_container_link_size() as i16, ocx, ctx);
            ocx.embedded_traversal_context.embedded_container_depth = 0;
        },
    }
    node_head
}

fn process_embedded_container(
    node_head: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, modify: bool,
) -> (ReturnCode, *mut NodeHeader) {
    log_to_file("process_embedded_container");
    safe_sub_node_jump_table_context(ocx, ctx);
    let offset: usize = get_offset_child_container(node_head);

    ocx.embedded_traversal_context.next_embedded_container = Some(unsafe { (node_head as *mut u8).add(offset) as *mut EmbeddedContainer });
    assert!(
        unsafe { (*(ocx.embedded_traversal_context.next_embedded_container.expect(ERR_NO_NEXT_CONTAINER))).size() as u32 }
            < ocx.get_root_container().size()
    ); // auch für !modify?

    if ocx.embedded_traversal_context.embedded_stack.is_none() {
        ocx.embedded_traversal_context.embedded_stack = Some([const { None }; CONTAINER_MAX_EMBEDDED_DEPTH]);
    }

    ocx.embedded_traversal_context.embedded_stack.as_mut().expect(ERR_EMPTY_EMB_STACK)
        [ocx.embedded_traversal_context.embedded_container_depth as usize] =
        Some(AtomicEmbContainer::new_from_pointer(ocx.embedded_traversal_context.next_embedded_container.expect(ERR_NO_POINTER)));
    ocx.embedded_traversal_context.embedded_container_depth += 1;

    if !modify {
        ctx.current_container_offset += offset as i32;
        ocx.header.set_next_container_valid(EmbeddedContainerValid);
        ocx.next_container_pointer =
            Some(ocx.embedded_traversal_context.next_embedded_container.expect(ERR_NO_NEXT_CONTAINER) as *mut HyperionPointer);
        return (OK, node_head);
    }

    let config: spin::RwLockReadGuard<'_, GlobalConfiguration> = GLOBAL_CONFIG.read();
    let embedded_size = unsafe { (*(ocx.embedded_traversal_context.next_embedded_container.expect(ERR_NO_POINTER))).size() as u32 };
    let root_size = ocx.get_root_container().size();
    let embedding_hwm = config.header.container_embedding_high_watermark();
    let embedding_limit = config.container_embedding_limit;

    if ocx.header.command() == Put
        && (embedded_size > embedding_hwm || root_size >= embedding_limit || (embedded_size > embedding_hwm / 2 && root_size >= embedding_limit / 2))
    {
        eject_container(node_head, ocx, ctx);
        (ChildContainerMissing, unsafe {
            (ocx.embedded_traversal_context.root_container as *mut u8).add(ctx.current_container_offset as usize) as *mut NodeHeader
        })
    } else {
        ctx.current_container_offset += offset as i32;
        ocx.header.set_next_container_valid(EmbeddedContainerValid);
        ocx.next_container_pointer = Some(ocx.embedded_traversal_context.next_embedded_container.expect(ERR_NO_POINTER) as *mut HyperionPointer);
        (OK, node_head)
    }
}

pub fn get_child_container_pointer(
    mut node_head: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, modify: bool,
) -> ReturnCode {
    match as_sub_node(node_head).child_container() {
        ChildLinkType::EmbeddedContainer | Link => {
            if as_sub_node(node_head).child_container() == ChildLinkType::EmbeddedContainer {
                let (ret, node_header) = process_embedded_container(node_head, ocx, ctx, modify);
                node_head = node_header;

                if ret == OK {
                    return OK;
                }
            }

            log_to_file("update next container pointer");
            if let Some(ref mut next_ptr) = ocx.next_container_pointer {
                let value = unsafe { *((node_head as *mut u8).add(get_offset_child_container(node_head))) };
                log_to_file(&format!("root container offset value: {}", value));
                *next_ptr = unsafe { (node_head as *mut u8).add(get_offset_child_container(node_head)) as *mut HyperionPointer };
            }

            ocx.embedded_traversal_context.embedded_container_depth = 0;
            ocx.header.set_next_container_valid(ContainerValid);
            ocx.embedded_traversal_context.next_embedded_container = None;
            OK
        },
        _ => ChildContainerMissing,
    }
}

pub fn create_node(
    mut node_head: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, container_depth: u8,
    set_key_after_creation: bool, add_value_after_creation: bool, key_delta: u8, embedded: bool,
) -> *mut NodeHeader {
    let mut absolute_key: u8 = if embedded && container_depth == 0 {
        ctx.first_char
    } else {
        ctx.second_char
    };
    let input_memory_consumption: usize = ocx.input_value.map_or(0, |_| add_value_after_creation as usize * size_of::<NodeValue>());
    let required: usize = size_of::<NodeHeader>() + set_key_after_creation as usize + input_memory_consumption;
    log_to_file(&format!(
        "create_node: embedded: {}, absolute_key: {}, input_mem: {}, required: {}",
        embedded as u8, absolute_key, input_memory_consumption, required
    ));

    if !embedded && container_depth == 0 {
        ocx.jump_context.predecessor = None;
        ocx.jump_context.top_node_key = ctx.first_char as i32;
        absolute_key = ctx.first_char;
    }

    node_head = if embedded {
        new_expand_embedded(ocx, ctx, required as u32)
    } else {
        new_expand(ocx, ctx, required as u32)
    };

    if embedded {
        let remaining_space: i32 = unsafe {
            ocx.get_root_container().size() as i32
                - (ocx.get_root_container().free_bytes() as i32
                    + ((node_head as *mut u8).offset_from(ocx.embedded_traversal_context.root_container as *mut u8) as i32))
        };

        if remaining_space > 0 {
            log_to_file("remaining space > 0, shift container");
            unsafe {
                shift_container(node_head as *mut u8, required, remaining_space as usize);
            }
        }
    }

    if !embedded {
        if ctx.header.force_shift_before_insert() {
            log_to_file("wrap shift container");
            unsafe {
                wrap_shift_container(ocx.get_root_container_pointer(), node_head as *mut u8, required);
            }
        }
        assert!(unsafe { *(node_head as *mut u8) == 0 })
    }

    as_top_node_mut(node_head).set_type_flag(if add_value_after_creation && input_memory_consumption != 0 {
        LeafNodeWithValue
    } else {
        InnerNode
    });
    as_top_node_mut(node_head).set_container_type(container_depth);
    update_space_usage(
        if !embedded {
            1 + input_memory_consumption + set_key_after_creation as usize
        } else {
            required
        } as i16,
        ocx,
        ctx,
    );

    if set_key_after_creation {
        set_nodes_key2(node_head as *mut Node, ocx, ctx, embedded, absolute_key);
    } else {
        as_top_node_mut(node_head).set_delta(key_delta);
        let mut successor_ptr: Option<*mut Node> = None;
        let skipped_bytes: u32 = if !embedded {
            get_successor(node_head, &mut successor_ptr, ocx, ctx, false)
        } else {
            get_successor(node_head, &mut successor_ptr, ocx, ctx, true)
        };

        if let Some(successor) = successor_ptr.filter(|_| skipped_bytes > 0) {
            let successor: &mut Node = unsafe { successor.as_mut().expect(ERR_NO_CAST_MUT_REF) };
            let diff: u8 = if as_top_node(&mut successor.header).delta() == 0 {
                successor.stored_value - key_delta
            } else {
                as_top_node(&mut successor.header).delta() - key_delta
            };
            update_successor_key(successor as *mut Node, diff, absolute_key + diff, skipped_bytes, ocx, ctx);
        }
    }

    if add_value_after_creation {
        set_node_value(node_head, ocx);
    }

    if !ctx.header.end_operation() && container_depth > 0 {
        if embedded {
            as_sub_node_mut(node_head).set_child_container(ChildLinkType::None);
            embed_or_link_child(node_head, ocx, ctx);
        } else {
            node_head = embed_or_link_child(node_head, ocx, ctx);
        }
    }
    ocx.header.set_performed_put(true);
    node_head
}

pub fn get_successor(
    node_head: *mut NodeHeader, successor: &mut Option<*mut Node>, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, embedded: bool,
) -> u32 {
    let mut successor_ptr: *mut Node;
    let mut skipped_bytes: u32 = 0;

    if as_top_node(node_head).container_type() == 0 {
        if !embedded && as_top_node(node_head).jump_successor_present() {
            skipped_bytes = get_jump_value(node_head) as u32;
            successor_ptr = unsafe { (node_head as *mut u8).add(skipped_bytes as usize) as *mut Node };
        } else {
            successor_ptr = node_head as *mut Node;

            loop {
                let offset: usize = unsafe { get_offset(&mut (*successor_ptr).header) };
                skipped_bytes += offset as u32;

                if embedded {
                    if ctx.current_container_offset as u32 + skipped_bytes
                        >= unsafe { (*(ocx.embedded_traversal_context.next_embedded_container.expect(ERR_NO_NEXT_CONTAINER))).size() as u32 }
                    {
                        return 0;
                    }
                } else if ctx.current_container_offset as u32 + skipped_bytes >= ocx.get_root_container().size() {
                    return 0;
                }

                successor_ptr = unsafe { (successor_ptr as *mut u8).add(offset) as *mut Node };

                if unsafe { as_top_node(&mut (*successor_ptr).header).type_flag() == Invalid } {
                    return 0;
                }

                if embedded {
                    if unsafe { as_top_node(&mut (*successor_ptr).header).container_type() == 0 } {
                        break;
                    }
                } else if unsafe { as_top_node(&mut (*successor_ptr).header).container_type() != 1 } {
                    break;
                }
            }
        }
    } else {
        skipped_bytes = get_offset_sub_node(node_head) as u32;
        successor_ptr = unsafe { (node_head as *mut u8).add(skipped_bytes as usize) as *mut Node };

        if !embedded {
            if ctx.current_container_offset as u32 + skipped_bytes >= ocx.get_root_container().size()
                || unsafe { as_top_node(&mut (*successor_ptr).header).container_type() == 0 }
            {
                return 0;
            }
        } else {
            if ctx.current_container_offset as u32 + skipped_bytes
                >= unsafe { (*(ocx.embedded_traversal_context.next_embedded_container.expect(ERR_NO_NEXT_CONTAINER))).size() as u32 }
            {
                return 0;
            }

            if unsafe { as_top_node(&mut (*successor_ptr).header).container_type() == 0 } {
                return 0;
            }
        }
    }

    log_to_file(&format!("get_successor: embedded: {}, skipped: {}", embedded as u8, skipped_bytes));

    if skipped_bytes > 0 {
        *successor = Some(successor_ptr);
    }
    skipped_bytes
}

pub fn create_sublevel_jumptable(mut node_head: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) {
    log_to_file("create_sublevel_jumptable");
    const JUMP_TABLE_KEYS: [u8; 15] = [16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240];

    assert!(!as_top_node(node_head).jump_table_present());
    let required_max = size_of::<TopNodeJumpTable>() + SUBLEVEL_JUMPTABLE_ENTRIES * (size_of::<NodeHeader>() + 1);
    let mut free_size_left = ocx.get_root_container().free_bytes() as usize;

    unsafe {
        let mut offset: usize = (node_head as *mut u8).offset_from(ocx.get_root_container_pointer() as *mut u8) as usize;
        let offset_to_jumptable0: usize = offset + get_offset_jump_table(node_head) as usize;
        let mut bytes_to_move: i32 = ocx.get_root_container().size() as i32 - (offset_to_jumptable0 as i32 + free_size_left as i32);
        log_to_file(&format!(
            "free: {}, offset: {}, offset to jt0: {}, move: {}",
            ocx.get_root_container().free_bytes(),
            offset,
            offset_to_jumptable0,
            bytes_to_move
        ));

        if free_size_left <= required_max {
            new_expand(ocx, ctx, required_max as u32);
        }

        let mut target: *mut u16 = (ocx.get_root_container_pointer() as *mut u8).add(offset_to_jumptable0) as *mut u16;
        shift_container(target as *mut u8, size_of::<TopNodeJumpTable>(), bytes_to_move as usize);
        update_space_usage(size_of::<TopNodeJumpTable>() as i16, ocx, ctx);
        node_head = (ocx.get_root_container_pointer() as *mut u8).add(offset) as *mut NodeHeader;
        assert!(!as_top_node(node_head).jump_table_present());

        let mut tmp_ctx = ContainerTraversalContext::default();
        tmp_ctx.header.set_in_first_char_scope(true);
        tmp_ctx.current_container_offset = offset as i32;

        let jump_start: usize = get_offset(node_head) + size_of::<TopNodeJumpTable>();
        offset = 0;

        let mut expect: usize = 0;
        let base_offset: i32 = tmp_ctx.current_container_offset + jump_start as i32;
        let mut scan_node: *mut NodeHeader = node_head.add(get_offset(node_head));
        tmp_ctx.header.set_last_sub_char_set(false);
        tmp_ctx.last_sub_char_seen = 0;

        loop {
            tmp_ctx.current_container_offset = base_offset + offset as i32;
            log_to_file(&format!("create_sublevel_jumptable set current container offset to {}", tmp_ctx.current_container_offset));
            scan_node = (ocx.get_root_container_pointer() as *mut u8).add(tmp_ctx.current_container_offset as usize) as *mut NodeHeader;

            if as_top_node(scan_node).container_type() == 1 {
                let mut key: u8 = get_sub_node_key(scan_node as *mut Node, &mut tmp_ctx, false);
                log_to_file(&format!("found key {}", key));

                match key.cmp(&JUMP_TABLE_KEYS[expect]) {
                    Ordering::Less => {},
                    Ordering::Equal => {
                        write_unaligned(target, offset as u16);
                        log_to_file(&format!("key equal, written target to {}", read_unaligned(target)));
                        expect += 1;
                        target = target.add(1);
                        if expect == SUBLEVEL_JUMPTABLE_ENTRIES {
                            break;
                        }
                    },
                    Ordering::Greater => {
                        inject_sublevel_reference_key(scan_node, ocx, &mut tmp_ctx, JUMP_TABLE_KEYS[expect]);
                        write_unaligned(target, offset as u16);
                        log_to_file(&format!("key greater, written target to {}", read_unaligned(target)));
                        key = JUMP_TABLE_KEYS[expect];
                        expect += 1;
                        target = target.add(1);
                        if expect == SUBLEVEL_JUMPTABLE_ENTRIES {
                            break;
                        }
                    },
                }
                tmp_ctx.last_sub_char_seen = key;
                tmp_ctx.header.set_last_sub_char_set(true);
                offset += get_offset(scan_node);
            } else {
                free_size_left = ocx.get_root_container().free_bytes() as usize;
                let offset_tmp: i32 = (scan_node as *mut u8).offset_from(ocx.get_root_container_pointer() as *mut u8) as i32;
                bytes_to_move = ocx.get_root_container().size() as i32 - (offset_tmp + free_size_left as i32);

                if bytes_to_move < 0 {
                    bytes_to_move = 0;
                }
                log_to_file(&format!("insert jumptable: free: {}, offset: {}, move: {}", free_size_left, offset_tmp, bytes_to_move));

                let numer_of_missing = SUBLEVEL_JUMPTABLE_ENTRIES - expect;
                assert!(tmp_ctx.header.last_sub_char_set());
                assert!(JUMP_TABLE_KEYS[expect] > tmp_ctx.last_sub_char_seen);
                let diff: u8 = JUMP_TABLE_KEYS[expect] - tmp_ctx.last_sub_char_seen;
                let first_insert_is_relative: bool = diff <= KEY_DELTA_STATES as u8;
                let shift_by: usize = ((size_of::<NodeHeader>() + 1) * numer_of_missing) - first_insert_is_relative as usize;
                log_to_file(&format!(
                    "num missing: {}, diff: {}, relative: {}, shift_by: {}",
                    numer_of_missing, diff, first_insert_is_relative as u8, shift_by
                ));

                shift_container(scan_node as *mut u8, shift_by, bytes_to_move as usize);
                update_space_usage(shift_by as i16, ocx, &mut tmp_ctx);

                as_sub_node_mut(scan_node).set_type_flag(InnerNode);
                as_sub_node_mut(scan_node).set_container_type(1);

                if !first_insert_is_relative {
                    *((scan_node as *mut u8).add(1)) = diff;
                    tmp_ctx.last_sub_char_seen = JUMP_TABLE_KEYS[expect];
                } else {
                    as_sub_node_mut(scan_node).set_delta(diff);
                }

                write_unaligned(target, offset as u16);
                target = target.add(1);
                offset += get_offset(scan_node);
                expect += 1;

                while expect < SUBLEVEL_JUMPTABLE_ENTRIES {
                    scan_node = (ocx.get_root_container_pointer() as *mut u8).add(base_offset as usize + offset) as *mut NodeHeader;
                    as_sub_node_mut(scan_node).set_type_flag(InnerNode);
                    as_sub_node_mut(scan_node).set_container_type(1);
                    as_sub_node_mut(scan_node).set_delta(0);
                    let target_key = (scan_node as *mut u8).add(size_of::<NodeHeader>());
                    *target_key = JUMP_TABLE_KEYS[expect] - tmp_ctx.last_sub_char_seen;
                    tmp_ctx.last_sub_char_seen = JUMP_TABLE_KEYS[expect];
                    expect += 1;
                    write_unaligned(target, offset as u16);
                    target = target.add(1);
                    offset += get_offset(scan_node);
                }
                break;
            }
        }
        as_top_node_mut(node_head).set_jump_table_present(true);
    }
}

pub fn transform_pc_node(mut node_head: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) {
    log_to_file("transform_pc_node");
    assert_eq!(as_sub_node(node_head).child_container(), PathCompressed);
    assert!(ocx.get_pc_ejection_context().pec_valid);
    if ocx.embedded_traversal_context.embedded_stack.is_none() {
        ocx.embedded_traversal_context.embedded_stack = Some([const { None }; CONTAINER_MAX_EMBEDDED_DEPTH]);
    }

    let child_container_offset: usize = get_offset_child_container(node_head);
    let pc_key_offset: usize = size_of::<PathCompressedNodeHeader>()
        + ocx.get_pc_ejection_context().path_compressed_node_header.value_present() as usize * size_of::<NodeValue>();
    let pc_key_len: usize = ocx.get_pc_ejection_context().path_compressed_node_header.size() as usize - pc_key_offset;
    let container_embedding_limit: u32 = GLOBAL_CONFIG.read().container_embedding_limit;
    let container_embedding_hwm: u32 = GLOBAL_CONFIG.read().header.container_embedding_high_watermark();

    if (ocx.get_root_container().size() >= container_embedding_limit)
        || (ocx.embedded_traversal_context.embedded_container_depth >= CONTAINER_MAX_EMBEDDED_DEPTH as i32)
        || (ocx.embedded_traversal_context.embedded_container_depth > 0
            && ((ocx.embedded_traversal_context.embedded_stack.as_mut().expect(ERR_EMPTY_EMB_STACK)[0]
                .as_mut()
                .expect(ERR_EMPTY_EMB_STACK_POS)
                .borrow_mut()
                .size() as u32)
                >= (container_embedding_hwm - get_container_link_size() as u32)))
    {
        let pc_delta: i32 = ocx.get_pc_ejection_context().path_compressed_node_header.size() as i32 - get_container_link_size() as i32;
        if pc_delta < 0 {
            node_head = meta_expand(ocx, ctx, get_container_link_size() as u32);
        }

        as_sub_node_mut(node_head).set_child_container(Link);
        let free_size_left: u8 = ocx.get_root_container().free_bytes();

        let link: *mut ContainerLink = unsafe { (node_head as *mut u8).add(child_container_offset) as *mut ContainerLink };
        let diff: i32 = get_container_link_size() as i32 - ocx.get_pc_ejection_context().path_compressed_node_header.size() as i32;

        let absolute_offset: isize = unsafe { (node_head as *mut u8).offset_from(ocx.get_root_container_pointer() as *mut u8) };
        let container_tail: i32 = ocx.get_root_container().size() as i32
            - (absolute_offset as i32
                + child_container_offset as i32
                + ocx.get_pc_ejection_context().path_compressed_node_header.size() as i32
                + free_size_left as i32);

        let new_container: *mut c_void;
        unsafe {
            let tail_target: *mut u8 = (link as *mut u8).add(get_container_link_size());

            copy(tail_target.add(pc_delta as usize), tail_target, container_tail as usize);

            if pc_delta >= 0 {
                write_bytes(tail_target.add(container_tail as usize), 0, pc_delta as usize);
            }
            update_space_usage(diff as i16, ocx, ctx);

            (*link).ptr = initialize_container(ocx.get_arena());
            new_container = get_pointer(ocx.get_arena(), &mut (*link).ptr, 1, ocx.chained_pointer_hook);
            ocx.embedded_traversal_context.root_container = new_container as *mut Container;
        }

        ocx.embedded_traversal_context.embedded_container_depth = 0;
        ocx.header.set_next_container_valid(ContainerValid);
        ocx.embedded_traversal_context.next_embedded_container = None;
        ocx.next_container_pointer = unsafe { Some(&mut (*link).ptr as *mut HyperionPointer) };
        ocx.embedded_traversal_context.root_container_pointer = ocx.next_container_pointer.expect(ERR_NO_POINTER);
        ocx.embedded_traversal_context.root_container = new_container as *mut Container;
        ctx.current_container_offset = ocx.get_root_container().get_container_head_size();

        let data_offset: *mut u8 =
            unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ocx.get_root_container().get_container_head_size() as usize) };
        let mut consumed_newcon: usize = 0;
        assert!(pc_key_len > 0);

        let top: *mut NodeHeader = data_offset as *mut NodeHeader;
        as_top_node_mut(top).set_type_flag(InnerNode);
        unsafe {
            copy_nonoverlapping(ocx.get_pc_ejection_context().partial_key.as_mut_ptr(), (top as *mut u8).add(size_of::<NodeHeader>()), 1);
        }
        ctx.current_container_offset += 2;

        if pc_key_len == 1 {
            if ocx.get_pc_ejection_context().path_compressed_node_header.value_present() {
                as_top_node_mut(top).set_type_flag(LeafNodeWithValue);
                consumed_newcon = 2 + size_of::<NodeValue>();
                unsafe {
                    copy_nonoverlapping(
                        &mut ocx.get_pc_ejection_context().node_value as *mut NodeValue as *mut u8,
                        (top as *mut u8).add(size_of::<NodeHeader>()),
                        size_of::<NodeValue>(),
                    );
                }
            } else {
                as_top_node_mut(top).set_type_flag(LeafNodeEmpty);
                consumed_newcon = 2;
            }
        } else if pc_key_len == 2 {
            let sub: *mut NodeHeader = unsafe { data_offset.add(size_of::<NodeHeader>() + 1) as *mut NodeHeader };
            as_sub_node_mut(sub).set_container_type(1);
            unsafe {
                copy_nonoverlapping(ocx.get_pc_ejection_context().partial_key.as_mut_ptr().add(1), (sub as *mut u8).add(size_of::<NodeHeader>()), 1);
            }

            if ocx.get_pc_ejection_context().path_compressed_node_header.value_present() {
                as_sub_node_mut(sub).set_type_flag(LeafNodeWithValue);
                consumed_newcon = 4 + size_of::<NodeValue>();
                unsafe {
                    copy_nonoverlapping(
                        ocx.get_pc_ejection_context().partial_key.as_mut_ptr(),
                        (sub as *mut u8).add(size_of::<NodeHeader>() + 1),
                        size_of::<NodeValue>(),
                    );
                }
            } else {
                as_sub_node_mut(sub).set_type_flag(LeafNodeEmpty);
                consumed_newcon = 4;
            }
        } else {
            let mut sub: *mut NodeHeader = unsafe { data_offset.add(size_of::<NodeHeader>() + 1) as *mut NodeHeader };
            as_sub_node_mut(sub).set_container_type(1);
            as_sub_node_mut(sub).set_type_flag(InnerNode);
            unsafe {
                copy_nonoverlapping(ocx.get_pc_ejection_context().partial_key.as_mut_ptr().add(1), (sub as *mut u8).add(size_of::<NodeHeader>()), 1);
            }

            as_sub_node_mut(sub).set_child_container(PathCompressed);
            let remaining_pc_key_len: usize = pc_key_len - 2;
            let required: usize = ocx.get_pc_ejection_context().path_compressed_node_header.value_present() as usize * size_of::<NodeValue>()
                + remaining_pc_key_len
                + 1;
            consumed_newcon = 2 + 2 * size_of::<NodeHeader>() + required;
            sub = meta_expand(ocx, ctx, consumed_newcon as u32);

            let pc_node: *mut PathCompressedNodeHeader =
                unsafe { (sub as *mut u8).add(size_of::<NodeHeader>() + 1) as *mut PathCompressedNodeHeader };

            unsafe {
                if ocx.get_pc_ejection_context().path_compressed_node_header.value_present() {
                    (*pc_node).set_value_present(true);
                    (*pc_node).set_size((size_of::<PathCompressedNodeHeader>() + size_of::<NodeValue>() + remaining_pc_key_len) as u8);
                    copy_nonoverlapping(
                        &mut ocx.get_pc_ejection_context().node_value as *mut NodeValue as *mut u8,
                        (pc_node as *mut u8).add(size_of::<PathCompressedNodeHeader>()),
                        size_of::<NodeValue>(),
                    );
                    copy_nonoverlapping(
                        ocx.get_pc_ejection_context().partial_key.as_mut_ptr().add(2),
                        (pc_node as *mut u8).add(size_of::<PathCompressedNodeHeader>()),
                        remaining_pc_key_len,
                    );
                } else {
                    (*pc_node).set_value_present(false);
                    (*pc_node).set_size((size_of::<PathCompressedNodeHeader>() + remaining_pc_key_len) as u8);
                    copy_nonoverlapping(
                        ocx.get_pc_ejection_context().partial_key.as_mut_ptr().add(2),
                        (pc_node as *mut u8).add(size_of::<PathCompressedNodeHeader>()),
                        remaining_pc_key_len,
                    );
                }
            }
        }
        assert!(ocx.get_root_container().free_bytes() as usize >= consumed_newcon);
        let current_value = ocx.get_root_container().free_bytes();
        ocx.get_root_container().set_free_bytes(current_value - consumed_newcon as u8);
        ocx.flush_jump_context();
        ocx.flush_jump_table_sub_context();
    } else {
        if ocx.embedded_traversal_context.embedded_container_depth == 0 {
            safe_sub_node_jump_table_context(ocx, ctx);
        }

        if pc_key_len == 1 {
            let required: usize = size_of::<NodeHeader>() + size_of::<EmbeddedContainer>() - size_of::<PathCompressedNodeHeader>();
            node_head = meta_expand(ocx, ctx, required as u32);
            let child_container: *mut u8 = unsafe { (node_head as *mut u8).add(child_container_offset) };
            unsafe {
                wrap_shift_container(ocx.get_root_container_pointer(), child_container, required);
            }
            update_space_usage(required as i16, ocx, ctx);

            unsafe {
                ocx.embedded_traversal_context.next_embedded_container =
                    Some((node_head as *mut u8).add(child_container_offset) as *mut EmbeddedContainer);
                let value_present: usize = ocx.get_pc_ejection_context().path_compressed_node_header.value_present() as usize;

                if let Some(ref mut next_embedded_container) = ocx.embedded_traversal_context.next_embedded_container {
                    (*(*next_embedded_container))
                        .set_size((size_of::<EmbeddedContainer>() + size_of::<NodeHeader>() + 1 + value_present * size_of::<NodeValue>()) as u8);
                } else {
                    panic!("{}", ERR_NO_NEXT_CONTAINER)
                }
                /*unsafe { (*(ocx.embedded_traversal_context.next_embedded_container.unwrap())).set_size(
                    (size_of::<EmbeddedContainer>() + size_of::<NodeHeader>() + 1 + value_present * size_of::<NodeValue>()) as u8
                )};*/
                let embedded_top: *mut NodeHeader =
                    (node_head as *mut u8).add(child_container_offset + size_of::<EmbeddedContainer>()) as *mut NodeHeader;
                write_bytes(embedded_top as *mut u8, 0, size_of::<NodeHeader>());

                if ocx.get_pc_ejection_context().path_compressed_node_header.value_present() {
                    as_top_node_mut(embedded_top).set_type_flag(LeafNodeWithValue);
                    copy_nonoverlapping(
                        &mut ocx.get_pc_ejection_context().node_value as *mut NodeValue as *mut u8,
                        (embedded_top as *mut u8).add(size_of::<NodeHeader>() + 1),
                        size_of::<NodeValue>(),
                    );
                } else {
                    as_top_node_mut(embedded_top).set_type_flag(LeafNodeEmpty);
                }
                copy_nonoverlapping(
                    ocx.get_pc_ejection_context().partial_key.as_mut_ptr(),
                    (embedded_top as *mut u8).add(size_of::<NodeHeader>()),
                    1,
                );
            }
        } else if pc_key_len == 2 {
            let required: usize = size_of::<NodeHeader>() * 2 + size_of::<EmbeddedContainer>() - size_of::<PathCompressedNodeHeader>();
            node_head = meta_expand(ocx, ctx, required as u32);

            let child_container: *mut u8 = unsafe { (node_head as *mut u8).add(child_container_offset) };
            unsafe {
                wrap_shift_container(ocx.get_root_container_pointer(), child_container, required);
            }

            update_space_usage(required as i16, ocx, ctx);

            unsafe {
                ocx.embedded_traversal_context.next_embedded_container =
                    Some((node_head as *mut u8).add(child_container_offset) as *mut EmbeddedContainer);
                let value_present = ocx.get_pc_ejection_context().path_compressed_node_header.value_present() as usize;

                if let Some(ref mut next_embedded_container) = ocx.embedded_traversal_context.next_embedded_container {
                    (*(*(next_embedded_container))).set_size(
                        (size_of::<EmbeddedContainer>() + (size_of::<NodeHeader>() + 1) * 2 + value_present * size_of::<NodeValue>()) as u8,
                    );
                } else {
                    panic!("{}", ERR_NO_NEXT_CONTAINER)
                }
                /*unsafe { (*(ocx.embedded_traversal_context.next_embedded_container.unwrap())).set_size(
                    (size_of::<EmbeddedContainer>() + (size_of::<NodeHeader>() + 1) * 2 + value_present * size_of::<NodeValue>()) as u8
                )};*/

                let embedded_top: *mut NodeHeader =
                    (node_head as *mut u8).add(child_container_offset + size_of::<EmbeddedContainer>()) as *mut NodeHeader;
                write_bytes(embedded_top as *mut u8, 0, size_of::<NodeHeader>());
                as_top_node_mut(embedded_top).set_type_flag(InnerNode);
                copy_nonoverlapping(
                    ocx.get_pc_ejection_context().partial_key.as_mut_ptr(),
                    (embedded_top as *mut u8).add(size_of::<NodeHeader>()),
                    1,
                );

                let embedded_sub: *mut NodeHeader = embedded_top.add(size_of::<NodeHeader>() + 1);
                write_bytes(embedded_sub as *mut u8, 0, 1);
                as_sub_node_mut(embedded_sub).set_container_type(1);

                if ocx.get_pc_ejection_context().path_compressed_node_header.value_present() {
                    as_sub_node_mut(embedded_sub).set_type_flag(LeafNodeWithValue);
                    copy_nonoverlapping(
                        &mut ocx.get_pc_ejection_context().node_value as *mut NodeValue as *mut u8,
                        (embedded_sub as *mut u8).add(size_of::<NodeHeader>() + 1),
                        size_of::<NodeValue>(),
                    );
                } else {
                    as_sub_node_mut(embedded_sub).set_type_flag(LeafNodeEmpty);
                }
                copy_nonoverlapping(
                    ocx.get_pc_ejection_context().partial_key.as_mut_ptr().add(1),
                    (embedded_sub as *mut u8).add(size_of::<NodeHeader>()),
                    1,
                );
            }
        } else {
            let required: usize = size_of::<NodeHeader>() * 2 + size_of::<EmbeddedContainer>();
            node_head = meta_expand(ocx, ctx, required as u32);

            let child_container: *mut u8 = unsafe { (node_head as *mut u8).add(child_container_offset) };
            unsafe {
                wrap_shift_container(ocx.get_root_container_pointer(), child_container, required);
            }
            update_space_usage(required as i16, ocx, ctx);

            let remaining_partial_key = pc_key_len - 2;
            unsafe {
                ocx.embedded_traversal_context.next_embedded_container =
                    Some((node_head as *mut u8).add(child_container_offset) as *mut EmbeddedContainer);
                let value_present: usize = ocx.get_pc_ejection_context().path_compressed_node_header.value_present() as usize;

                if let Some(ref mut next_embedded_container) = ocx.embedded_traversal_context.next_embedded_container {
                    (*(*(next_embedded_container))).set_size(
                        (size_of::<EmbeddedContainer>()
                            + (size_of::<NodeHeader>() + 1) * 2
                            + value_present * size_of::<NodeValue>()
                            + remaining_partial_key) as u8,
                    );
                } else {
                    panic!("{}", ERR_NO_NEXT_CONTAINER)
                }

                /*unsafe { (*(ocx.embedded_traversal_context.next_embedded_container.unwrap())).set_size(
                    (size_of::<EmbeddedContainer>() + (size_of::<NodeHeader>() + 1) * 2 + value_present * size_of::<NodeValue>() + remaining_partial_key) as u8
                )};*/

                let embedded_top: *mut NodeHeader =
                    (node_head as *mut u8).add(child_container_offset + size_of::<EmbeddedContainer>()) as *mut NodeHeader;
                write_bytes(embedded_top as *mut u8, 0, size_of::<NodeHeader>());
                as_top_node_mut(embedded_top).set_type_flag(InnerNode);
                copy_nonoverlapping(
                    ocx.get_pc_ejection_context().partial_key.as_mut_ptr(),
                    (embedded_top as *mut u8).add(size_of::<NodeHeader>()),
                    1,
                );

                let embedded_sub: *mut NodeHeader = embedded_top.add(size_of::<NodeHeader>() + 1);
                write_bytes(embedded_sub as *mut u8, 0, 1);
                as_sub_node_mut(embedded_sub).set_container_type(1);
                as_sub_node_mut(embedded_sub).set_type_flag(InnerNode);
                copy_nonoverlapping(
                    ocx.get_pc_ejection_context().partial_key.as_mut_ptr().add(1),
                    (embedded_sub as *mut u8).add(size_of::<NodeHeader>()),
                    1,
                );
                as_sub_node_mut(embedded_sub).set_child_container(PathCompressed);

                let pc_node: *mut PathCompressedNodeHeader =
                    (embedded_sub as *mut u8).add(size_of::<NodeHeader>() + 1) as *mut PathCompressedNodeHeader;

                if ocx.get_pc_ejection_context().path_compressed_node_header.value_present() {
                    (*pc_node).set_value_present(true);
                    (*pc_node).set_size((size_of::<PathCompressedNodeHeader>() + size_of::<NodeValue>() + pc_key_len - 2) as u8);
                    copy_nonoverlapping(
                        &mut ocx.get_pc_ejection_context().node_value as *mut NodeValue as *mut u8,
                        (pc_node as *mut u8).add(size_of::<PathCompressedNodeHeader>()),
                        size_of::<NodeValue>(),
                    );
                    copy_nonoverlapping(
                        ocx.get_pc_ejection_context().partial_key.as_mut_ptr().add(2),
                        (pc_node as *mut u8).add(size_of::<PathCompressedNodeHeader>() + size_of::<NodeValue>()),
                        pc_key_len - 2,
                    );
                } else {
                    (*pc_node).set_value_present(false);
                    (*pc_node).set_size((size_of::<PathCompressedNodeHeader>() + pc_key_len - 2) as u8);
                    copy_nonoverlapping(
                        ocx.get_pc_ejection_context().partial_key.as_mut_ptr().add(2),
                        (pc_node as *mut u8).add(size_of::<PathCompressedNodeHeader>()),
                        pc_key_len - 2,
                    );
                }
            }
        }

        let current_embedded_container_depth: i32 = ocx.embedded_traversal_context.embedded_container_depth;

        if let Some(ref mut next_embedded_container) = ocx.embedded_traversal_context.next_embedded_container {
            ocx.embedded_traversal_context.embedded_stack.as_mut().expect(ERR_EMPTY_EMB_STACK)[current_embedded_container_depth as usize] =
                Some(AtomicEmbContainer::new_from_pointer(*next_embedded_container));
        } else {
            panic!("{}", ERR_NO_POINTER)
        }
        ocx.embedded_traversal_context.embedded_container_depth += 1;
        ocx.next_container_pointer = None;

        as_sub_node_mut(node_head).set_child_container(ChildLinkType::EmbeddedContainer);
        ocx.path_compressed_ejection_context = None;
        ocx.header.set_next_container_valid(EmbeddedContainerValid);
        ctx.current_container_offset += child_container_offset as i32;
        safe_sub_node_jump_table_context(ocx, ctx);
    }
}

pub fn inject_sublevel_reference_key(node_head: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, refkey: u8) {
    log_to_file("inject_sublevel_reference_key");
    let mut relative: i32 = 0;
    let diff: u8 = refkey - ctx.last_sub_char_seen;

    let target: *mut u8 = if diff <= KEY_DELTA_STATES as u8 {
        relative = 1;
        unsafe { (node_head as *mut u8).add(size_of::<NodeHeader>()) }
    } else {
        unsafe { (node_head as *mut u8).add(size_of::<NodeHeader>() + 1) }
    };

    unsafe {
        let node_offset: i32 = (node_head as *mut u8).offset_from(ocx.get_root_container_pointer() as *mut u8) as i32;
        let free_size_left: i32 = ocx.get_root_container().free_bytes() as i32;
        let bytes_to_move: i32 = ocx.get_root_container().size() as i32 - (node_offset + free_size_left);
        copy(node_head as *mut u8, target, bytes_to_move as usize);
        write_bytes(node_head as *mut u8, 0, size_of::<NodeHeader>() + 1 - relative as usize);
        as_top_node_mut(node_head).set_type_flag(InnerNode);
        as_top_node_mut(node_head).set_container_type(1);
    }

    update_space_usage(size_of::<NodeHeader>() as i16 + 1 - relative as i16, ocx, ctx);
    ctx.second_char = refkey;

    if relative == 0 {
        set_nodes_key2(node_head as *mut Node, ocx, ctx, false, refkey);
    } else {
        as_top_node_mut(node_head).set_delta(diff);
        let mut successor: Option<*mut Node> = None;
        let skipped: u32 = get_successor(node_head, &mut successor, ocx, ctx, false);

        if skipped > 0 {
            assert_eq!(unsafe { as_top_node(&mut (*(successor.expect(ERR_NO_SUCCESSOR))).header as *mut NodeHeader).container_type() }, 1);
            let succ_delta: u8;
            unsafe {
                let successor_ptr: *mut Node = successor.expect(ERR_NO_SUCCESSOR);
                succ_delta = if as_top_node(&mut (*successor_ptr).header as *mut NodeHeader).delta() == 0 {
                    (*successor_ptr).stored_value
                } else {
                    as_top_node(&mut (*successor_ptr).header as *mut NodeHeader).delta()
                };
                update_successor_key(successor_ptr, succ_delta - diff, refkey, skipped, ocx, ctx);
            }
        }
    }
}

#[bitfield(u8)]
pub struct PathCompressedNodeHeader {
    #[bits(1)]
    pub value_present: bool,

    #[bits(7)]
    pub size: u8,
}

impl PathCompressedNodeHeader {
    pub fn as_raw(&self) -> *const PathCompressedNodeHeader {
        self as *const PathCompressedNodeHeader
    }

    pub fn as_raw_char(&self) -> *const u8 {
        self.as_raw() as *const u8
    }
}
