use crate::hyperion::components::container::{
    get_container_link_size, shift_container, Container, ContainerLink, EmbeddedContainer, CONTAINER_MAX_EMBEDDED_DEPTH, CONTAINER_MAX_FREESIZE,
};
use crate::hyperion::components::context::ContainerValidTypes::{ContainerValid, EmbeddedContainerValid};
use crate::hyperion::components::context::OperationCommand::Put;
use crate::hyperion::components::context::{
    ContainerTraversalContext, ContainerTraversalHeader, ContainerValidTypes, EmbeddedTraversalContext, JumpContext, OperationContext,
    PathCompressedEjectionContext, RangeQueryContext, KEY_DELTA_STATES,
};
use crate::hyperion::components::jump_table::{TopNodeJumpTable, SUBLEVEL_JUMPTABLE_ENTRIES, SUBLEVEL_JUMPTABLE_SHIFTBITS};
use crate::hyperion::components::node::NodeType::{InnerNode, Invalid, LeafNodeEmpty, LeafNodeWithValue};
use crate::hyperion::components::node::{update_successor_key, Node, NodeType, NodeValue};
use crate::hyperion::components::node_header::EmbedLinkCommands::{
    CreateEmbeddedContainer, CreateLinkToContainer, CreatePathCompressedNode, TransformPathCompressedNode,
};
use crate::hyperion::components::return_codes::ReturnCode;
use crate::hyperion::components::return_codes::ReturnCode::{ChildContainerMissing, GetFailureNoLeaf, OK};
use crate::hyperion::components::sub_node::ChildLinkType::{Link, PathCompressed};
use crate::hyperion::components::sub_node::{ChildLinkType, SubNode};
use crate::hyperion::components::top_node::TopNode;
use crate::hyperion::internals::atomic_pointer::{initialize_container, AtomicChar, AtomicEmbContainer, AtomicNodeValue};
use crate::hyperion::internals::core::{initialize_ejected_container, HyperionCallback, GLOBAL_CONFIG};
use crate::hyperion::internals::helpers::{copy_memory_from, copy_memory_to};
use crate::memorymanager::api::{get_pointer, reallocate, HyperionPointer};
use bitfield_struct::bitfield;
use libc::{memcmp, memmove, size_t, tm};
use std::ffi::c_void;
use std::ptr::{copy, write_bytes, NonNull};

#[repr(C)]
#[derive(Clone, Copy)]
union NodeUnion {
    pub top_node: TopNode,
    pub sub_node: SubNode,
}

pub struct NodeHeader {
    header: NodeUnion,
}

impl NodeHeader {
    pub fn deep_copy(&self) -> NodeHeader {
        let node = self.as_top_node();

        if node.is_top_node() {
            NodeHeader {
                header: NodeUnion { top_node: *node },
            }
        } else {
            NodeHeader {
                header: NodeUnion {
                    sub_node: *self.as_sub_node(),
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

    pub fn as_raw(&self) -> *const NodeHeader {
        self as *const NodeHeader
    }

    pub fn as_raw_mut(&mut self) -> *mut NodeHeader {
        self as *mut NodeHeader
    }

    pub fn as_raw_char(&self) -> *const char {
        self.as_raw() as *const char
    }

    pub fn as_raw_char_mut(&self) -> *mut char {
        self.as_raw() as *mut char
    }

    pub fn as_raw_compressed(&self) -> *const PathCompressedNodeHeader {
        unsafe { self.as_raw().add(self.get_offset_child_container()) as *const PathCompressedNodeHeader }
    }

    pub fn as_raw_compressed_mut(&mut self) -> *mut PathCompressedNodeHeader {
        unsafe { self.as_raw().add(self.get_offset_child_container()) as *mut PathCompressedNodeHeader }
    }

    pub fn as_path_compressed(&self) -> &PathCompressedNodeHeader {
        unsafe { self.as_raw_compressed().as_ref().unwrap() }
    }

    pub fn as_path_compressed_mut(&mut self) -> &mut PathCompressedNodeHeader {
        unsafe { self.as_raw_compressed_mut().as_mut().unwrap() }
    }

    pub fn as_raw_embedded(&self, offset: usize) -> *const EmbeddedContainer {
        unsafe { self.as_raw().add(offset) as *const EmbeddedContainer }
    }

    pub fn as_top_node_mut(&mut self) -> &mut TopNode {
        unsafe { &mut self.header.top_node }
    }

    pub fn as_top_node(&self) -> &TopNode {
        unsafe { &self.header.top_node }
    }

    pub fn as_sub_node_mut(&mut self) -> &mut SubNode {
        unsafe { &mut self.header.sub_node }
    }

    pub fn as_sub_node(&self) -> &SubNode {
        unsafe { &self.header.sub_node }
    }

    pub fn get_jump_overhead(&self) -> u8 {
        self.as_top_node().jump_successor_present() as u8 * size_of::<u16>() as u8
            + self.as_top_node().jump_table_present() as u8 * size_of::<TopNodeJumpTable>() as u8
    }

    pub fn get_leaf_size(&self) -> usize {
        match self.as_top_node().type_flag() {
            LeafNodeWithValue => size_of::<NodeValue>(),
            _ => 0,
        }
    }

    pub fn get_offset_child_container(&self) -> usize {
        if self.as_top_node().delta() == 0 {
            return size_of::<NodeHeader>() + 1 + self.get_leaf_size();
        }
        size_of::<NodeHeader>() + self.get_leaf_size()
    }

    pub fn get_child_link_size(&self) -> usize {
        match self.as_sub_node().child_container() {
            ChildLinkType::None => 0,
            ChildLinkType::Link => size_of::<ContainerLink>(),
            ChildLinkType::EmbeddedContainer => unsafe { (*self.as_raw_embedded(self.get_offset_child_container())).size() as usize },
            ChildLinkType::PathCompressed => unsafe { (*self.as_raw_compressed()).size() as usize },
        }
    }

    pub fn get_offset_to_next_node(&self) -> usize {
        if self.as_top_node().is_top_node() {
            return self.get_offset_top_node();
        }
        self.get_offset_sub_node()
    }

    pub fn get_offset(&self) -> usize {
        if self.as_top_node().container_type() == 0 {
            return self.get_offset_top_node();
        }
        self.get_offset_sub_node()
    }

    pub fn get_offset_top_node(&self) -> usize {
        if !self.as_top_node().has_delta() {
            self.get_offset_top_node_nondelta()
        } else {
            self.get_offset_top_node_delta()
        }
    }

    pub fn get_offset_top_node_delta(&self) -> usize {
        size_of::<NodeHeader>() + self.get_jump_overhead() as usize + self.get_leaf_size()
    }

    pub fn get_offset_top_node_nondelta(&self) -> usize {
        self.get_offset_top_node_delta() + 1
    }

    pub fn get_offset_sub_node(&self) -> usize {
        if !self.as_top_node().has_delta() {
            self.get_offset_sub_node_nondelta()
        } else {
            self.get_offset_sub_node_delta()
        }
    }

    pub fn get_offset_sub_node_delta(&self) -> usize {
        size_of::<NodeHeader>() + self.get_jump_overhead() as usize + self.get_child_link_size()
    }

    pub fn get_offset_sub_node_nondelta(&self) -> usize {
        self.get_offset_sub_node_delta() + 1
    }

    pub fn get_offset_node_value(&self) -> usize {
        let base_size: usize = size_of::<NodeHeader>();
        if self.as_top_node().is_top_node() {
            return base_size + self.get_jump_overhead() as usize;
        }
        if !self.as_top_node().has_delta() {
            base_size + 1
        } else {
            base_size
        }
    }

    pub fn get_offset_jump(&self) -> usize {
        if !self.as_top_node().has_delta() {
            return size_of::<NodeHeader>() + 1;
        }
        size_of::<NodeHeader>()
    }

    pub fn get_jump_value(&self) -> u16 {
        let self_pointer: *const NodeHeader = self as *const NodeHeader;
        unsafe { *(self_pointer.add(self.get_offset_jump()) as *const u16) }
    }

    pub fn get_offset_jump_table(&self) -> u16 {
        self.get_offset_jump() as u16 + self.as_top_node().jump_successor_present() as u16 * size_of::<u16>() as u16
    }

    fn get_node_value_pc(&self, ocx: &mut OperationContext) -> ReturnCode {
        let pc_head: &PathCompressedNodeHeader = self.as_path_compressed();
        if pc_head.value_present() {
            unsafe {
                copy_memory_from(
                    pc_head.as_raw_char().add(size_of::<PathCompressedNodeHeader>()),
                    ocx.get_return_value_mut() as *mut NodeValue,
                    size_of::<NodeValue>(),
                )
            }
        }
        ocx.header.set_operation_done(true);
        OK
    }

    pub fn get_node_value(&self, ocx: &mut OperationContext) -> ReturnCode {
        if ocx.header.pathcompressed_child() {
            return self.get_node_value_pc(ocx);
        }

        let top_node_type: NodeType = self.as_top_node().type_flag();

        if top_node_type == InnerNode || top_node_type == Invalid {
            return GetFailureNoLeaf;
        }

        if top_node_type == LeafNodeWithValue {
            unsafe {
                copy_memory_from(
                    self.as_raw_char().add(self.get_offset_node_value()),
                    ocx.get_return_value_mut() as *mut NodeValue,
                    size_of::<NodeValue>(),
                );
            }
        }

        ocx.header.set_operation_done(true);
        OK
    }

    pub fn set_node_value(&mut self, ocx: &mut OperationContext) -> ReturnCode {
        let top_node: &mut TopNode = self.as_top_node_mut();

        if top_node.type_flag() == Invalid || top_node.type_flag() == InnerNode {
            ocx.header.set_performed_put(true);
        }

        if ocx.input_value.is_some() {
            let input_value: &mut NodeValue = ocx.get_input_value_mut();
            unsafe {
                copy_memory_to(self.as_raw_char_mut().add(self.get_offset_node_value()), input_value as *const NodeValue, size_of::<NodeValue>());
            }
            self.as_top_node_mut().set_type_flag(LeafNodeWithValue);
        } else {
            self.as_top_node_mut().set_type_flag(LeafNodeEmpty);
        }
        ocx.header.set_operation_done(true);
        OK
    }

    pub fn register_jump_context(&mut self, ctx: &mut ContainerTraversalContext, ocx: &mut OperationContext) {
        let jump_context: &mut JumpContext = ocx.get_jump_context_mut();
        if self.as_top_node().jump_successor_present() {
            jump_context.predecessor = Some(unsafe { Box::from_raw(self.as_raw_mut()) }); //AtomicHeader::new_from_pointer(self.as_raw_mut());
            jump_context.sub_nodes_seen = 0;
            jump_context.top_node_predecessor_offset_absolute = ctx.current_container_offset;
        } else {
            jump_context.predecessor = None;
        }
    }

    pub fn call_top_node(&mut self, rqc: &mut RangeQueryContext, hyperion_callback: HyperionCallback<NodeValue>) -> bool {
        match self.as_top_node().type_flag() {
            LeafNodeEmpty => hyperion_callback(&mut rqc.current_key, rqc.current_key_offset + 1, &mut AtomicNodeValue::new()),
            LeafNodeWithValue => unsafe {
                hyperion_callback(
                    &mut rqc.current_key,
                    rqc.current_key_offset + 1,
                    &mut AtomicNodeValue::new_from_pointer(self.as_raw_mut().add(self.get_offset_node_value()) as *mut NodeValue),
                )
            },
            Invalid | InnerNode => true,
        }
    }

    pub fn call_sub_node(&mut self, range_query_context: &mut RangeQueryContext, hyperion_callback: HyperionCallback<NodeValue>) -> bool {
        match self.as_sub_node().type_flag() {
            LeafNodeEmpty => {
                hyperion_callback(&mut range_query_context.current_key, range_query_context.current_key_offset + 2, &mut AtomicNodeValue::new())
            },
            LeafNodeWithValue => unsafe {
                hyperion_callback(
                    &mut range_query_context.current_key,
                    range_query_context.current_key_offset + 2,
                    &mut AtomicNodeValue::new_from_pointer(self.as_raw_mut().add(self.get_offset_node_value()) as *mut NodeValue),
                )
            },
            Invalid | InnerNode => true,
        }
    }

    pub fn compare_path_compressed_node(&self, ocx: &mut OperationContext) -> bool {
        let pc_header: &PathCompressedNodeHeader = unsafe { self.as_raw_compressed().as_ref().unwrap() };

        let overhead: usize = size_of::<PathCompressedNodeHeader>() + pc_header.value_present() as usize * size_of::<NodeValue>();
        let key_len: u8 = pc_header.size() - overhead as u8;

        if ocx.key_len_left - 2 != key_len as i32 {
            return false;
        }

        let op_key: &mut AtomicChar = ocx.get_key_as_mut();
        unsafe {
            let key: *const PathCompressedNodeHeader = (pc_header as *const PathCompressedNodeHeader).add(overhead);
            memcmp(op_key.add_get(2) as *mut c_void, key as *mut c_void, key_len as size_t) == 0
        }
    }

    pub fn use_sub_node_jump_table(&mut self, ctx: &mut ContainerTraversalContext) -> u8 {
        let jump_class = ctx.second_char >> SUBLEVEL_JUMPTABLE_SHIFTBITS;

        if jump_class > 0 {
            let jump_table_pointer: *mut u16 = unsafe { self.as_raw_mut().add(self.get_offset_jump_table() as usize) } as *mut u16;
            ctx.current_container_offset += self.get_offset() as i32 + unsafe { *jump_table_pointer + (jump_class as u16 - 1) } as i32;
            return jump_class << SUBLEVEL_JUMPTABLE_SHIFTBITS;
        }

        ctx.current_container_offset += self.get_offset() as i32;
        0
    }

    pub fn safe_path_compressed_context(&mut self, ocx: &mut OperationContext) {
        let pc_node: &PathCompressedNodeHeader = self.as_path_compressed();
        ocx.path_compressed_ejection_context = Some(PathCompressedEjectionContext::default());

        if pc_node.value_present() {
            unsafe {
                copy(
                    (pc_node as *const PathCompressedNodeHeader as *const c_void)
                        .add(size_of::<PathCompressedNodeHeader>())
                        .add(size_of::<NodeValue>()) as *const u8,
                    ocx.path_compressed_ejection_context.as_mut().unwrap().partial_key.as_mut_ptr() as *mut u8,
                    pc_node.size() as usize - (size_of::<PathCompressedNodeHeader>() + size_of::<NodeValue>()),
                );
                copy(
                    (pc_node as *const PathCompressedNodeHeader as *const c_void)
                        .add(size_of::<PathCompressedNodeHeader>())
                        .add(size_of::<NodeValue>()) as *const u8,
                    &mut ocx.path_compressed_ejection_context.as_mut().unwrap().node_value as *mut NodeValue as *mut u8,
                    size_of::<NodeValue>(),
                );
            }
        } else {
            unsafe {
                copy(
                    (pc_node as *const PathCompressedNodeHeader as *const c_void).add(size_of::<PathCompressedNodeHeader>()) as *const u8,
                    ocx.path_compressed_ejection_context.as_mut().unwrap().partial_key.as_mut_ptr() as *mut u8,
                    pc_node.size() as usize - size_of::<PathCompressedNodeHeader>(),
                );
            }
        }
        ocx.path_compressed_ejection_context.as_mut().unwrap().pec_valid = 1;
        unsafe {
            copy(
                (pc_node as *const PathCompressedNodeHeader as *const c_void) as *const u8,
                &mut ocx.path_compressed_ejection_context.as_mut().unwrap().path_compressed_node_header as *mut PathCompressedNodeHeader as *mut u8,
                size_of::<PathCompressedNodeHeader>(),
            );
        }
    }
}

pub fn delete_node(node_head: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) -> ReturnCode {
    let node_ref: &mut NodeHeader = unsafe { node_head.as_mut().unwrap() };
    let size_deleted = if node_ref.as_top_node().type_flag() == LeafNodeWithValue {
        size_of::<NodeValue>()
    } else {
        0
    };
    unsafe {
        let container: *mut Container = ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut() as *mut Container;
        let dest: *mut c_void = (node_head as *mut c_void).add(node_ref.get_offset_node_value());
        let src: *mut c_void = dest.add(size_of::<NodeValue>());
        let offset: i64 = src.offset_from(container as *mut c_void) as i64;
        let fsl: i64 = (*container).free_bytes() as i64;
        let remaining_length: i64 = (*container).size() as i64 - (offset + fsl);
        copy(src as *const u8, dest as *mut u8, remaining_length as usize);
    }
    node_ref.as_top_node_mut().set_type_flag(InnerNode);
    let mut emb_ctx: EmbeddedTraversalContext = ocx.embedded_traversal_context.take().unwrap();
    emb_ctx.root_container.as_mut().update_space_usage(0 - size_deleted as i16, ocx, ctx);
    ocx.embedded_traversal_context = Some(emb_ctx);
    OK
}

pub fn update_path_compressed_node(mut node: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) -> *mut NodeHeader {
    if ocx.input_value.is_some() {
        let mut pc_node: &mut PathCompressedNodeHeader = unsafe { (*node).as_path_compressed_mut() };
        let mut value: *mut c_void = unsafe { (pc_node as *mut PathCompressedNodeHeader as *mut c_void).add(size_of::<PathCompressedNodeHeader>()) };

        if pc_node.value_present() {
            node = ocx.new_expand(ctx, size_of::<NodeValue>() as u32).as_raw_mut();
            let mut embedded_context: EmbeddedTraversalContext = ocx.embedded_traversal_context.take().unwrap();
            let root_container: &mut Container = embedded_context.root_container.as_mut();
            unsafe {
                root_container.wrap_shift_container(value, size_of::<NodeValue>());
            }
            root_container.update_space_usage(size_of::<NodeValue>() as i16, ocx, ctx);
            ocx.embedded_traversal_context = Some(embedded_context);
            pc_node = unsafe { (*node).as_path_compressed_mut() };
            value = unsafe { (pc_node as *mut PathCompressedNodeHeader as *mut c_void).add(size_of::<PathCompressedNodeHeader>()) };
        }
        unsafe {
            copy_memory_from(value, ocx.input_value.as_mut().unwrap().as_mut() as *mut NodeValue, size_of::<NodeValue>());
        }
        pc_node.set_value_present(true);
    }
    node
}

pub fn eject_container(mut node: Box<NodeHeader>, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) {
    assert!(ocx.embedded_traversal_context.as_mut().unwrap().embedded_container_depth > 0);
    node = ocx.meta_expand(ctx, get_container_link_size() as u32);
    let mut emb_context: EmbeddedTraversalContext = ocx.embedded_traversal_context.take().unwrap();
    let emb_container: &mut AtomicEmbContainer = &mut emb_context.embedded_stack[0];

    let child_offset: usize = node.get_offset_child_container();
    let embedded_container_offset: usize =
        unsafe { emb_container.get_as_mut_memory().offset_from(emb_context.root_container.as_mut() as *mut Container as *mut c_void) as usize };
    let em_csize: u32 = unsafe { (*(emb_container.get())).size() as u32 };
    let ro_csize: u32 = emb_context.root_container.as_mut().size();
    assert!(ro_csize > em_csize);
    let ro_free_size_left: u8 = emb_context.root_container.as_mut().free_bytes();

    let mut container_ptr: HyperionPointer = initialize_ejected_container(ocx.arena.as_mut().unwrap().as_mut(), em_csize);
    let p_new: *mut Container = get_pointer(ocx.arena.as_mut().unwrap(), &mut container_ptr, 1, ctx.first_char) as *mut Container;
    unsafe {
        let target: *mut c_void = (p_new as *mut c_void).add((*p_new).get_container_head_size() as usize);
        let source: *mut c_void = emb_container.get_as_mut_memory().add(size_of::<EmbeddedContainer>());
        copy_memory_from(source, target, em_csize as usize - size_of::<EmbeddedContainer>());
        (*p_new).set_free_size_left((*p_new).free_bytes() as u32 - (em_csize - size_of::<EmbeddedContainer>() as u32));
    }
    node.as_sub_node_mut().set_child_container(ChildLinkType::Link);

    unsafe {
        let target2: *mut ContainerLink = (node.as_mut() as *mut NodeHeader as *mut c_void).add(child_offset) as *mut ContainerLink;
        (*target2).ptr = container_ptr;
    }

    let size: i32 = ro_csize as i32 - (em_csize as i32 + embedded_container_offset as i32 + ro_free_size_left as i32);
    emb_context.embedded_container_depth = 0;

    if size > 0 {
        unsafe {
            let node_ptr: *mut NodeHeader = node.as_mut() as *mut NodeHeader;
            let shift_dest: *mut c_void = (node_ptr as *mut c_void).add((*node_ptr).get_offset());
            let shift_src: *mut c_void = emb_container.get_as_mut_memory().add(em_csize as usize);
            memmove(shift_dest, shift_src, size as size_t);
        }
    }

    let delta: i32 = -(em_csize as i32 - get_container_link_size() as i32);
    let new_free_size_left: i32 = emb_context.root_container.as_mut().free_bytes() as i32 - delta;
    emb_context.root_container.as_mut().update_space_usage(delta as i16, ocx, ctx);
    assert!(ro_csize as i32 > new_free_size_left);

    unsafe {
        let p_free = (emb_context.root_container.as_mut() as *mut Container as *mut c_void).add(ro_csize as usize - new_free_size_left as usize);
        write_bytes(p_free as *mut u8, 0, new_free_size_left as usize);
    }

    if new_free_size_left > CONTAINER_MAX_FREESIZE as i32 {
        let used = ro_csize as i32 - (ro_free_size_left as i32 - delta);
        assert!(used > 0);
        let container_increment = unsafe { GLOBAL_CONFIG.lock().unwrap().header.container_size_increment() as i32 };
        let mut tgt: u32 = (used / container_increment) as u32;
        if (used % container_increment) != 0 {
            tgt += 1;
        }
        let tgt_size: u32 = tgt * container_increment as u32;
        let new_free_size: u32 = (ro_free_size_left as u32 - delta as u32) % container_increment as u32;

        assert_eq!(emb_context.embedded_container_depth, 0);
        emb_context.root_container_pointer =
            reallocate(ocx.arena.as_mut().unwrap().as_mut(), &mut emb_context.root_container_pointer, tgt_size as usize, ocx.chained_pointer_hook);
        unsafe {
            emb_context.root_container =
                Box::from_raw(
                    get_pointer(ocx.arena.as_mut().unwrap().as_mut(), &mut emb_context.root_container_pointer, 1, ocx.chained_pointer_hook)
                        as *mut Container,
                );
        }
        emb_context.root_container.set_free_size_left(new_free_size);
        emb_context.root_container.as_mut().set_size(tgt_size);
    }
    ocx.embedded_traversal_context = Some(emb_context);
}

pub fn add_embedded_container(mut node: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) {
    ocx.header.set_next_container_valid(EmbeddedContainerValid);
    let offset_child_container: usize = unsafe { (*node).get_offset_child_container() };
    node = ocx.new_expand_embedded(ctx, size_of::<EmbeddedContainer>() as u32).as_raw_mut();
    let mut emb_context: EmbeddedTraversalContext = ocx.embedded_traversal_context.take().unwrap();
    unsafe {
        let base_ptr: *mut c_void = node as *mut c_void;
        emb_context.next_embedded_container = Some(Box::from_raw(base_ptr.add(offset_child_container) as *mut EmbeddedContainer));

        emb_context.root_container.as_mut().wrap_shift_container(
            emb_context.next_embedded_container.as_mut().unwrap().as_mut() as *mut EmbeddedContainer as *mut c_void,
            size_of::<EmbeddedContainer>(),
        );
    }
    ctx.current_container_offset += offset_child_container as i32;
    unsafe { (*node).as_sub_node_mut().set_child_container(ChildLinkType::EmbeddedContainer) };
    ocx.embedded_traversal_context = Some(emb_context);
    ocx.safe_sub_node_jump_table_context(ctx);
    let mut emb_context: EmbeddedTraversalContext = ocx.embedded_traversal_context.take().unwrap();
    emb_context.embedded_stack[emb_context.embedded_container_depth as usize] =
        AtomicEmbContainer::new_from_pointer(emb_context.next_embedded_container.as_mut().unwrap().as_mut() as *mut EmbeddedContainer);
    emb_context.embedded_container_depth += 1;
    ocx.next_container_pointer = None;
    emb_context.root_container.update_space_usage(size_of::<EmbeddedContainer>() as i16, ocx, ctx);
    ocx.embedded_traversal_context = Some(emb_context);
}

pub fn create_node_embedded(
    mut node_head: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, container_depth: u8,
    set_key_after_creation: bool, add_value_after_creation: bool, key_delta: u8,
) -> *mut NodeHeader {
    let absolute_key: u8 = if container_depth == 0 { ctx.first_char } else { ctx.second_char };
    let input_memory_consumption: usize = if ocx.input_value.is_some() {
        add_value_after_creation as usize * size_of::<NodeValue>()
    } else {
        0
    };
    let required: usize = size_of::<NodeHeader>() + set_key_after_creation as usize + input_memory_consumption;
    node_head = ocx.new_expand_embedded(ctx, required as u32).as_raw_mut();

    let mut emb_context: EmbeddedTraversalContext = ocx.embedded_traversal_context.take().unwrap();
    let amount: i32 = unsafe {
        emb_context.root_container.as_mut().size() as i32
            - (emb_context.root_container.as_mut().free_bytes() as i32
                + ((node_head as *mut c_void).offset_from(emb_context.root_container.as_mut() as *mut Container as *mut c_void) as i32))
    };

    if amount > 0 {
        unsafe {
            shift_container(node_head as *mut c_void, required, amount as usize);
        }
    }

    unsafe {
        (*node_head).as_top_node_mut().set_type_flag(if add_value_after_creation && input_memory_consumption != 0 {
            LeafNodeWithValue
        } else {
            InnerNode
        });
        (*node_head).as_top_node_mut().set_container_type(container_depth);
    }
    emb_context.root_container.as_mut().update_space_usage(required as i16, ocx, ctx);
    ocx.embedded_traversal_context = Some(emb_context);

    if set_key_after_creation {
        unsafe {
            (*(node_head as *mut Node)).set_nodes_key2(ocx, ctx, true, absolute_key);
        }
    } else {
        unsafe {
            (*node_head).as_top_node_mut().set_delta(key_delta);
        }
        let mut successor_ptr: Option<NonNull<Node>> = None;
        let skipped: u32 = get_successor_embedded(node_head, &mut successor_ptr, ocx, ctx);
        if skipped > 0 {
            let successor: &mut Node = unsafe { successor_ptr.as_mut().unwrap().as_mut() };
            let diff: u8 = if successor.header.as_top_node().delta() == 0 {
                successor.stored_value - key_delta
            } else {
                successor.header.as_top_node().delta() - key_delta
            };
            update_successor_key(successor as *mut Node, diff, absolute_key, skipped, ocx, ctx);
        }
    }

    if add_value_after_creation {
        unsafe {
            (*node_head).set_node_value(ocx);
        }
    }

    if !ctx.header.end_operation() && container_depth > 0 {
        unsafe {
            (*node_head).as_sub_node_mut().set_child_container(ChildLinkType::None);
        }
        embed_or_link_child(node_head, ocx, ctx);
    }
    ocx.header.set_performed_put(true);
    node_head
}

pub enum EmbedLinkCommands {
    CreateLinkToContainer,
    CreatePathCompressedNode,
    CreateEmbeddedContainer,
    TransformPathCompressedNode,
}

pub fn embed_or_link_child(mut node_head: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) -> *mut NodeHeader {
    let mut switch_condition = CreateLinkToContainer;
    let mut required_size_for_path_compression = size_of::<PathCompressedNodeHeader>() as i32 + ocx.key_len_left - 2;
    let container_embedding_hwm = unsafe { GLOBAL_CONFIG.lock().unwrap().container_embedding_limit as i32 };
    if ocx.input_value.is_some() {
        required_size_for_path_compression += size_of::<NodeValue>() as i32;
    }
    if unsafe { (*node_head).as_sub_node().child_container() == PathCompressed } {
        switch_condition = TransformPathCompressedNode;
    } else if ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut().size() as i32 + required_size_for_path_compression
        < container_embedding_hwm
    {
        if ocx.embedded_traversal_context.as_mut().unwrap().embedded_container_depth == 0 {
            if required_size_for_path_compression < 128 {
                switch_condition = CreatePathCompressedNode;
            } else {
                switch_condition = CreateEmbeddedContainer;
            }
        } else if ocx.embedded_traversal_context.as_mut().unwrap().embedded_container_depth < CONTAINER_MAX_EMBEDDED_DEPTH as i32 {
            if (ocx.embedded_traversal_context.as_mut().unwrap().embedded_stack[0].borrow_mut().size() as i32) + required_size_for_path_compression
                < container_embedding_hwm
                && required_size_for_path_compression < 128
            {
                switch_condition = CreatePathCompressedNode;
            } else if (ocx.embedded_traversal_context.as_mut().unwrap().embedded_stack[0].borrow_mut().size() as i32) < container_embedding_hwm {
                switch_condition = CreateEmbeddedContainer;
            }
        }
    } else if unsafe {
        (*node_head).as_sub_node().child_container() == ChildLinkType::None
            && required_size_for_path_compression < 16
            && ((ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut().size() as i32) < (2 * container_embedding_hwm))
    } {
        switch_condition = CreatePathCompressedNode;
    }

    match switch_condition {
        TransformPathCompressedNode => {
            transform_pc_node(node_head, ocx, ctx);
            node_head = unsafe {
                (ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut() as *mut Container as *mut c_void)
                    .add(ctx.current_container_offset as usize) as *mut NodeHeader
            };
        },
        CreateEmbeddedContainer => {
            assert!(unsafe { (*node_head).as_sub_node().child_container() == ChildLinkType::None });
            add_embedded_container(node_head, ocx, ctx);
            node_head = unsafe {
                (ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut() as *mut Container as *mut c_void)
                    .add(ctx.current_container_offset as usize) as *mut NodeHeader
            };
        },
        CreatePathCompressedNode => {
            let offset = unsafe { (*node_head).get_offset_child_container() };
            if (ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut().free_bytes() as i32) < required_size_for_path_compression {
                node_head = ocx.meta_expand(ctx, required_size_for_path_compression as u32).as_raw_mut();
            }

            unsafe {
                let target: *mut PathCompressedNodeHeader = (node_head as *mut c_void).add(offset) as *mut PathCompressedNodeHeader;
                ocx.embedded_traversal_context
                    .as_mut()
                    .unwrap()
                    .root_container
                    .as_mut()
                    .wrap_shift_container(target as *mut c_void, required_size_for_path_compression as usize);
                (*target).set_size(required_size_for_path_compression as u8);
                let mut target_partial_key: *mut c_void = (target as *mut c_void).add(size_of::<PathCompressedNodeHeader>());

                if ocx.input_value.is_some() {
                    (*target).set_value_present(true);
                    copy(
                        ocx.input_value.as_mut().unwrap().as_mut() as *mut NodeValue as *mut u8,
                        target_partial_key as *mut u8,
                        size_of::<NodeValue>(),
                    );
                    target_partial_key = target_partial_key.add(size_of::<NodeValue>());
                }
                copy(ocx.key.as_mut().unwrap().get() as *mut u8, target_partial_key as *mut u8, (ocx.key_len_left - 2) as usize);
                (*node_head).as_sub_node_mut().set_child_container(PathCompressed);
            }

            let mut emb_ctx: EmbeddedTraversalContext = ocx.embedded_traversal_context.take().unwrap();
            emb_ctx.root_container.as_mut().update_space_usage(required_size_for_path_compression as i16, ocx, ctx);
            ocx.embedded_traversal_context = Some(emb_ctx);
            ocx.header.set_next_container_valid(ContainerValidTypes::Invalid);
            ocx.header.set_operation_done(true);
            ocx.header.set_performed_put(true);
        },
        CreateLinkToContainer => {
            if (ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut().free_bytes() as usize) < get_container_link_size() {
                node_head = ocx.meta_expand(ctx, get_container_link_size() as u32).as_raw_mut();
            }

            unsafe {
                let target: *mut c_void = (node_head as *mut c_void).add((*node_head).get_offset_child_container());
                ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut().wrap_shift_container(target, get_container_link_size());
                let new_link: *mut ContainerLink = target as *mut ContainerLink;
                (*new_link).ptr = initialize_container(ocx.arena.as_mut().unwrap());
                ocx.next_container_pointer = Some(Box::new((*new_link).ptr));
                (*node_head).as_sub_node_mut().set_child_container(Link);
            }
            ocx.header.set_next_container_valid(ContainerValid);
            let mut emb_ctx: EmbeddedTraversalContext = ocx.embedded_traversal_context.take().unwrap();
            emb_ctx.root_container.as_mut().update_space_usage(get_container_link_size() as i16, ocx, ctx);
            emb_ctx.embedded_container_depth = 0;
            ocx.embedded_traversal_context = Some(emb_ctx);
        },
    }
    node_head
}

pub fn get_child_container_pointer(
    mut node_head: *mut NodeHeader, childcon: &mut Option<NonNull<HyperionPointer>>, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext,
) -> ReturnCode {
    let node_ref: &mut NodeHeader = unsafe { node_head.as_mut().unwrap() };

    match node_ref.as_sub_node().child_container() {
        ChildLinkType::EmbeddedContainer | ChildLinkType::Link => {
            if node_ref.as_sub_node().child_container() == ChildLinkType::EmbeddedContainer {
                ocx.safe_sub_node_jump_table_context(ctx);
                let offset: usize = node_ref.get_offset_child_container();
                let mut emb_context: EmbeddedTraversalContext = ocx.embedded_traversal_context.take().unwrap();

                emb_context.next_embedded_container =
                    unsafe { Some(Box::from_raw((node_ref as *mut NodeHeader as *mut c_void).add(offset) as *mut EmbeddedContainer)) };

                assert!((emb_context.next_embedded_container.as_mut().unwrap().as_mut().size() as u32) < emb_context.root_container.as_mut().size());
                emb_context.embedded_stack[emb_context.embedded_container_depth as usize] =
                    AtomicEmbContainer::new_from_pointer(emb_context.next_embedded_container.as_mut().unwrap().as_mut() as *mut EmbeddedContainer);
                emb_context.embedded_container_depth += 1;

                let config = unsafe { GLOBAL_CONFIG.lock().unwrap() };
                if ocx.header.command() == Put
                    && (emb_context.next_embedded_container.as_mut().unwrap().as_mut().size() as u32
                        > config.header.container_embedding_high_watermark()
                        || emb_context.root_container.as_mut().size() >= config.container_embedding_limit
                        || (emb_context.next_embedded_container.as_mut().unwrap().as_mut().size() as u32
                            > config.header.container_embedding_high_watermark() / 2
                            && emb_context.root_container.as_mut().size() >= config.container_embedding_limit / 2))
                {
                    eject_container(unsafe { Box::from_raw(node_ref as *mut NodeHeader) }, ocx, ctx);
                    node_head = unsafe {
                        (emb_context.root_container.as_mut() as *mut Container as *mut c_void).add(ctx.current_container_offset as usize)
                            as *mut NodeHeader
                    };
                    ocx.embedded_traversal_context = Some(emb_context);
                } else {
                    ctx.current_container_offset += offset as i32;
                    ocx.header.set_next_container_valid(EmbeddedContainerValid);
                    ocx.embedded_traversal_context = Some(emb_context);
                    ocx.next_container_pointer = unsafe {
                        Some(Box::from_raw(ocx.embedded_traversal_context.as_mut().unwrap().next_embedded_container.as_mut().unwrap().as_mut()
                            as *mut EmbeddedContainer as *mut HyperionPointer))
                    };
                    return OK;
                }
            }

            unsafe {
                *childcon = NonNull::new((node_head as *mut c_void).add((*node_head).get_offset_child_container()) as *mut HyperionPointer);
            }
            ocx.embedded_traversal_context.as_mut().unwrap().embedded_container_depth = 0;
            ocx.header.set_next_container_valid(ContainerValid);
            ocx.embedded_traversal_context.as_mut().unwrap().next_embedded_container = None;
            OK
        },
        _ => ChildContainerMissing,
    }
}

pub fn create_node(
    mut node_head: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, container_depth: u8,
    set_key_after_creation: bool, add_value_after_creation: bool, key_delta: u8,
) -> *mut NodeHeader {
    let mut absolute_key: u8 = ctx.second_char;
    let input_memory_consumption: usize = if ocx.input_value.is_some() {
        add_value_after_creation as usize * size_of::<NodeValue>()
    } else {
        0
    };
    let required: usize = size_of::<NodeHeader>() + set_key_after_creation as usize + input_memory_consumption;

    if container_depth > 0 {
        ocx.jump_context.as_mut().unwrap().predecessor = None;
        ocx.jump_context.as_mut().unwrap().top_node_key = ctx.first_char as i32;
        absolute_key = ctx.first_char;
    }

    node_head = ocx.new_expand(ctx, required as u32).as_raw_mut();

    if ctx.header.force_shift_before_insert() {
        unsafe {
            ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut().wrap_shift_container(node_head as *mut c_void, required);
        }
    }

    let node_ref: &mut NodeHeader = unsafe { node_head.as_mut().unwrap() };

    node_ref.as_top_node_mut().set_type_flag(if add_value_after_creation && input_memory_consumption != 0 {
        LeafNodeWithValue
    } else {
        InnerNode
    });
    node_ref.as_top_node_mut().set_container_type(container_depth);
    let mut emb_ctx: EmbeddedTraversalContext = ocx.embedded_traversal_context.take().unwrap();
    emb_ctx.root_container.as_mut().update_space_usage((1 + input_memory_consumption + set_key_after_creation as usize) as i16, ocx, ctx);
    ocx.embedded_traversal_context = Some(emb_ctx);

    if set_key_after_creation {
        unsafe {
            (*(node_head as *mut Node)).set_nodes_key2(ocx, ctx, false, absolute_key);
        }
    } else {
        node_ref.as_top_node_mut().set_delta(key_delta);
        let mut successor_ptr: Option<NonNull<Node>> = None;
        let skipped_bytes: u32 = get_successor(node_ref, &mut successor_ptr, ocx, ctx);
        if skipped_bytes > 0 {
            let successor: &mut Node = unsafe { successor_ptr.as_mut().unwrap().as_mut() };
            let diff = if successor.header.as_top_node().delta() == 0 {
                successor.stored_value - key_delta
            } else {
                successor.header.as_top_node().delta() - key_delta
            };
            update_successor_key(successor as *mut Node, diff, absolute_key + diff, skipped_bytes, ocx, ctx);
        }
    }

    if add_value_after_creation {
        unsafe {
            (*node_head).set_node_value(ocx);
        }
    }

    if container_depth > 0 && !ctx.header.end_operation() {
        node_head = embed_or_link_child(node_head, ocx, ctx);
    }
    ocx.header.set_performed_put(true);
    node_head
}

pub fn get_child_container_nomod(
    mut node_head: *mut NodeHeader, childcon: &mut Option<NonNull<HyperionPointer>>, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext,
) -> ReturnCode {
    let node_ref: &mut NodeHeader = unsafe { node_head.as_mut().unwrap() };

    match node_ref.as_sub_node().child_container() {
        ChildLinkType::EmbeddedContainer => {
            ocx.safe_sub_node_jump_table_context(ctx);
            let offset: usize = node_ref.get_offset_child_container();
            let mut emb_context: EmbeddedTraversalContext = ocx.embedded_traversal_context.take().unwrap();

            emb_context.next_embedded_container =
                unsafe { Some(Box::from_raw((node_ref as *mut NodeHeader as *mut c_void).add(offset) as *mut EmbeddedContainer)) };

            emb_context.embedded_stack[emb_context.embedded_container_depth as usize] =
                AtomicEmbContainer::new_from_pointer(emb_context.next_embedded_container.as_mut().unwrap().as_mut() as *mut EmbeddedContainer);
            emb_context.embedded_container_depth += 1;
            ocx.embedded_traversal_context = Some(emb_context);
            ctx.current_container_offset += offset as i32;
            ocx.header.set_next_container_valid(EmbeddedContainerValid);
            ocx.next_container_pointer = unsafe {
                Some(Box::from_raw(ocx.embedded_traversal_context.as_mut().unwrap().next_embedded_container.as_mut().unwrap().as_mut()
                    as *mut EmbeddedContainer as *mut HyperionPointer))
            };
            OK
        },
        ChildLinkType::Link => {
            unsafe {
                *childcon = NonNull::new((node_head as *mut c_void).add((*node_head).get_offset_child_container()) as *mut HyperionPointer);
            }
            ocx.embedded_traversal_context.as_mut().unwrap().embedded_container_depth = 0;
            ocx.header.set_next_container_valid(ContainerValid);
            ocx.embedded_traversal_context.as_mut().unwrap().next_embedded_container = None;
            OK
        },
        _ => ChildContainerMissing,
    }
}

pub fn get_successor_embedded(
    node_head: *mut NodeHeader, successor: &mut Option<NonNull<Node>>, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext,
) -> u32 {
    let mut successor_ptr: *mut Node;
    let mut skipped_bytes: u32 = 0;
    let node_ref: &NodeHeader = unsafe { node_head.as_ref().unwrap() };

    if node_ref.as_top_node().container_type() == 0 {
        successor_ptr = node_head as *mut Node;
        loop {
            let offset: usize = unsafe { (*successor_ptr).header.get_offset() };
            skipped_bytes += offset as u32;

            if ctx.current_container_offset as u32 + skipped_bytes
                >= ocx.embedded_traversal_context.as_mut().unwrap().next_embedded_container.as_mut().unwrap().as_mut().size() as u32
            {
                return 0;
            }
            successor_ptr = unsafe { (successor_ptr as *mut c_void).add(offset) as *mut Node };

            if unsafe { (*successor_ptr).header.as_top_node().type_flag() == Invalid } {
                return 0;
            }

            if unsafe { (*successor_ptr).header.as_top_node().container_type() == 0 } {
                break;
            }
        }
    } else {
        skipped_bytes = unsafe { (*node_head).get_offset_sub_node() as u32 };
        successor_ptr = unsafe { (node_head as *mut c_void).add(skipped_bytes as usize) as *mut Node };

        if ctx.current_container_offset as u32 + skipped_bytes
            >= ocx.embedded_traversal_context.as_mut().unwrap().next_embedded_container.as_mut().unwrap().as_mut().size() as u32
        {
            return 0;
        }

        if unsafe { (*successor_ptr).header.as_top_node().type_flag() == Invalid } {
            return 0;
        }
    }

    if skipped_bytes > 0 {
        *successor = NonNull::new(successor_ptr);
    }
    skipped_bytes
}

pub fn get_successor(
    node_head: *mut NodeHeader, successor: &mut Option<NonNull<Node>>, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext,
) -> u32 {
    let mut successor_ptr: *mut Node;
    let mut skipped_bytes: u32 = 0;
    let node_ref: &NodeHeader = unsafe { node_head.as_ref().unwrap() };

    if node_ref.as_top_node().container_type() == 0 {
        if node_ref.as_top_node().jump_successor_present() {
            skipped_bytes = node_ref.get_jump_value() as u32;
            successor_ptr = unsafe { (node_head as *mut c_void).add(skipped_bytes as usize) as *mut Node };
        } else {
            successor_ptr = node_head as *mut Node;
            loop {
                let offset: usize = unsafe { (*successor_ptr).header.get_offset() };
                skipped_bytes += offset as u32;

                if ctx.current_container_offset as u32 + skipped_bytes
                    >= ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut().size()
                {
                    return 0;
                }
                successor_ptr = unsafe { (successor_ptr as *mut c_void).add(offset) as *mut Node };

                if unsafe { (*successor_ptr).header.as_top_node().type_flag() == Invalid } {
                    return 0;
                }

                if unsafe { (*successor_ptr).header.as_top_node().container_type() == 1 } {
                    continue;
                }
                break;
            }
        }
    } else {
        skipped_bytes = unsafe { (*node_head).get_offset_sub_node() as u32 };
        successor_ptr = unsafe { (node_head as *mut c_void).add(skipped_bytes as usize) as *mut Node };

        if ctx.current_container_offset as u32 + skipped_bytes >= ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut().size()
            || unsafe { (*successor_ptr).header.as_top_node().container_type() == 0 }
        {
            return 0;
        }
    }

    if skipped_bytes > 0 {
        *successor = NonNull::new(successor_ptr);
    }
    skipped_bytes
}

pub fn create_sublevel_jumptable(mut node_head: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) {
    const JUMPTABLE_KEYS: [u8; 15] = [16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240];

    assert!(unsafe { !(*node_head).as_top_node().jump_table_present() });
    let required_max = size_of::<TopNodeJumpTable>() + SUBLEVEL_JUMPTABLE_ENTRIES * (size_of::<NodeHeader>() + 1);
    let mut free_size_left = ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut().free_bytes() as usize;

    unsafe {
        let mut offset: usize = (node_head as *mut c_void)
            .offset_from(ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut() as *mut Container as *mut c_void)
            as usize;
        let offset_to_jumptable0: usize = offset + (*node_head).get_offset_jump_table() as usize;
        let mut bytes_to_move: i32 = ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut().size() as i32
            - (offset_to_jumptable0 as i32 + free_size_left as i32);

        if free_size_left <= required_max {
            ocx.new_expand(ctx, required_max as u32);
        }

        let mut target = (ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut() as *mut Container as *mut c_void)
            .add(offset_to_jumptable0) as *mut u16;
        shift_container(target as *mut c_void, size_of::<TopNodeJumpTable>(), bytes_to_move as usize);
        let mut emb_ctx = ocx.embedded_traversal_context.take().unwrap();
        emb_ctx.root_container.as_mut().update_space_usage(size_of::<TopNodeJumpTable>() as i16, ocx, ctx);
        ocx.embedded_traversal_context = Some(emb_ctx);
        node_head = (ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut() as *mut Container as *mut c_void).add(offset)
            as *mut NodeHeader;
        assert!(!(*node_head).as_top_node().jump_table_present());
        let mut tmp_ctx = ContainerTraversalContext {
            header: ContainerTraversalHeader::default(),
            last_top_char_seen: 0,
            last_sub_char_seen: 0,
            current_container_offset: 0,
            safe_offset: 0,
            first_char: 0,
            second_char: 0,
        };

        tmp_ctx.header.set_in_first_char_scope(true);
        tmp_ctx.current_container_offset = offset as i32;

        let jump_start = (*node_head).get_offset() + size_of::<TopNodeJumpTable>();
        offset = 0;

        let mut expect = 0;
        let base_offset = tmp_ctx.current_container_offset + jump_start as i32;
        let mut scan_node = node_head.add((*node_head).get_offset());
        tmp_ctx.header.set_last_sub_char_set(false);
        tmp_ctx.last_sub_char_seen = 0;

        loop {
            tmp_ctx.current_container_offset = base_offset + offset as i32;
            scan_node = (ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut() as *mut Container as *mut c_void)
                .add(tmp_ctx.current_container_offset as usize) as *mut NodeHeader;

            if (*scan_node).as_top_node().container_type() == 0 {
                let mut key = (*(scan_node as *mut Node)).get_sub_node_key(&mut tmp_ctx, false);

                if key == JUMPTABLE_KEYS[expect] {
                    *target = offset as u16;
                    expect += 1;
                    target = target.add(1);
                    if expect == SUBLEVEL_JUMPTABLE_ENTRIES {
                        break;
                    }
                } else if key > JUMPTABLE_KEYS[expect] {
                    inject_sublevel_reference_key(scan_node, ocx, &mut tmp_ctx, JUMPTABLE_KEYS[expect]);
                    *target = offset as u16;
                    key = JUMPTABLE_KEYS[expect];
                    expect += 1;
                    target = target.add(1);
                    if expect == SUBLEVEL_JUMPTABLE_ENTRIES {
                        break;
                    }
                }
                tmp_ctx.last_sub_char_seen = key;
                tmp_ctx.header.set_last_sub_char_set(true);
                offset += (*scan_node).get_offset();
            } else {
                free_size_left = ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut().free_bytes() as usize;
                let offset_tmp = (scan_node as *mut c_void)
                    .offset_from(ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut() as *mut Container as *mut c_void)
                    as i32;
                bytes_to_move =
                    ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut().size() as i32 - (offset_tmp + free_size_left as i32);

                if bytes_to_move < 0 {
                    bytes_to_move = 0;
                }

                let numer_of_missing = SUBLEVEL_JUMPTABLE_ENTRIES - expect;
                assert!(tmp_ctx.header.last_top_char_set());
                assert!(JUMPTABLE_KEYS[expect] > tmp_ctx.last_sub_char_seen);
                let diff = JUMPTABLE_KEYS[expect] - tmp_ctx.last_sub_char_seen;
                let first_insert_is_relative = if diff <= KEY_DELTA_STATES as u8 { true } else { false };
                let shift_by = ((size_of::<NodeHeader>() + 1) * numer_of_missing) - first_insert_is_relative as usize;

                shift_container(scan_node as *mut c_void, shift_by, bytes_to_move as usize);
                let mut emb_ctx = ocx.embedded_traversal_context.take().unwrap();
                emb_ctx.root_container.as_mut().update_space_usage(shift_by as i16, ocx, &mut tmp_ctx);
                ocx.embedded_traversal_context = Some(emb_ctx);

                (*scan_node).as_sub_node_mut().set_type_flag(InnerNode);
                (*scan_node).as_sub_node_mut().set_container_type(1);

                if !first_insert_is_relative {
                    *((scan_node as *mut u8).add(1)) = diff;
                    tmp_ctx.last_sub_char_seen = JUMPTABLE_KEYS[expect];
                } else {
                    (*scan_node).as_sub_node_mut().set_delta(diff);
                }

                *target = offset as u16;
                target = target.add(1);
                offset += (*scan_node).get_offset();
                expect += 1;

                while expect < SUBLEVEL_JUMPTABLE_ENTRIES {
                    scan_node = (ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut() as *mut Container as *mut c_void)
                        .add(base_offset as usize + offset) as *mut NodeHeader;
                    (*scan_node).as_sub_node_mut().set_type_flag(InnerNode);
                    (*scan_node).as_sub_node_mut().set_container_type(1);
                    (*scan_node).as_sub_node_mut().set_delta(0);
                    let target_key = (scan_node as *mut u8).add(size_of::<NodeHeader>());
                    *target_key = JUMPTABLE_KEYS[expect] - tmp_ctx.last_sub_char_seen;
                    tmp_ctx.last_sub_char_seen = JUMPTABLE_KEYS[expect];
                    expect += 1;
                    *target = offset as u16;
                    target = target.add(1);
                    offset += (*scan_node).get_offset();
                }
                break;
            }
        }
        (*node_head).as_top_node_mut().set_jump_table_present(true);
    }
}

pub fn transform_pc_node(node_head: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) {
    todo!()
}

pub fn inject_sublevel_reference_key(node_head: *mut NodeHeader, ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, refkey: u8) {
    let mut relative = 0;
    let diff = refkey - ctx.last_sub_char_seen;

    let target = if diff >= KEY_DELTA_STATES as u8 {
        relative = -1;
        unsafe { (node_head as *mut c_void).add(size_of::<NodeHeader>()) }
    } else {
        unsafe { (node_head as *mut c_void).add(size_of::<NodeHeader>() + 1) }
    };

    unsafe {
        let node_offset: i32 = (node_head as *mut c_void)
            .offset_from(ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut() as *mut Container as *mut c_void)
            as i32;
        let free_size_left: i32 = ocx.embedded_traversal_context.as_mut().unwrap().root_container.free_bytes() as i32;
        let bytes_to_move: i32 =
            ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut().size() as i32 - (node_offset + free_size_left);
        copy(node_head as *mut u8, target as *mut u8, bytes_to_move as usize);
        write_bytes(node_head as *mut u8, 0, size_of::<NodeHeader>() + 1 - relative as usize);
        (*node_head).as_top_node_mut().set_type_flag(InnerNode);
        (*node_head).as_top_node_mut().set_container_type(1);
    }

    let mut emb_ctx: EmbeddedTraversalContext = ocx.embedded_traversal_context.take().unwrap();
    emb_ctx.root_container.as_mut().update_space_usage(size_of::<NodeHeader>() as i16 + 1 - relative as i16, ocx, ctx);
    ocx.embedded_traversal_context = Some(emb_ctx);
    ctx.second_char = refkey;

    if relative == 0 {
        unsafe {
            (*(node_head as *mut Node)).set_nodes_key2(ocx, ctx, false, refkey);
        }
    } else {
        unsafe {
            (*node_head).as_top_node_mut().set_delta(diff);
        }
        let mut successor: Option<NonNull<Node>> = None;
        let skipped: u32 = get_successor(node_head, &mut successor, ocx, ctx);

        if skipped > 0 {
            assert_eq!(unsafe { successor.as_mut().unwrap().as_mut().header.as_top_node().container_type() }, 1);
            let succ_delta: u8;
            unsafe {
                let successor_ptr: *mut Node = successor.unwrap().as_ptr();
                succ_delta = if (*successor_ptr).header.as_top_node().delta() == 0 {
                    (*successor_ptr).stored_value
                } else {
                    (*successor_ptr).header.as_top_node().delta()
                };
                update_successor_key(successor_ptr, succ_delta - diff, refkey, skipped, ocx, ctx);
            }
        }
    }
}

#[bitfield(u8, order = Msb)]
pub struct PathCompressedNodeHeader {
    #[bits(7)]
    pub size: u8,

    #[bits(1)]
    pub value_present: bool,
}

impl PathCompressedNodeHeader {
    pub fn as_raw(&self) -> *const PathCompressedNodeHeader {
        self as *const PathCompressedNodeHeader
    }

    pub fn as_raw_char(&self) -> *const char {
        self.as_raw() as *const char
    }
}
