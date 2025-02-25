use std::ffi::c_void;
use std::ptr::copy;
use bitfield_struct::bitfield;
use libc::{memcmp, size_t};

use crate::hyperion::components::container::{ContainerLink, EmbeddedContainer};
use crate::hyperion::components::context::{ContainerTraversalContext, JumpContext, OperationCommand, OperationContext, PathCompressedEjectionContext, RangeQueryContext};
use crate::hyperion::components::jump_table::{TopNodeJumpTable, SUBLEVEL_JUMPTABLE_SHIFTBITS};
use crate::hyperion::components::node::NodeType::{InnerNode, Invalid, LeafNodeEmpty, LeafNodeWithValue};
use crate::hyperion::components::node::{NodeType, NodeValue};
use crate::hyperion::components::return_codes::ReturnCode;
use crate::hyperion::components::return_codes::ReturnCode::{GetFailureNoLeaf, OK};
use crate::hyperion::components::sub_node::{ChildLinkType, SubNode};
use crate::hyperion::components::top_node::TopNode;
use crate::hyperion::internals::atomic_pointer::{AtomicChar, AtomicHeader, AtomicNodeValue, AtomicPointer};
use crate::hyperion::internals::core::HyperionCallback;
use crate::hyperion::internals::helpers::{copy_memory_from, copy_memory_to};

#[repr(C)]
#[derive(Clone, Copy)]
union NodeUnion {
    pub top_node: TopNode,
    pub sub_node: SubNode
}

pub struct NodeHeader {
    header: NodeUnion
}

impl NodeHeader {
    pub fn new_top_node(top_node: TopNode) -> Self {
        NodeHeader {
            header: NodeUnion { top_node }
        }
    }

    pub fn new_sub_node(sub_node: SubNode) -> Self {
        NodeHeader {
            header: NodeUnion { sub_node }
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

    pub fn as_path_compressed(&self) -> &PathCompressedNodeHeader {
        unsafe { self.as_raw_compressed().as_ref().unwrap() }
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
        self.as_top_node().jump_successor() * size_of::<u16>() as u8 + self.as_top_node().jump_table() * size_of::<TopNodeJumpTable>() as u8
    }

    pub fn get_leaf_size(&self) -> usize {
        match self.as_top_node().type_flag() {
            LeafNodeWithValue => size_of::<NodeValue>(),
            _ => 0
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
            ChildLinkType::PathCompressed => unsafe { (*self.as_raw_compressed()).size() as usize }
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
        self.get_offset_jump() as u16 + self.as_top_node().jump_successor() as u16 * size_of::<u16>() as u16
    }

    fn get_node_value_pc(&self, operation_context: &mut OperationContext) -> ReturnCode {
        let pc_head: &PathCompressedNodeHeader = self.as_path_compressed();
        if pc_head.value_present() > 0 {
            unsafe {
                copy_memory_from(
                    pc_head.as_raw_char().add(size_of::<PathCompressedNodeHeader>()),
                    operation_context.get_return_value_mut() as *mut NodeValue,
                    size_of::<NodeValue>()
                )
            }
        }
        operation_context.header.set_operation_done(1);
        OK
    }

    pub fn get_node_value(&self, operation_context: &mut OperationContext) -> ReturnCode {
        if operation_context.header.pathcompressed_child() == 1 {
            return self.get_node_value_pc(operation_context);
        }

        let top_node_type: NodeType = self.as_top_node().type_flag();

        if top_node_type == InnerNode || top_node_type == Invalid {
            return GetFailureNoLeaf;
        }

        if top_node_type == LeafNodeWithValue {
            unsafe {
                copy_memory_from(
                    self.as_raw_char().add(self.get_offset_node_value()),
                    operation_context.get_return_value_mut() as *mut NodeValue,
                    size_of::<NodeValue>()
                );
            }
        }

        operation_context.header.set_operation_done(1);
        OK
    }

    pub fn set_node_value(&mut self, operation_context: &mut OperationContext) -> ReturnCode {
        let top_node: &mut TopNode = self.as_top_node_mut();

        if top_node.type_flag() == Invalid || top_node.type_flag() == InnerNode {
            operation_context.header.set_performed_put(1);
        }

        if operation_context.input_value.is_some() {
            let input_value: &mut NodeValue = operation_context.get_input_value_mut();
            unsafe {
                copy_memory_to(self.as_raw_char_mut().add(self.get_offset_node_value()), input_value as *const NodeValue, size_of::<NodeValue>());
            }
            self.as_top_node_mut().set_type_flag(LeafNodeWithValue);
        } else {
            self.as_top_node_mut().set_type_flag(LeafNodeEmpty);
        }
        operation_context.header.set_operation_done(1);
        OK
    }

    pub fn register_jump_context(&mut self, container_traversal_context: &mut ContainerTraversalContext, operation_context: &mut OperationContext) {
        let jump_context: &mut JumpContext = operation_context.get_jump_context_mut();
        if self.as_top_node().jump_successor() == 1 {
            jump_context.predecessor = Some(unsafe { Box::from_raw(self.as_raw_mut()) });//AtomicHeader::new_from_pointer(self.as_raw_mut());
            jump_context.sub_nodes_seen = 0;
            jump_context.top_node_predecessor_offset_absolute = container_traversal_context.current_container_offset;
        } else {
            jump_context.predecessor = None;
        }
    }

    pub fn call_top_node(&mut self, range_query_context: &mut RangeQueryContext, hyperion_callback: HyperionCallback<NodeValue>) -> bool {
        match self.as_top_node().type_flag() {
            LeafNodeEmpty => {
                hyperion_callback(&mut range_query_context.current_key, range_query_context.current_key_offset + 1, &mut AtomicNodeValue::new())
            },
            LeafNodeWithValue => unsafe {
                hyperion_callback(
                    &mut range_query_context.current_key,
                    range_query_context.current_key_offset + 1,
                    &mut AtomicNodeValue::new_from_pointer(self.as_raw_mut().add(self.get_offset_node_value()) as *mut NodeValue)
                )
            },
            Invalid | InnerNode => true
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
                    &mut AtomicNodeValue::new_from_pointer(self.as_raw_mut().add(self.get_offset_node_value()) as *mut NodeValue)
                )
            },
            Invalid | InnerNode => true
        }
    }

    pub fn compare_path_compressed_node(&self, operation_context: &mut OperationContext) -> bool {
        let pc_header: &PathCompressedNodeHeader = unsafe { self.as_raw_compressed().as_ref().unwrap() };

        let overhead: usize = size_of::<PathCompressedNodeHeader>() + pc_header.value_present() as usize * size_of::<NodeValue>();
        let key_len: u8 = pc_header.size() - overhead as u8;

        if operation_context.key_len_left - 2 != key_len as i32 {
            return false;
        }

        let op_key: &mut AtomicChar = operation_context.get_key_as_mut();
        unsafe {
            let key: *const PathCompressedNodeHeader = (pc_header as *const PathCompressedNodeHeader).add(overhead);
            memcmp(op_key.add_get(2) as *mut c_void, key as *mut c_void, key_len as size_t) == 0
        }
    }

    pub fn use_sub_node_jump_table(&mut self, container_traversal_context: &mut ContainerTraversalContext) -> u8 {
        let jump_class = container_traversal_context.second_char >> SUBLEVEL_JUMPTABLE_SHIFTBITS;

        if jump_class > 0 {
            let jump_table_pointer: *mut u16 = unsafe { self.as_raw_mut().add(self.get_offset_jump_table() as usize) } as *mut u16;
            container_traversal_context.current_container_offset += self.get_offset() as i32 + unsafe { *jump_table_pointer + (jump_class as u16 - 1) } as i32;
            return jump_class << SUBLEVEL_JUMPTABLE_SHIFTBITS;
        }

        container_traversal_context.current_container_offset += self.get_offset() as i32;
        0
    }

    pub fn safe_path_compressed_context(&mut self, operation_context: &mut OperationContext) {
        let pc_node = self.as_path_compressed();
        operation_context.path_compressed_ejection_context = Some(PathCompressedEjectionContext::default());

        if pc_node.value_present() == 1 {
            unsafe {
                copy(
                    (pc_node as *const PathCompressedNodeHeader as *const c_void).add(size_of::<PathCompressedNodeHeader>()).add(size_of::<NodeValue>()) as *const u8,
                    operation_context.path_compressed_ejection_context.as_mut().unwrap().partial_key.as_mut_ptr() as *mut u8,
                    pc_node.size() as usize - (size_of::<PathCompressedNodeHeader>() + size_of::<NodeValue>())
                );
                copy(
                    (pc_node as *const PathCompressedNodeHeader as *const c_void).add(size_of::<PathCompressedNodeHeader>()).add(size_of::<NodeValue>()) as *const u8,
                    &mut operation_context.path_compressed_ejection_context.as_mut().unwrap().node_value as *mut NodeValue as *mut u8,
                    size_of::<NodeValue>()
                );
            }
        }
        else {
            unsafe {
                copy(
                    (pc_node as *const PathCompressedNodeHeader as *const c_void).add(size_of::<PathCompressedNodeHeader>()) as *const u8,
                    operation_context.path_compressed_ejection_context.as_mut().unwrap().partial_key.as_mut_ptr() as *mut u8,
                    pc_node.size() as usize - size_of::<PathCompressedNodeHeader>()
                );
            }
        }
        operation_context.path_compressed_ejection_context.as_mut().unwrap().pec_valid = 1;
        unsafe {
            copy(
                (pc_node as *const PathCompressedNodeHeader as *const c_void) as *const u8,
                &mut operation_context.path_compressed_ejection_context.as_mut().unwrap().path_compressed_node_header as *mut PathCompressedNodeHeader as *mut u8,
                size_of::<PathCompressedNodeHeader>()
            );
        }
    }


}

#[bitfield(u8, order = Msb)]
pub struct PathCompressedNodeHeader {
    #[bits(7)]
    pub size: u8,

    #[bits(1)]
    pub value_present: u8
}

impl PathCompressedNodeHeader {
    pub fn as_raw(&self) -> *const PathCompressedNodeHeader {
        self as *const PathCompressedNodeHeader
    }

    pub fn as_raw_char(&self) -> *const char {
        self.as_raw() as *const char
    }
}
