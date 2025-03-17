use crate::hyperion::components::container::{Container, EmbeddedContainer, CONTAINER_MAX_EMBEDDED_DEPTH};
use crate::hyperion::components::context::TraversalType::{
    EmptyOneCharTopNode, EmptyTwoCharTopNode, EmptyTwoCharTopNodeInFirstCharScope, FilledOneCharSubNode, FilledOneCharTopNode, FilledTwoCharSubNode,
    FilledTwoCharSubNodeInFirstCharScope, FilledTwoCharTopNode, FilledTwoCharTopNodeInFirstCharScope, InvalidTraversal,
};
use crate::hyperion::components::node::{NodeState, NodeValue};
use crate::hyperion::components::node_header::NodeHeader;
use crate::hyperion::components::path_compressed_header::PathCompressedNodeHeader;
use crate::hyperion::internals::atomic_pointer::AtomicEmbContainer;
use crate::hyperion::internals::errors::ERR_NO_CAST_MUT_REF;
use crate::memorymanager::api::{Arena, HyperionPointer};
use bitfield_struct::bitfield;
use std::ptr::null_mut;

pub const DELTA_MAX_VALUE: u8 = 7;
pub const TOP_NODE_JUMP_TABLE_HWM: usize = 16;
pub const TOPLEVEL_JUMPTABLE_HWM: usize = 9;
pub const MAX_CONTAINER_JUMP_TABLES: usize = 7;
pub const TOPLEVEL_AGGRESSIVE_GROWTH__HWM: usize = 5;

#[derive(Debug, PartialEq)]
pub enum OperationCommand {
    Put = 0,
    Get = 1,
    Range = 2,
    Delete = 3,
}

impl OperationCommand {
    /// Transforms its states into a 2 bit representation.
    pub(crate) const fn into_bits(self) -> u8 {
        self as _
    }

    /// Transforms its states from an 8 bit value into a named state.
    ///
    /// # Panics
    /// Panics if an invalid operation type was found.
    pub(crate) const fn from_bits(value: u8) -> Self {
        match value {
            0 => OperationCommand::Put,
            1 => OperationCommand::Get,
            2 => OperationCommand::Range,
            3 => OperationCommand::Delete,
            _ => panic!("Use of undefined operation type"),
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct TraversalContext {
    pub offset: usize,
    pub hyperion_pointer: HyperionPointer,
}

#[derive(Debug, PartialEq)]
pub enum TraversalType {
    EmptyOneCharTopNode,                  // 0
    FilledOneCharTopNode,                 // 1
    EmptyTwoCharTopNode,                  // 2
    FilledTwoCharTopNode,                 // 3
    EmptyTwoCharTopNodeInFirstCharScope,  // 6
    FilledTwoCharTopNodeInFirstCharScope, // 7
    FilledOneCharSubNode,                 // 9
    FilledTwoCharSubNode,                 // 11
    FilledTwoCharSubNodeInFirstCharScope, // 15
    InvalidTraversal,
}

#[bitfield(u8)]
pub struct ContainerTraversalHeader {
    #[bits(1)]
    pub node_type: u8,
    #[bits(1)]
    pub two_chars: bool,
    #[bits(1)]
    pub in_first_char_scope: bool,
    #[bits(1)]
    pub container_type: NodeState,
    #[bits(1)]
    pub last_top_char_set: bool,
    #[bits(1)]
    pub last_sub_char_set: bool,
    #[bits(1)]
    pub end_operation: bool,
    #[bits(1)]
    pub force_shift_before_insert: bool,
}

#[derive(Default)]
#[repr(C)]
pub struct ContainerTraversalContext {
    pub header: ContainerTraversalHeader,
    pub last_top_char_seen: u8,
    pub last_sub_char_seen: u8,
    pub current_container_offset: usize,
    pub max_offset: usize,
    pub first_char: u8,
    pub second_char: u8,
}

impl ContainerTraversalContext {
    pub fn flush(&mut self) {
        self.last_top_char_seen = 0;
        self.last_sub_char_seen = 0;
        self.current_container_offset = 0;
        self.header.set_in_first_char_scope(true);
    }

    pub fn as_combined_header(&mut self) -> TraversalType {
        let bit_pattern: (NodeState, bool, bool, u8) =
            (self.header.container_type(), self.header.in_first_char_scope(), self.header.two_chars(), self.header.node_type());
        match bit_pattern {
            (NodeState::TopNode, false, false, 0) => EmptyOneCharTopNode,
            (NodeState::TopNode, false, false, 1) => FilledOneCharTopNode,
            (NodeState::TopNode, false, true, 0) => EmptyTwoCharTopNode,
            (NodeState::TopNode, false, true, 1) => FilledTwoCharTopNode,
            (NodeState::TopNode, true, true, 0) => EmptyTwoCharTopNodeInFirstCharScope,
            (NodeState::TopNode, true, true, 1) => FilledTwoCharTopNodeInFirstCharScope,
            (NodeState::SubNode, false, false, 1) => FilledOneCharSubNode,
            (NodeState::SubNode, false, true, 1) => FilledTwoCharSubNode,
            (NodeState::SubNode, true, true, 1) => FilledTwoCharSubNodeInFirstCharScope,
            _ => InvalidTraversal,
        }
    }

    pub fn key_delta_top(&mut self) -> u8 {
        self.header.last_top_char_set().then(|| self.first_char - self.last_top_char_seen).filter(|&delta| delta <= DELTA_MAX_VALUE).unwrap_or(0)
    }

    pub fn key_delta_sub(&mut self) -> u8 {
        self.header.last_sub_char_set().then(|| self.second_char - self.last_sub_char_seen).filter(|&delta| delta <= DELTA_MAX_VALUE).unwrap_or(0)
    }
}

#[repr(C)]
pub struct PathCompressedEjectionContext {
    pub node_value: NodeValue,
    pub partial_key: [u8; 127],
    pub pec_valid: bool,
    pub path_compressed_node_header: PathCompressedNodeHeader,
}

impl Default for PathCompressedEjectionContext {
    fn default() -> Self {
        Self {
            node_value: NodeValue { value: 0 },
            partial_key: [0; 127],
            pec_valid: false,
            path_compressed_node_header: PathCompressedNodeHeader::default(),
        }
    }
}

#[derive(Default)]
#[repr(C)]
pub struct ContainerInjectionContext {
    pub root_container: Option<*mut Container>,
    pub container_pointer: Option<*mut HyperionPointer>,
}

#[repr(C)]
pub struct EmbeddedTraversalContext {
    pub root_container: *mut Container,
    pub next_embedded_container: Option<*mut EmbeddedContainer>,
    pub embedded_stack: Option<[Option<AtomicEmbContainer>; CONTAINER_MAX_EMBEDDED_DEPTH]>,
    pub next_embedded_container_offset: i32,
    pub embedded_container_depth: i32,
    pub root_container_pointer: *mut HyperionPointer,
}

impl Default for EmbeddedTraversalContext {
    fn default() -> Self {
        EmbeddedTraversalContext {
            root_container: null_mut(),
            next_embedded_container: None,
            embedded_stack: None,
            next_embedded_container_offset: 0,
            embedded_container_depth: 0,
            root_container_pointer: null_mut(),
        }
    }
}

impl EmbeddedTraversalContext {
    pub fn root_container(&mut self) -> &mut Container {
        unsafe { self.root_container.as_mut().expect(ERR_NO_CAST_MUT_REF) }
    }
}

#[derive(Default)]
#[repr(C)]
pub struct JumpTableSubContext {
    pub top_node: Option<*mut NodeHeader>,
    pub root_container_sub_char_set: bool,
    pub root_container_sub_char: u8,
}

impl JumpTableSubContext {
    pub fn flush(&mut self) {
        self.top_node = None;
        self.root_container_sub_char = 0;
        self.root_container_sub_char_set = false;
    }
}

#[derive(Default)]
#[repr(C)]
pub struct JumpContext {
    pub predecessor: Option<*mut NodeHeader>,
    pub top_node_predecessor_offset_absolute: i32,
    pub sub_nodes_seen: i32,
    pub top_node_key: i32,
}

impl JumpContext {
    pub fn flush(&mut self) {
        self.predecessor = None;
        self.top_node_predecessor_offset_absolute = 0;
        self.sub_nodes_seen = 0;
        self.top_node_key = 0;
    }

    pub fn duplicate(&mut self) -> JumpContext {
        JumpContext {
            predecessor: self.predecessor.as_mut().map(|predecessor: &mut *mut NodeHeader| *predecessor),
            top_node_predecessor_offset_absolute: self.top_node_predecessor_offset_absolute,
            sub_nodes_seen: self.sub_nodes_seen,
            top_node_key: self.top_node_key,
        }
    }
}

#[repr(C)]
pub struct RangeQueryContext {
    pub key_begin: *mut u8,
    pub current_key: *mut u8,
    pub arena: *mut Arena,
    pub current_stack_depth: u16,
    pub current_key_offset: u16,
    pub key_len: u16,
    pub do_report: u8,
    pub traversed_leaves: i32,
    pub stack: [Option<TraversalContext>; 128],
}
