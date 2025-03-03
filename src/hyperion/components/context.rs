use crate::hyperion::components::container::{Container, EmbeddedContainer, CONTAINER_MAX_EMBEDDED_DEPTH};
use crate::hyperion::components::context::TraversalType::{
    EmptyOneCharTopNode, EmptyTwoCharTopNode, EmptyTwoCharTopNodeInFirstCharScope, FilledOneCharSubNode, FilledOneCharTopNode, FilledTwoCharSubNode,
    FilledTwoCharSubNodeInFirstCharScope, FilledTwoCharTopNode, FilledTwoCharTopNodeInFirstCharScope, InvalidTraversal,
};
use crate::hyperion::components::node::NodeValue;
use crate::hyperion::components::node_header::{
    NodeHeader, PathCompressedNodeHeader,
};
use crate::hyperion::internals::atomic_pointer::{AtomicChar, AtomicEmbContainer, Atomicu8};
use crate::memorymanager::api::{Arena, HyperionPointer};
use bitfield_struct::bitfield;
pub const KEY_DELTA_STATES: usize = 7;
pub const SUBLEVEL_JUMPTABLE_HWM: usize = 16;
pub const TOPLEVEL_JUMPTABLE_HWM: usize = 9;
pub const TOPLEVEL_JUMPTABLE_INCREMENTS: usize = 7;
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

#[repr(C, packed)]
pub struct TraversalContext {
    pub offset: i32,
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

#[bitfield(u8, order = Msb)]
pub struct ContainerTraversalHeader {
    #[bits(1)]
    pub node_type: u8,
    #[bits(1)]
    pub two_chars: bool,
    #[bits(1)]
    pub in_first_char_scope: bool,
    #[bits(1)]
    pub container_type: u8,
    #[bits(1)]
    pub last_top_char_set: bool,
    #[bits(1)]
    pub last_sub_char_set: bool,
    #[bits(1)]
    pub end_operation: bool,
    #[bits(1)]
    pub force_shift_before_insert: bool,
}

pub struct ContainerTraversalContext {
    pub header: ContainerTraversalHeader,
    pub last_top_char_seen: u8,
    pub last_sub_char_seen: u8,
    pub current_container_offset: i32,
    pub safe_offset: i32,
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
        let bit_pattern = (self.header.container_type(), self.header.in_first_char_scope(), self.header.two_chars(), self.header.node_type());
        match bit_pattern {
            (0, false, false, 0) => EmptyOneCharTopNode,
            (0, false, false, 1) => FilledOneCharTopNode,
            (0, false, true, 0) => EmptyTwoCharTopNode,
            (0, false, true, 1) => FilledTwoCharTopNode,
            (0, true, true, 0) => EmptyTwoCharTopNodeInFirstCharScope,
            (0, true, true, 1) => FilledTwoCharTopNodeInFirstCharScope,
            (1, false, false, 1) => FilledOneCharSubNode,
            (1, false, true, 1) => FilledTwoCharSubNode,
            (1, true, true, 1) => FilledTwoCharSubNodeInFirstCharScope,
            _ => InvalidTraversal,
        }
    }
}

pub struct PathCompressedEjectionContext {
    pub node_value: NodeValue,
    pub partial_key: [char; 127],
    pub pec_valid: bool,
    pub path_compressed_node_header: PathCompressedNodeHeader,
}

impl Default for PathCompressedEjectionContext {
    fn default() -> Self {
        Self {
            node_value: NodeValue { v: 0 },
            partial_key: [char::from(0); 127],
            pec_valid: false,
            path_compressed_node_header: PathCompressedNodeHeader::default(),
        }
    }
}

pub struct ContainerInjectionContext {
    pub root_container: Option<Box<Container>>,
    pub container_pointer: Option<Box<HyperionPointer>>,
}

pub struct EmbeddedTraversalContext {
    pub root_container: Box<Container>,
    pub next_embedded_container: Option<Box<EmbeddedContainer>>,
    pub embedded_stack: Option<[Option<AtomicEmbContainer>; CONTAINER_MAX_EMBEDDED_DEPTH]>,
    pub next_embedded_container_offset: i32,
    pub embedded_container_depth: i32,
    pub root_container_pointer: Box<HyperionPointer>,
}

impl EmbeddedTraversalContext {
    pub fn root_container(&mut self) -> &mut Container {
        self.root_container.as_mut()
    }
}

pub struct JumpTableSubContext {
    pub top_node: Option<Box<NodeHeader>>,
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

pub struct JumpContext {
    pub predecessor: Option<Box<NodeHeader>>,
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
            predecessor: self.predecessor.as_mut().map(|node| Box::new(node.deep_copy())),
            top_node_predecessor_offset_absolute: self.top_node_predecessor_offset_absolute,
            sub_nodes_seen: self.sub_nodes_seen,
            top_node_key: self.top_node_key,
        }
    }
}

pub struct RangeQueryContext {
    pub key_begin: AtomicChar,
    pub current_key: Atomicu8,
    pub arena: Box<Arena>,
    pub current_stack_depth: u16,
    pub current_key_offset: u16,
    pub key_len: u16,
    pub do_report: u8,
    pub stack: [Option<TraversalContext>; 128],
}

