use std::ops::DerefMut;

use bitfield_struct::bitfield;

use crate::hyperion::components::container::{Container, EmbeddedContainer, RootContainerEntry, CONTAINER_MAX_EMBEDDED_DEPTH};
use crate::hyperion::components::node::NodeValue;
use crate::hyperion::components::node_header::PathCompressedNodeHeader;
use crate::hyperion::internals::atomic_pointer::{AtomicArena,
                                                 AtomicChar,
                                                 AtomicContainer,
                                                 AtomicEmbContainer,
                                                 AtomicHeader,
                                                 AtomicHyperionPointer,
                                                 AtomicNodeValue,
                                                 AtomicPCContext,
                                                 AtomicRootEntry,
                                                 Atomicu8};
use crate::memorymanager::api::{Arena, HyperionPointer};

#[derive(Debug)]
pub enum OperationCommand {
    Put = 0,
    Get = 1,
    Range = 2,
    Delete = 3
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
            _ => panic!("Use of undefined operation type")
        }
    }
}

#[repr(packed)]
pub struct TraversalContext {
    pub offset: i32,
    pub hyperion_pointer: HyperionPointer
}

#[bitfield(u8, order = Msb)]
pub struct ContainerTraversalHeader {
    #[bits(1)]
    pub node_type: u8,
    #[bits(1)]
    pub two_chars: u8,
    #[bits(1)]
    pub in_first_char_scope: u8,
    #[bits(1)]
    pub container_type: u8,
    #[bits(1)]
    pub last_top_char_set: u8,
    #[bits(1)]
    pub last_sub_char_set: u8,
    #[bits(1)]
    pub end_operation: u8,
    #[bits(1)]
    pub force_shift_before_insert: u8
}

pub struct ContainerTraversalContext {
    pub header: ContainerTraversalHeader,
    pub last_top_char_seen: u8,
    pub last_sub_char_seen: u8,
    pub current_container_offset: i32,
    pub safe_offset: i32,
    pub first_char: u8,
    pub second_char: u8
}

impl ContainerTraversalContext {
    pub fn flush(&mut self) {
        self.last_top_char_seen = 0;
        self.last_sub_char_seen = 0;
        self.current_container_offset = 0;
        self.header.set_in_first_char_scope(0);
    }
}

pub struct PathCompressedEjectionContext {
    pub node_value: NodeValue,
    pub partial_key: [char; 127],
    pub pec_valid: u8,
    pub path_compressed_node_header: PathCompressedNodeHeader
}

pub struct ContainerInjectionContext {
    pub root_container: AtomicContainer,
    pub container_pointer: AtomicHyperionPointer
}

pub struct EmbeddedTraversalContext<'a> {
    pub root_container: &'a mut Container,
    pub next_embedded_container: &'a mut EmbeddedContainer,
    pub embedded_stack: [AtomicEmbContainer; CONTAINER_MAX_EMBEDDED_DEPTH],
    pub next_embedded_container_offset: i32,
    pub embedded_container_depth: i32,
    pub root_container_pointer: &'a mut HyperionPointer
}

pub struct JumpTableSubContext {
    pub top_node: AtomicHeader,
    pub root_container_sub_char_set: u8,
    pub root_container_sub_char: char
}

impl JumpTableSubContext {
    pub fn flush(&mut self) {
        self.top_node.clear();
        self.root_container_sub_char = char::from(0);
        self.root_container_sub_char_set = 0;
    }
}

pub struct JumpContext {
    pub predecessor: AtomicHeader,
    pub top_node_predecessor_offset_absolute: i32,
    pub sub_nodes_seen: i32,
    pub top_node_key: i32
}

impl JumpContext {
    pub fn flush(&mut self) {
        self.predecessor.clear();
        self.top_node_predecessor_offset_absolute = 0;
        self.sub_nodes_seen = 0;
        self.top_node_key = 0;
    }
}

pub struct RangeQueryContext<'a> {
    pub key_begin: AtomicChar,
    pub current_key: Atomicu8,
    pub arena: &'a mut AtomicArena,
    pub current_stack_depth: u16,
    pub current_key_offset: u16,
    pub key_len: u16,
    pub do_report: u8,
    pub stack: [Option<TraversalContext>; 128]
}

#[bitfield(u8, order = Msb)]
pub struct OperationContextHeader {
    #[bits(2)]
    pub command: OperationCommand,
    #[bits(2)]
    pub next_container_valid: u8,
    #[bits(1)]
    pub operation_done: u8,
    #[bits(1)]
    pub performed_put: u8,
    #[bits(1)]
    pub pathcompressed_child: u8,
    #[bits(1)]
    __: u8
}

pub struct OperationContext<'a> {
    pub header: OperationContextHeader,
    pub chained_pointer_hook: u8,
    pub key_len_left: i32,
    pub key: Option<AtomicChar>,
    pub jump_context: Option<JumpContext>,
    pub root_container_entry: Option<&'a mut RootContainerEntry>,
    pub embedded_traversal_context: Option<EmbeddedTraversalContext<'a>>,
    pub jump_table_sub_context: Option<JumpTableSubContext>,
    pub next_container_pointer: Option<&'a mut HyperionPointer>,
    pub arena: Option<&'a mut Arena>,
    pub path_compressed_ejection_context: Option<PathCompressedEjectionContext>,
    pub return_value: Option<&'a mut NodeValue>,
    pub input_value: Option<&'a mut NodeValue>,
    pub container_injection_context: Option<ContainerInjectionContext>
}

impl<'a> OperationContext<'a> {
    pub fn flush_jump_context(&mut self) {
        if let Some(jump_context) = &mut self.jump_context {
            jump_context.flush();
        }
    }

    pub fn flush_jump_table_sub_context(&mut self) {
        if let Some(sub_context) = &mut self.jump_table_sub_context {
            sub_context.flush();
        }
    }

    pub fn get_return_value_mut(&mut self) -> &mut NodeValue {
        self.return_value.as_deref_mut().unwrap()
    }

    pub fn get_input_value_mut(&mut self) -> &mut NodeValue {
        self.input_value.as_deref_mut().unwrap()
    }

    pub fn get_jump_context_mut(&mut self) -> &mut JumpContext {
        self.jump_context.as_mut().unwrap()
    }

    pub fn get_key_as_mut(&mut self) -> &mut AtomicChar {
        self.key.as_mut().unwrap()
    }
}
