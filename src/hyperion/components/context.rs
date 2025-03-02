use std::cmp::Ordering;
use crate::hyperion::components::container::{shift_container, Container, EmbeddedContainer, RootContainerEntry, CONTAINER_MAX_EMBEDDED_DEPTH};
use crate::hyperion::components::context::JumpStates::{JumpPoint1, JumpPoint2, NoJump};
use crate::hyperion::components::context::TraversalType::{
    EmptyOneCharTopNode, EmptyTwoCharTopNode, EmptyTwoCharTopNodeInFirstCharScope, FilledOneCharSubNode, FilledOneCharTopNode, FilledTwoCharSubNode,
    FilledTwoCharSubNodeInFirstCharScope, FilledTwoCharTopNode, FilledTwoCharTopNodeInFirstCharScope, InvalidTraversal,
};
use crate::hyperion::components::jump_table::{SubNodeJumpTable, TopNodeJumpTable, TOPLEVEL_JUMPTABLE_ENTRIES, TOPLEVEL_NODE_JUMP_HWM};
use crate::hyperion::components::node::NodeType::{Invalid, LeafNodeWithValue};
use crate::hyperion::components::node::{get_top_node_key, Node, NodeValue};
use crate::hyperion::components::node_header::{
    as_sub_node, as_top_node, as_top_node_mut, compare_path_compressed_node, create_node, create_node_embedded, create_sublevel_jumptable,
    embed_or_link_child, get_child_container_pointer, get_jump_value, get_offset, get_offset_jump, get_offset_node_value, get_offset_sub_node,
    get_offset_top_node, get_successor, register_jump_context, safe_path_compressed_context, set_node_value, update_path_compressed_node,
    use_sub_node_jump_table, NodeHeader, PathCompressedNodeHeader,
};
use crate::hyperion::components::return_codes::ReturnCode;
use crate::hyperion::components::return_codes::ReturnCode::{UnknownOperation, OK};
use crate::hyperion::components::sub_node::ChildLinkType;
use crate::hyperion::components::sub_node::ChildLinkType::PathCompressed;
use crate::hyperion::components::top_node::TopNode;
use crate::hyperion::internals::atomic_pointer::{AtomicChar, AtomicEmbContainer, Atomicu8, CONTAINER_SIZE_TYPE_0};
use crate::hyperion::internals::core::GLOBAL_CONFIG;
use crate::memorymanager::api::{get_pointer, reallocate, Arena, HyperionPointer};
use bitfield_struct::bitfield;
use std::ffi::c_void;
use std::ops::DerefMut;
use std::ptr::{null_mut, write_bytes, NonNull};

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
    pub pec_valid: u8,
    pub path_compressed_node_header: PathCompressedNodeHeader,
}

impl Default for PathCompressedEjectionContext {
    fn default() -> Self {
        Self {
            node_value: NodeValue { v: 0 },
            partial_key: [char::from(0); 127],
            pec_valid: 0,
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
    pub root_container_sub_char_set: u8,
    pub root_container_sub_char: char,
}

impl JumpTableSubContext {
    pub fn flush(&mut self) {
        self.top_node = None;
        self.root_container_sub_char = char::from(0);
        self.root_container_sub_char_set = 0;
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

#[derive(Debug, PartialEq)]
pub enum ContainerValidTypes {
    Invalid = 0,
    ContainerValid = 1,
    EmbeddedContainerValid = 2,
}

impl ContainerValidTypes {
    /// Transforms its states into a 2 bit representation.
    pub(crate) const fn into_bits(self) -> u8 {
        self as _
    }

    /// Transforms its states from an 8 bit value into a named state.
    ///
    /// # Panics
    /// Panics if an invalid container valid type was found.
    pub(crate) const fn from_bits(value: u8) -> Self {
        match value {
            0 => ContainerValidTypes::Invalid,
            1 => ContainerValidTypes::ContainerValid,
            2 => ContainerValidTypes::EmbeddedContainerValid,
            _ => panic!("Use of undefined container valid type"),
        }
    }
}

#[derive(PartialEq)]
pub enum JumpStates {
    JumpPoint1,
    JumpPoint2,
    NoJump,
}

#[bitfield(u8, order = Msb)]
pub struct OperationContextHeader {
    #[bits(2)]
    pub command: OperationCommand,
    #[bits(2)]
    pub next_container_valid: ContainerValidTypes,
    #[bits(1)]
    pub operation_done: bool,
    #[bits(1)]
    pub performed_put: bool,
    #[bits(1)]
    pub pathcompressed_child: bool,
    #[bits(1)]
    __: u8,
}

pub struct OperationContext {
    pub header: OperationContextHeader,
    pub chained_pointer_hook: u8,
    pub key_len_left: i32,
    pub key: Option<AtomicChar>,
    pub jump_context: Option<JumpContext>,
    pub root_container_entry: Option<Box<RootContainerEntry>>,
    pub embedded_traversal_context: Option<EmbeddedTraversalContext>,
    pub jump_table_sub_context: Option<JumpTableSubContext>,
    pub next_container_pointer: Option<Box<HyperionPointer>>,
    pub arena: Option<Box<Arena>>,
    pub path_compressed_ejection_context: Option<PathCompressedEjectionContext>,
    pub return_value: Option<Box<NodeValue>>,
    pub input_value: Option<Box<NodeValue>>,
    pub container_injection_context: Option<ContainerInjectionContext>,
}

impl OperationContext {
    pub fn get_root_container(&mut self) -> &mut Container {
        self.embedded_traversal_context.as_mut().unwrap().root_container()
    }

    pub fn get_root_container_pointer(&mut self) -> *mut Container {
        self.get_root_container() as *mut Container
    }

    pub fn get_next_embedded_container(&mut self) -> &mut EmbeddedContainer {
        self.embedded_traversal_context.as_mut().unwrap().next_embedded_container.as_mut().unwrap().as_mut()
    }

    pub fn get_next_embedded_container_pointer(&mut self) -> *mut EmbeddedContainer {
        self.get_next_embedded_container() as *mut EmbeddedContainer
    }

    pub fn get_next_embedded_container_offset(&mut self) -> &mut i32 {
        &mut self.embedded_traversal_context.as_mut().unwrap().next_embedded_container_offset
    }

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

pub fn new_expand(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, required: u32) -> *mut NodeHeader {
    let mut embedded_traversal_context: EmbeddedTraversalContext = ocx.embedded_traversal_context.take().unwrap();
    let mut arena: Box<Arena> = ocx.arena.take().unwrap();
    let free_space_left: u32 = embedded_traversal_context.root_container.deref_mut().free_bytes() as u32;

    if free_space_left > required {
        let old_size: u32;
        let new_size: u32;
        let mut sublevel_ref_toplevel_node_offset = 0;
        {
            let root_container: &mut Container = embedded_traversal_context.root_container.deref_mut();

            if let Some(jump_context) = &mut ocx.jump_table_sub_context {
                if let Some(top_node) = jump_context.top_node.as_deref_mut() {
                    unsafe {
                        sublevel_ref_toplevel_node_offset =
                            (top_node as *mut NodeHeader as *mut c_void).offset_from(root_container as *mut Container as *mut c_void) as i32;
                    }
                }
            }
            old_size = root_container.size();
            new_size = root_container.increment_container_size((required - free_space_left) as i32);
            assert_eq!(embedded_traversal_context.embedded_container_depth, 0);
            embedded_traversal_context.root_container_pointer = Box::new(reallocate(
                arena.as_mut(),
                embedded_traversal_context.root_container_pointer.as_mut(),
                new_size as usize,
                ocx.chained_pointer_hook,
            ));
        }

        unsafe {
            embedded_traversal_context.root_container =
                Box::from_raw(get_pointer(arena.as_mut(), &mut embedded_traversal_context.root_container_pointer, 1, ocx.chained_pointer_hook)
                    as *mut Container);
        }

        ocx.arena = Some(arena);

        embedded_traversal_context.root_container.set_free_size_left(new_size - old_size + free_space_left);

        let mut jump_context: JumpContext = ocx.jump_context.take().unwrap();
        let raw_container_pointer: *mut Container = embedded_traversal_context.root_container.as_mut() as *mut Container;

        if jump_context.predecessor.is_some() {
            unsafe {
                jump_context.predecessor =
                    Some(Box::from_raw(raw_container_pointer.add(jump_context.top_node_predecessor_offset_absolute as usize) as *mut NodeHeader));
            }
        }
        ocx.jump_context = Some(jump_context);

        if sublevel_ref_toplevel_node_offset > 0 {
            unsafe {
                ocx.jump_table_sub_context.as_mut().unwrap().top_node =
                    Some(Box::from_raw(raw_container_pointer.add(sublevel_ref_toplevel_node_offset as usize) as *mut NodeHeader));
            }
        }
    }

    let raw_container_pointer: *mut Container = embedded_traversal_context.root_container.as_mut() as *mut Container;
    ocx.embedded_traversal_context = Some(embedded_traversal_context);

    unsafe { raw_container_pointer.add(ctx.current_container_offset as usize) as *mut NodeHeader }
}

pub fn safe_sub_node_jump_table_context(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) {
    let mut sub_jump_table: JumpTableSubContext = ocx.jump_table_sub_context.take().unwrap();

    if let Some(node) = sub_jump_table.top_node.as_mut() {
        if as_top_node(node.as_mut() as *mut NodeHeader).jump_table_present()
            && ocx.embedded_traversal_context.as_mut().unwrap().embedded_container_depth == 0
        {
            sub_jump_table.root_container_sub_char_set = 1;
            sub_jump_table.root_container_sub_char = char::from(ctx.second_char);
        }
    }
    ocx.jump_table_sub_context = Some(sub_jump_table);
}

pub fn new_expand_embedded(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, required: u32) -> *mut NodeHeader {
    let mut embedded_traversal_context: EmbeddedTraversalContext = ocx.embedded_traversal_context.take().unwrap();
    let mut arena: Box<Arena> = ocx.arena.take().unwrap();
    let free_space_left: u32 = embedded_traversal_context.root_container.deref_mut().free_bytes() as u32;

    if free_space_left > required {
        let i: usize = 0;
        let old_size: u32;
        let new_size: u32;
        let mut sublevel_ref_toplevel_node_offset = 0;
        let mut embedded_stack: [i32; CONTAINER_MAX_EMBEDDED_DEPTH] = [0; CONTAINER_MAX_EMBEDDED_DEPTH];
        {
            let root_container: &mut Container = embedded_traversal_context.root_container.deref_mut();

            if let Some(jump_context) = &mut ocx.jump_table_sub_context {
                if let Some(top_node) = jump_context.top_node.as_deref_mut() {
                    unsafe {
                        sublevel_ref_toplevel_node_offset =
                            (top_node as *mut NodeHeader as *mut c_void).offset_from(root_container as *mut Container as *mut c_void) as i32;
                    }
                }
            }

            unsafe {
                for i in (i..embedded_traversal_context.next_embedded_container_offset as usize).rev() {
                    embedded_stack[i] = embedded_traversal_context.embedded_stack.as_mut().unwrap()[i]
                        .as_mut()
                        .unwrap()
                        .get_as_mut_memory()
                        .offset_from(root_container as *mut Container as *mut c_void) as i32;
                }
            }
            old_size = root_container.size();
            new_size = root_container.increment_container_size((required - free_space_left) as i32);
            root_container.set_free_size_left(0);
            embedded_traversal_context.root_container_pointer = Box::new(reallocate(
                arena.as_mut(),
                &mut embedded_traversal_context.root_container_pointer,
                new_size as usize,
                ocx.chained_pointer_hook,
            ));
        }

        unsafe {
            embedded_traversal_context.root_container =
                Box::from_raw(get_pointer(arena.as_mut(), &mut embedded_traversal_context.root_container_pointer, 1, ocx.chained_pointer_hook)
                    as *mut Container);
        }

        unsafe {
            let p_new: *mut c_void = (embedded_traversal_context.root_container.as_mut() as *mut Container as *mut c_void).add(old_size as usize);
            write_bytes(p_new as *mut u8, 0, (new_size - old_size) as usize);
            embedded_traversal_context.next_embedded_container = Some(Box::from_raw(
                (embedded_traversal_context.root_container.as_mut() as *mut Container as *mut c_void)
                    .add(embedded_traversal_context.next_embedded_container_offset as usize) as *mut EmbeddedContainer,
            ));

            let root_container: &mut Container = embedded_traversal_context.root_container.deref_mut();
            root_container.set_free_size_left((new_size - old_size) + free_space_left);

            for i in (i..embedded_traversal_context.embedded_container_depth as usize).rev() {
                embedded_traversal_context.embedded_stack.as_mut().unwrap()[i] = Some(AtomicEmbContainer::new_from_pointer(
                    (root_container as *mut Container as *mut c_void).add(embedded_stack[i] as usize) as *mut EmbeddedContainer,
                ));
            }

            if ocx.jump_context.as_mut().unwrap().predecessor.is_some() {
                ocx.jump_context.as_mut().unwrap().predecessor = Some(Box::from_raw(
                    (embedded_traversal_context.root_container.as_mut() as *mut Container as *mut c_void)
                        .add(ocx.jump_context.as_mut().unwrap().top_node_predecessor_offset_absolute as usize) as *mut NodeHeader,
                ));
            }

            if sublevel_ref_toplevel_node_offset > 0 {
                ocx.jump_table_sub_context.as_mut().unwrap().top_node = Some(Box::from_raw(
                    (embedded_traversal_context.root_container.as_mut() as *mut Container as *mut c_void)
                        .add(sublevel_ref_toplevel_node_offset as usize) as *mut NodeHeader,
                ));
            }
        }
    }

    let raw_container_pointer: *mut Container = embedded_traversal_context.root_container.as_mut() as *mut Container;

    ocx.embedded_traversal_context = Some(embedded_traversal_context);
    ocx.arena = Some(arena);
    unsafe {
        (raw_container_pointer as *mut char)
            .add(ctx.current_container_offset as usize + ocx.embedded_traversal_context.as_mut().unwrap().next_embedded_container_offset as usize)
            as *mut NodeHeader
    }
}

pub fn insert_jump(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, jump_value: u16) -> *mut NodeHeader {
    new_expand(ocx, ctx, size_of::<NodeValue>() as u32);
    let node_head: *mut NodeHeader = unsafe {
        (ocx.get_root_container() as *mut Container as *mut c_void)
            .add(ocx.jump_context.as_mut().unwrap().top_node_predecessor_offset_absolute as usize) as *mut NodeHeader
    };
    assert!(ocx.jump_context.as_mut().unwrap().top_node_predecessor_offset_absolute > 0);
    assert_eq!(as_top_node(node_head).container_type(), 0);
    let free_size_left: usize = ocx.embedded_traversal_context.as_mut().unwrap().root_container.deref_mut().free_bytes() as usize;
    unsafe {
        let node_offset_to_jump: usize = get_offset_jump(node_head);
        let target: *mut c_void = (node_head as *mut c_void).add(node_offset_to_jump);
        shift_container(
            target,
            size_of::<u16>(),
            ocx.embedded_traversal_context.as_mut().unwrap().root_container.deref_mut().size() as usize
                - (free_size_left + node_offset_to_jump + ocx.jump_context.as_mut().unwrap().top_node_predecessor_offset_absolute as usize),
        );

        as_top_node_mut(node_head).set_jump_successor_present(true);
        *((node_head as *mut u16).add(get_offset_jump(node_head))) += jump_value;
        let mut etc: EmbeddedTraversalContext = ocx.embedded_traversal_context.take().unwrap();
        let root_container: &mut Container = etc.root_container.as_mut();
        root_container.update_space_usage(size_of::<u16>() as i16, ocx, ctx);
        ocx.embedded_traversal_context = Some(etc);
        ctx.current_container_offset += size_of::<u16>() as i32;
        (ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut() as *mut Container as *mut c_void)
            .add(ctx.current_container_offset as usize) as *mut NodeHeader
    }
}

pub fn meta_expand(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, required: u32) -> *mut NodeHeader {
    if ocx.embedded_traversal_context.as_mut().unwrap().embedded_container_depth == 0 {
        return new_expand(ocx, ctx, required);
    }
    new_expand_embedded(ocx, ctx, required)
}

pub fn scan_put_embedded(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) -> ReturnCode {
    //     0000
    //     #[bits(1)]
    //     pub container_type: u8,
    //     #[bits(1)]
    //     pub in_first_char_scope: u8,
    //     #[bits(1)]
    //     pub two_chars: u8,
    //     #[bits(1)]
    //     pub node_type: u8,

    // 0 -> 0000 + Top node (0) + not in first char scope (0) + one char (0) + Invalid (0)
    // 1 -> 0000 + Top node (0) + not in first char scope (0) + one char (0) + InnerNode (1)
    // 2 -> 0000 + Top node (0) + not in first char scope (0) + two chars (1) + Invalid (0)
    // 3 -> 0000 + Top node (0) + not in first char scope (0) + two chars (1) + InnerNode (1)
    // 6 -> 0000 + Top node (0) + in first char scope (1) + two chars (1) + Invalid (0)
    // 7 -> 0000 + Top node (0) + in first char scope (1) + two chars (1) + InnerNode (1)

    let switch: TraversalType = ctx.as_combined_header();
    let mut key: u8;
    ctx.header.set_node_type(1);

    loop {
        let mut node_header: *mut NodeHeader = unsafe {
            (ocx.embedded_traversal_context.as_mut().unwrap().next_embedded_container.as_mut().unwrap().as_mut() as *mut EmbeddedContainer
                as *mut char)
                .add(ctx.current_container_offset as usize) as *mut NodeHeader
        };

        if ctx.current_container_offset
            >= ocx.embedded_traversal_context.as_mut().unwrap().next_embedded_container.as_mut().unwrap().as_mut().size() as i32
        {
            // ran out of container boundaries
            // Emulate an empty node
            // Container size left will be zero and will be updated
            ctx.header.set_node_type(0);
        }

        match switch {
            EmptyOneCharTopNode => {
                // Empty node, not two chars
                if ctx.header.last_top_char_set() && (ctx.first_char - ctx.last_top_char_seen) as usize <= KEY_DELTA_STATES {
                    create_node_embedded(node_header, ocx, ctx, 0, false, true, ctx.first_char - ctx.last_top_char_seen);
                } else {
                    create_node_embedded(node_header, ocx, ctx, 0, true, true, 0);
                }
                return OK;
            },
            FilledOneCharTopNode => {
                // Node found, single char op
                // Not in first char scope

                if as_top_node(node_header).container_type() == 0 {
                    // Don't process jumps for embedded nodes
                    key = get_top_node_key(node_header as *mut Node, ctx);

                    match key.cmp(&ctx.first_char) {
                        Ordering::Less => {
                            ctx.header.set_last_top_char_set(true);
                            ctx.last_top_char_seen = key;
                        }
                        Ordering::Equal => {
                            if as_top_node(node_header).type_flag() != LeafNodeWithValue && ocx.input_value.is_some() {
                                node_header = new_expand_embedded(ocx, ctx, size_of::<NodeValue>() as u32);
                                let target: *mut c_void = unsafe { (node_header as *mut c_void).add(get_offset_node_value(node_header)) };
                                let mut emb_context: EmbeddedTraversalContext = ocx.embedded_traversal_context.take().unwrap();
                                unsafe {
                                    emb_context.root_container.as_mut().wrap_shift_container(target, size_of::<NodeValue>());
                                }
                                emb_context.root_container.as_mut().update_space_usage(size_of::<NodeValue>() as i16, ocx, ctx);
                                ocx.embedded_traversal_context = Some(emb_context);
                            }
                            return set_node_value(node_header, ocx);
                        }
                        Ordering::Greater => {
                            // Need to shift and insert
                            ctx.header.set_force_shift_before_insert(true);
                            ctx.header.set_in_first_char_scope(true);
                            if ctx.header.last_top_char_set() && (ctx.first_char - ctx.last_top_char_seen) as usize <= KEY_DELTA_STATES {
                                create_node_embedded(node_header, ocx, ctx, 0, false, true, ctx.first_char - ctx.last_top_char_seen);
                            } else {
                                create_node_embedded(node_header, ocx, ctx, 0, true, true, 0);
                            }
                            return OK;
                        }
                    }
                    ctx.current_container_offset += get_offset_sub_node(node_header) as i32;
                    continue;
                }
                ctx.current_container_offset += get_offset_sub_node(node_header) as i32;
                continue;
            },
            EmptyTwoCharTopNode => {
                // Empty node, two chars, not in first char scope
                if ctx.header.last_top_char_set() && (ctx.first_char - ctx.last_top_char_seen) as usize <= KEY_DELTA_STATES {
                    // Create a relative first char key
                    // Add value afterward
                    node_header = create_node_embedded(node_header, ocx, ctx, 0, false, false, ctx.first_char - ctx.last_top_char_seen);
                } else {
                    // Create an absolute key
                    // Add value afterward
                    node_header = create_node_embedded(node_header, ocx, ctx, 0, true, false, 0);
                }
                ctx.header.set_in_first_char_scope(true);
                ctx.current_container_offset += get_offset_sub_node(node_header) as i32;
                continue;
            },
            FilledTwoCharTopNode => {
                // Valid node found
                // Two char operation, not in first char scope

                if as_top_node(node_header).container_type() == 0 {
                    // Don't process jumps for embedded nodes
                    key = get_top_node_key(node_header as *mut Node, ctx);

                    match key.cmp(&ctx.first_char) {
                        Ordering::Less => {
                            ctx.header.set_last_top_char_set(true);
                            ctx.last_top_char_seen = key;
                        }
                        Ordering::Equal => {
                            ctx.header.set_in_first_char_scope(true);
                        }
                        Ordering::Greater => {
                            // Need to shift and insert
                            ctx.header.set_force_shift_before_insert(true);
                            ctx.header.set_in_first_char_scope(true);
                            if ctx.header.last_top_char_set() && (ctx.first_char - ctx.last_top_char_seen) as usize <= KEY_DELTA_STATES {
                                node_header = create_node_embedded(node_header, ocx, ctx, 0, false, true, ctx.first_char - ctx.last_top_char_seen);
                            } else {
                                node_header = create_node_embedded(node_header, ocx, ctx, 0, true, false, 0);
                            }
                        }
                    }
                    ctx.current_container_offset += get_offset_sub_node(node_header) as i32;
                    continue;
                }
                ctx.current_container_offset += get_offset_sub_node(node_header) as i32;
                continue;
            },
            EmptyTwoCharTopNodeInFirstCharScope => {
                // Empty node, two chars, in first char scope
                // create a new node with container depth 1
                if ctx.header.last_sub_char_set() && (ctx.second_char - ctx.last_sub_char_seen) as usize <= KEY_DELTA_STATES {
                    create_node_embedded(node_header, ocx, ctx, 1, false, ctx.header.end_operation(), ctx.second_char - ctx.last_sub_char_seen);
                } else {
                    create_node_embedded(node_header, ocx, ctx, 1, true, ctx.header.end_operation(), 0);
                }
                return OK;
            },
            FilledTwoCharTopNodeInFirstCharScope => {
                // Node found, two char operation, in first char scope

                if as_top_node(node_header).container_type() == 1 {
                    // Still in first char scope
                    key = get_top_node_key(node_header as *mut Node, ctx);

                    match key.cmp(&ctx.first_char) {
                        Ordering::Less => {
                            ctx.header.set_last_top_char_set(true);
                            ctx.last_top_char_seen = key;
                            ctx.current_container_offset += get_offset_sub_node(node_header) as i32;
                            continue;
                        }
                        Ordering::Equal => {
                            return if ctx.header.end_operation() {
                                if as_top_node(node_header).type_flag() != LeafNodeWithValue && ocx.input_value.is_some() {
                                    node_header = new_expand_embedded(ocx, ctx, size_of::<NodeValue>() as u32);
                                    let target: *mut c_void = unsafe { (node_header as *mut c_void).add(get_offset_node_value(node_header)) };
                                    let mut emb_context: EmbeddedTraversalContext = ocx.embedded_traversal_context.take().unwrap();
                                    unsafe {
                                        emb_context.root_container.as_mut().wrap_shift_container(target, size_of::<NodeValue>());
                                    }
                                    emb_context.root_container.as_mut().update_space_usage(size_of::<NodeValue>() as i16, ocx, ctx);
                                    ocx.embedded_traversal_context = Some(emb_context);
                                }
                                set_node_value(node_header, ocx)
                            } else {
                                if as_sub_node(node_header).child_container() == PathCompressed {
                                    if !compare_path_compressed_node(node_header, ocx) {
                                        update_path_compressed_node(node_header, ocx, ctx);
                                        return OK;
                                    } else {
                                        safe_path_compressed_context(node_header, ocx);
                                    }
                                } else if as_sub_node(node_header).child_container() == ChildLinkType::None {
                                    embed_or_link_child(node_header, ocx, ctx);
                                } else {
                                    let mut next_container: Box<HyperionPointer> = ocx.next_container_pointer.take().unwrap();
                                    let mut next_container_pointer: Option<NonNull<HyperionPointer>> =
                                        NonNull::new(next_container.as_mut() as *mut HyperionPointer);
                                    get_child_container_pointer(node_header, &mut next_container_pointer, ocx, ctx);
                                    ocx.next_container_pointer = Some(next_container);
                                }
                                OK
                            }
                        }
                        Ordering::Greater => {
                            ctx.header.set_force_shift_before_insert(true);
                            if ctx.header.last_sub_char_set() && (ctx.second_char - ctx.last_sub_char_seen) as usize <= KEY_DELTA_STATES {
                                create_node_embedded(
                                    node_header,
                                    ocx,
                                    ctx,
                                    1,
                                    false,
                                    ctx.header.end_operation(),
                                    ctx.second_char - ctx.last_sub_char_seen,
                                );
                            } else {
                                create_node_embedded(node_header, ocx, ctx, 1, true, ctx.header.end_operation(), 0);
                            }
                            return OK;
                        }
                    }
                } else {
                    ctx.header.set_force_shift_before_insert(true);
                    if ctx.header.last_sub_char_set() && (ctx.second_char - ctx.last_sub_char_seen) as usize <= KEY_DELTA_STATES {
                        create_node_embedded(node_header, ocx, ctx, 1, false, ctx.header.end_operation(), ctx.second_char - ctx.last_sub_char_seen);
                    } else {
                        create_node_embedded(node_header, ocx, ctx, 1, true, ctx.header.end_operation(), 0);
                    }
                    return OK;
                }
            },
            _ => {
                return UnknownOperation;
            },
        }
    }
}

pub fn scan_put_single(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) -> ReturnCode {
    let mut node_head: *mut NodeHeader = null_mut();
    let mut key = 0;
    let mut emb_ctx: EmbeddedTraversalContext = ocx.embedded_traversal_context.take().unwrap();
    let root_container: &mut Container = emb_ctx.root_container.as_mut();
    let mut jump_point = NoJump;

    ctx.safe_offset = root_container.size() as i32 - root_container.free_bytes() as i32;

    if root_container.jump_table() == 0 {
        ctx.current_container_offset = root_container.get_container_head_size();
    } else {
        key = root_container.use_jumptable_2(ctx.first_char, &mut ctx.current_container_offset);
        node_head = unsafe { (root_container as *mut Container as *mut char).add(ctx.current_container_offset as usize) as *mut NodeHeader };

        if key != 0 {
            jump_point = JumpPoint2;
        }
    }

    loop {
        match jump_point {
            NoJump => {
                node_head = unsafe { (root_container as *mut Container as *mut char).add(ctx.current_container_offset as usize) as *mut NodeHeader };

                if ctx.safe_offset > ctx.current_container_offset {
                    jump_point = JumpPoint1;
                    continue;
                }

                if ctx.current_container_offset >= root_container.size() as i32 || as_top_node(node_head).type_flag() == Invalid {
                    ocx.embedded_traversal_context = Some(emb_ctx);
                    ocx.jump_context.as_mut().unwrap().top_node_key = ctx.first_char as i32;
                    if ctx.header.last_top_char_set() && (ctx.first_char - ctx.last_top_char_seen) as usize <= KEY_DELTA_STATES {
                        create_node(node_head, ocx, ctx, 0, false, true, ctx.first_char - ctx.last_top_char_seen);
                    } else {
                        create_node(node_head, ocx, ctx, 0, true, true, 0);
                    }
                    return OK;
                }
                jump_point = JumpPoint1;
                continue;
            },
            JumpPoint1 => {
                jump_point = NoJump;
                if as_top_node(node_head).container_type() == 0 {
                    key = get_top_node_key(node_head as *mut Node, ctx);
                    jump_point = JumpPoint2;
                    continue;
                }
                ocx.jump_context.as_mut().unwrap().sub_nodes_seen += 1;
                ctx.current_container_offset += get_offset_sub_node(node_head) as i32;
            },
            JumpPoint2 => {
                ocx.jump_context.as_mut().unwrap().top_node_key = key as i32;

                match key.cmp(&ctx.first_char) {
                    Ordering::Less => {
                        ctx.header.set_last_top_char_set(true);
                        ctx.last_top_char_seen = key;
                    }
                    Ordering::Equal => {
                        register_jump_context(node_head, ctx, ocx);
                        if as_top_node(node_head).type_flag() != LeafNodeWithValue && ocx.input_value.is_some() {
                            node_head = new_expand(ocx, ctx, size_of::<NodeValue>() as u32);
                            unsafe {
                                root_container
                                    .wrap_shift_container((node_head as *mut c_void).add(get_offset_node_value(node_head)), size_of::<NodeValue>());
                            }
                            root_container.update_space_usage(size_of::<NodeValue>() as i16, ocx, ctx);
                        }
                        ocx.embedded_traversal_context = Some(emb_ctx);
                        return set_node_value(node_head, ocx);
                    }
                    Ordering::Greater => {
                        ocx.jump_context.as_mut().unwrap().predecessor = None;
                        ctx.header.set_force_shift_before_insert(true);
                        ocx.embedded_traversal_context = Some(emb_ctx);

                        if ctx.header.last_top_char_set() && (ctx.first_char - ctx.last_top_char_seen) as usize <= KEY_DELTA_STATES {
                            create_node(node_head, ocx, ctx, 0, false, true, ctx.first_char - ctx.last_top_char_seen);
                        } else {
                            create_node(node_head, ocx, ctx, 0, true, true, 0);
                        }
                        return OK;
                    }
                }

                if as_top_node(node_head).jump_successor_present() {
                    ctx.current_container_offset = get_jump_value(node_head) as i32;
                } else {
                    ctx.current_container_offset += get_offset_top_node(node_head) as i32;
                }
                ocx.jump_context.as_mut().unwrap().predecessor = unsafe { Some(Box::from_raw(node_head.as_mut().unwrap() as *mut NodeHeader)) };
                ocx.jump_context.as_mut().unwrap().top_node_predecessor_offset_absolute =
                    unsafe { (node_head as *mut c_void).offset_from(root_container as *mut Container as *mut c_void) as i32 };
                ocx.jump_context.as_mut().unwrap().sub_nodes_seen = 0;
                jump_point = NoJump;
                continue;
            },
        }
    }
}

pub fn scan_put_phase2(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) -> ReturnCode {
    let mut node_head: *mut NodeHeader = null_mut();
    let mut key = 0;
    let mut emb_ctx: EmbeddedTraversalContext = ocx.embedded_traversal_context.take().unwrap();
    let root_container: &mut Container = emb_ctx.root_container.as_mut();
    let mut jump_point = NoJump;

    ctx.safe_offset = root_container.size() as i32 - root_container.free_bytes() as i32;

    node_head = unsafe { (root_container as *mut Container as *mut char).add(ctx.current_container_offset as usize) as *mut NodeHeader };

    loop {
        match jump_point {
            NoJump => {
                assert!(ctx.safe_offset > 0);

                if ctx.safe_offset > ctx.current_container_offset {
                    jump_point = JumpPoint1;
                    continue;
                }

                if ctx.current_container_offset >= root_container.size() as i32 || as_top_node(node_head).type_flag() == Invalid {
                    ocx.embedded_traversal_context = Some(emb_ctx);
                    ctx.header.set_node_type(0);
                    if ctx.header.last_sub_char_set() && (ctx.second_char - ctx.last_sub_char_seen) as usize <= KEY_DELTA_STATES {
                        create_node(node_head, ocx, ctx, 1, false, ctx.header.end_operation(), ctx.second_char - ctx.last_sub_char_seen);
                    } else {
                        create_node(node_head, ocx, ctx, 1, true, ctx.header.end_operation(), 0);
                    }
                    return OK;
                }

                jump_point = JumpPoint1;
                continue;
            },
            JumpPoint1 => {
                jump_point = NoJump;
                if as_top_node(node_head).container_type() == 1 {
                    key = get_top_node_key(node_head as *mut Node, ctx);

                    match key.cmp(&ctx.second_char) {
                        Ordering::Less => {
                            ctx.current_container_offset += get_offset_sub_node(node_head) as i32;
                            node_head =
                                unsafe { (root_container as *mut Container as *mut char).add(ctx.current_container_offset as usize) as *mut NodeHeader };
                            ctx.header.set_last_sub_char_set(true);
                            ctx.last_sub_char_seen = key;
                            ocx.jump_context.as_mut().unwrap().sub_nodes_seen += 1;

                            if ocx.jump_context.as_mut().unwrap().sub_nodes_seen >= SUBLEVEL_JUMPTABLE_HWM as i32 {
                                ocx.embedded_traversal_context = Some(emb_ctx);
                                create_sublevel_jumptable(node_head, ocx, ctx);
                                ctx.flush();
                                ocx.flush_jump_context();
                                ocx.flush_jump_table_sub_context();
                                ctx.current_container_offset =
                                    ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut().get_container_head_size();
                                return scan_put(ocx, ctx);
                            }
                        }
                        Ordering::Equal => {
                            if ctx.header.end_operation() {
                                if as_top_node(node_head).type_flag() != LeafNodeWithValue && ocx.input_value.is_some() {
                                    node_head = new_expand(ocx, ctx, size_of::<NodeValue>() as u32);
                                    unsafe {
                                        emb_ctx.root_container.as_mut().wrap_shift_container(
                                            (node_head as *mut c_void).add(get_offset_node_value(node_head)),
                                            size_of::<NodeValue>(),
                                        );
                                    }
                                    emb_ctx.root_container.as_mut().update_space_usage(size_of::<NodeValue>() as i16, ocx, ctx);
                                }
                                set_node_value(node_head, ocx);
                            } else {
                                match as_sub_node(node_head).child_container() {
                                    ChildLinkType::None => {
                                        node_head = embed_or_link_child(node_head, ocx, ctx);
                                    },
                                    PathCompressed => {
                                        if !compare_path_compressed_node(node_head, ocx) {
                                            node_head = update_path_compressed_node(node_head, ocx, ctx);
                                        } else {
                                            safe_path_compressed_context(node_head, ocx);
                                            node_head = embed_or_link_child(node_head, ocx, ctx);
                                        }
                                    },
                                    _ => {
                                        let mut next_container: Box<HyperionPointer> = ocx.next_container_pointer.take().unwrap();
                                        let mut next_container_pointer: Option<NonNull<HyperionPointer>> =
                                            NonNull::new(next_container.as_mut() as *mut HyperionPointer);
                                        get_child_container_pointer(node_head, &mut next_container_pointer, ocx, ctx);
                                        ocx.next_container_pointer = Some(next_container);
                                    },
                                }
                            }
                            ocx.embedded_traversal_context = Some(emb_ctx);
                            return OK;
                        }
                        Ordering::Greater => {
                            ctx.header.set_force_shift_before_insert(true);
                            if ctx.header.last_sub_char_set() && (ctx.second_char - ctx.last_sub_char_seen) as usize <= KEY_DELTA_STATES {
                                create_node(node_head, ocx, ctx, 1, false, ctx.header.end_operation(), ctx.second_char - ctx.last_sub_char_seen);
                            } else {
                                if !ctx.header.last_sub_char_set() {
                                    ctx.header.set_last_sub_char_set(true);
                                    ctx.last_sub_char_seen = 0;
                                }
                                create_node(node_head, ocx, ctx, 1, true, ctx.header.end_operation(), 0);
                            }
                            ocx.embedded_traversal_context = Some(emb_ctx);
                            return OK;
                        }
                    }
                } else {
                    ctx.header.set_force_shift_before_insert(true);
                    if ctx.header.last_sub_char_set() && (ctx.second_char - ctx.last_sub_char_seen) as usize <= KEY_DELTA_STATES {
                        create_node(node_head, ocx, ctx, 1, false, ctx.header.end_operation(), ctx.second_char - ctx.last_sub_char_seen);
                    } else {
                        create_node(node_head, ocx, ctx, 1, true, ctx.header.end_operation(), 0);
                    }
                    ocx.embedded_traversal_context = Some(emb_ctx);
                    return OK;
                }
            },
            _ => {
                break;
            },
        }
    }
    OK
}

pub fn scan_put_phase2_withjt(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, destination: u8) -> ReturnCode {
    let mut node_head: *mut NodeHeader = null_mut();
    let mut key = destination;
    let mut emb_ctx: EmbeddedTraversalContext = ocx.embedded_traversal_context.take().unwrap();
    let root_container: &mut Container = emb_ctx.root_container.as_mut();
    let mut jump_point = NoJump;

    ctx.safe_offset = root_container.size() as i32 - root_container.free_bytes() as i32;

    node_head = unsafe { (root_container as *mut Container as *mut char).add(ctx.current_container_offset as usize) as *mut NodeHeader };

    if key != 0 {
        jump_point = JumpPoint2;
    }

    loop {
        match jump_point {
            NoJump => {
                if ctx.safe_offset > ctx.current_container_offset {
                    jump_point = JumpPoint1;
                    continue;
                }

                if ctx.current_container_offset >= root_container.size() as i32 || as_top_node(node_head).type_flag() == Invalid {
                    ocx.embedded_traversal_context = Some(emb_ctx);
                    ctx.header.set_node_type(0);
                    if ctx.header.last_sub_char_set() && (ctx.second_char - ctx.last_sub_char_seen) as usize <= KEY_DELTA_STATES {
                        create_node(node_head, ocx, ctx, 1, false, ctx.header.end_operation(), ctx.second_char - ctx.last_sub_char_seen);
                    } else {
                        create_node(node_head, ocx, ctx, 1, true, ctx.header.end_operation(), 0);
                    }
                    return OK;
                }
                jump_point = JumpPoint1;
                continue;
            },
            JumpPoint1 => {
                jump_point = NoJump;
                if as_top_node(node_head).container_type() == 1 {
                    key = get_top_node_key(node_head as *mut Node, ctx);
                    jump_point = JumpPoint2;
                    continue;
                } else {
                    ctx.header.set_force_shift_before_insert(true);
                    if ctx.header.last_sub_char_set() && (ctx.second_char - ctx.last_sub_char_seen) as usize <= KEY_DELTA_STATES {
                        create_node(node_head, ocx, ctx, 1, false, ctx.header.end_operation(), ctx.second_char - ctx.last_sub_char_seen);
                    } else {
                        create_node(node_head, ocx, ctx, 1, true, ctx.header.end_operation(), 0);
                    }
                    ocx.embedded_traversal_context = Some(emb_ctx);
                    return OK;
                }
            },
            JumpPoint2 => {
                jump_point = NoJump;

                match key.cmp(&ctx.second_char) {
                    Ordering::Less => {
                        ctx.current_container_offset += get_offset_sub_node(node_head) as i32;
                        node_head =
                            unsafe { (root_container as *mut Container as *mut char).add(ctx.current_container_offset as usize) as *mut NodeHeader };
                        ctx.header.set_last_sub_char_set(true);
                        ctx.last_sub_char_seen = key;
                    }
                    Ordering::Equal => {
                        if ctx.header.end_operation() {
                            if as_top_node(node_head).type_flag() != LeafNodeWithValue && ocx.input_value.is_some() {
                                node_head = new_expand(ocx, ctx, size_of::<NodeValue>() as u32);
                                unsafe {
                                    emb_ctx
                                        .root_container
                                        .as_mut()
                                        .wrap_shift_container((node_head as *mut c_void).add(get_offset_node_value(node_head)), size_of::<NodeValue>());
                                }
                                emb_ctx.root_container.as_mut().update_space_usage(size_of::<NodeValue>() as i16, ocx, ctx);
                            }
                            set_node_value(node_head, ocx);
                        } else {
                            match as_sub_node(node_head).child_container() {
                                ChildLinkType::None => {
                                    node_head = embed_or_link_child(node_head, ocx, ctx);
                                },
                                PathCompressed => {
                                    if !compare_path_compressed_node(node_head, ocx) {
                                        node_head = update_path_compressed_node(node_head, ocx, ctx);
                                    } else {
                                        safe_path_compressed_context(node_head, ocx);
                                        node_head = embed_or_link_child(node_head, ocx, ctx);
                                    }
                                },
                                _ => {
                                    let mut next_container: Box<HyperionPointer> = ocx.next_container_pointer.take().unwrap();
                                    let mut next_container_pointer: Option<NonNull<HyperionPointer>> =
                                        NonNull::new(next_container.as_mut() as *mut HyperionPointer);
                                    get_child_container_pointer(node_head, &mut next_container_pointer, ocx, ctx);
                                    ocx.next_container_pointer = Some(next_container);
                                },
                            }
                        }
                        ocx.embedded_traversal_context = Some(emb_ctx);
                        return OK;
                    }
                    Ordering::Greater => {
                        ctx.header.set_force_shift_before_insert(true);
                        if ctx.header.last_sub_char_set() && (ctx.second_char - ctx.last_sub_char_seen) as usize <= KEY_DELTA_STATES {
                            create_node(node_head, ocx, ctx, 1, false, ctx.header.end_operation(), ctx.second_char - ctx.last_sub_char_seen);
                        } else {
                            create_node(node_head, ocx, ctx, 1, true, ctx.header.end_operation(), 0);
                        }
                        ocx.embedded_traversal_context = Some(emb_ctx);
                        return OK;
                    }
                }
            }
        }
    }
}

pub fn scan_put(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) -> ReturnCode {
    let mut node_head: *mut NodeHeader = null_mut();
    let mut toplevel_nodes = TOPLEVEL_NODE_JUMP_HWM as i32;
    let mut emb_ctx: EmbeddedTraversalContext = ocx.embedded_traversal_context.take().unwrap();
    let root_container: &mut Container = emb_ctx.root_container.as_mut();
    let mut jump_point = NoJump;

    ctx.safe_offset = root_container.size() as i32 - root_container.free_bytes() as i32;

    if root_container.jump_table() != 0 {
        if (root_container.jump_table() as usize) < TOPLEVEL_JUMPTABLE_INCREMENTS {
            toplevel_nodes = TOPLEVEL_AGGRESSIVE_GROWTH__HWM as i32;
        }

        ocx.jump_context.as_mut().unwrap().top_node_key = root_container.use_jumptable_2(ctx.first_char, &mut ctx.current_container_offset) as i32;

        if ocx.jump_context.as_mut().unwrap().top_node_key != 0 {
            node_head = unsafe { (root_container as *mut Container as *mut char).add(ctx.current_container_offset as usize) as *mut NodeHeader };
            jump_point = JumpPoint2;
        }
    }

    loop {
        match jump_point {
            NoJump => {
                node_head = unsafe { (root_container as *mut Container as *mut char).add(ctx.current_container_offset as usize) as *mut NodeHeader };

                if ctx.safe_offset <= ctx.current_container_offset {
                    ocx.jump_context.as_mut().unwrap().top_node_key = ctx.first_char as i32;

                    if ctx.header.last_top_char_set() && (ctx.first_char - ctx.last_top_char_seen) as usize <= KEY_DELTA_STATES {
                        node_head = create_node(node_head, ocx, ctx, 0, false, false, ctx.first_char - ctx.last_top_char_seen);
                    } else {
                        node_head = create_node(node_head, ocx, ctx, 0, true, false, 0);
                    }
                    ctx.current_container_offset += get_offset_top_node(node_head) as i32;
                    node_head =
                        unsafe { (root_container as *mut Container as *mut char).add(ctx.current_container_offset as usize) as *mut NodeHeader };
                    create_node(node_head, ocx, ctx, 1, true, ctx.header.end_operation(), ctx.second_char);
                    ocx.embedded_traversal_context = Some(emb_ctx);
                    return OK;
                }

                if as_top_node(node_head).container_type() == 1 {
                    ocx.jump_context.as_mut().unwrap().sub_nodes_seen += 1;
                    ctx.current_container_offset += get_offset_sub_node(node_head) as i32;
                    node_head =
                        unsafe { (root_container as *mut Container as *mut char).add(ctx.current_container_offset as usize) as *mut NodeHeader };
                    jump_point = NoJump;
                    continue;
                }
            },
            JumpPoint1 => {
                if toplevel_nodes == 0 && (root_container.size() as usize) > CONTAINER_SIZE_TYPE_0 * 4 {
                    // insert or upgrade the jump table and restart the scan
                    // upgrade_jump_table will reset ctx and ocx as required
                    ocx.embedded_traversal_context = Some(emb_ctx);
                    insert_top_level_jumptable(ocx, ctx);
                    ctx.flush();
                    ocx.flush_jump_context();
                    ocx.flush_jump_table_sub_context();
                    return scan_put(ocx, ctx);
                }
                ocx.jump_context.as_mut().unwrap().top_node_key = get_top_node_key(node_head as *mut Node, ctx) as i32;
                jump_point = JumpPoint2;
                continue;
            },
            JumpPoint2 => {
                toplevel_nodes -= 1;

                match ocx.jump_context.as_mut().unwrap().top_node_key.cmp(&(ctx.first_char as i32)) {
                    Ordering::Less => {
                        ctx.header.set_last_top_char_set(true);
                        ctx.last_top_char_seen = ocx.jump_context.as_mut().unwrap().top_node_key as u8;

                        if ocx.jump_context.as_mut().unwrap().sub_nodes_seen
                            > unsafe { GLOBAL_CONFIG.lock().unwrap().top_level_successor_threshold as i32 }
                        {
                            let jump_value = unsafe {
                                ((node_head as *mut c_void).offset_from(root_container as *mut Container as *mut c_void) as u16)
                                    - ocx.jump_context.as_mut().unwrap().top_node_predecessor_offset_absolute as u16
                            };
                            node_head = insert_jump(ocx, ctx, jump_value);
                        }
                        ocx.jump_context.as_mut().unwrap().sub_nodes_seen = 0;

                        if as_top_node(node_head).jump_successor_present() {
                            ctx.current_container_offset += get_jump_value(node_head) as i32;
                            ocx.jump_context.as_mut().unwrap().predecessor =
                                unsafe { Some(Box::from_raw(node_head.as_mut().unwrap() as *mut NodeHeader)) };
                            ocx.jump_context.as_mut().unwrap().top_node_predecessor_offset_absolute =
                                unsafe { (node_head as *mut c_void).offset_from(root_container as *mut Container as *mut c_void) as i32 };
                            node_head =
                                unsafe { (root_container as *mut Container as *mut char).add(ctx.current_container_offset as usize) as *mut NodeHeader };
                            jump_point = JumpPoint1;
                            continue;
                        }

                        ocx.jump_context.as_mut().unwrap().predecessor = unsafe { Some(Box::from_raw(node_head.as_mut().unwrap() as *mut NodeHeader)) };
                        ocx.jump_context.as_mut().unwrap().top_node_predecessor_offset_absolute =
                            unsafe { (node_head as *mut c_void).offset_from(root_container as *mut Container as *mut c_void) as i32 };
                        ctx.current_container_offset += get_offset_top_node(node_head) as i32;
                        node_head =
                            unsafe { (root_container as *mut Container as *mut char).add(ctx.current_container_offset as usize) as *mut NodeHeader };
                        jump_point = NoJump;
                        continue;
                    }
                    Ordering::Equal => {
                        ctx.header.set_in_first_char_scope(true);
                        if ocx.jump_context.as_mut().unwrap().sub_nodes_seen
                            > unsafe { GLOBAL_CONFIG.lock().unwrap().top_level_successor_threshold as i32 }
                        {
                            let jump_distance = unsafe {
                                ((node_head as *mut c_void).offset_from(root_container as *mut Container as *mut c_void) as u16)
                                    - ocx.jump_context.as_mut().unwrap().top_node_predecessor_offset_absolute as u16
                            };
                            node_head = insert_jump(ocx, ctx, jump_distance);
                        }
                        ocx.jump_table_sub_context.as_mut().unwrap().top_node =
                            unsafe { Some(Box::from_raw(node_head.as_mut().unwrap() as *mut NodeHeader)) };
                        ocx.jump_context.as_mut().unwrap().top_node_predecessor_offset_absolute =
                            unsafe { (node_head as *mut c_void).offset_from(root_container as *mut Container as *mut c_void) as i32 };
                        ocx.jump_context.as_mut().unwrap().sub_nodes_seen = 0;
                        ocx.jump_context.as_mut().unwrap().predecessor = unsafe { Some(Box::from_raw(node_head.as_mut().unwrap() as *mut NodeHeader)) };

                        ocx.embedded_traversal_context = Some(emb_ctx);

                        if as_top_node(node_head).jump_table_present() {
                            let destination = use_sub_node_jump_table(node_head, ctx);
                            return scan_put_phase2_withjt(ocx, ctx, destination);
                        }
                        ctx.current_container_offset += get_offset(node_head) as i32;
                        return scan_put_phase2(ocx, ctx);
                    }
                    Ordering::Greater => {
                        ctx.header.set_force_shift_before_insert(true);
                        ocx.flush_jump_context();

                        if ctx.header.last_top_char_set() && (ctx.first_char - ctx.last_top_char_seen) as usize <= KEY_DELTA_STATES {
                            node_head = create_node(node_head, ocx, ctx, 0, false, false, ctx.first_char - ctx.last_top_char_seen);
                        } else {
                            node_head = create_node(node_head, ocx, ctx, 0, true, false, 0);
                        }
                        ctx.current_container_offset = get_offset_top_node(node_head) as i32;
                        node_head =
                            unsafe { (root_container as *mut Container as *mut char).add(ctx.current_container_offset as usize) as *mut NodeHeader };
                        create_node(node_head, ocx, ctx, 1, true, ctx.header.end_operation(), ctx.second_char);
                        return OK;
                    }
                }
            },
        }
    }
}

pub fn insert_top_level_jumptable(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) {
    let mut node_cache: Node = Node {
        header: NodeHeader::new_top_node(TopNode::default()),
        stored_value: 0,
    };
    let mut found_keys: [u8; 256] = [0; 256];
    let mut found_offsets: [u32; 256] = [0; 256];
    let mut found: usize = 0;
    let mut required_max = 0;
    let mut tmp_ctx = ContainerTraversalContext {
        header: ContainerTraversalHeader::default(),
        last_top_char_seen: 0,
        last_sub_char_seen: 0,
        current_container_offset: 0,
        safe_offset: 0,
        first_char: 0,
        second_char: 0,
    };

    tmp_ctx.header.set_last_top_char_set(false);

    let successor: *mut Node = &mut node_cache as *mut Node;
    let mut skipped = 0;
    tmp_ctx.current_container_offset = ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut().get_container_head_size()
        + ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut().get_jump_table_size();

    unsafe {
        let mut node_head = (ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut() as *mut Container as *mut c_void)
            .add(tmp_ctx.current_container_offset as usize) as *mut NodeHeader;

        while (ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut().size() as i32) > tmp_ctx.current_container_offset {
            if as_top_node(node_head).type_flag() == Invalid {
                break;
            }

            ocx.jump_context.as_mut().unwrap().top_node_key = get_top_node_key(node_head as *mut Node, &mut tmp_ctx) as i32;
            found_keys[found] = ocx.jump_context.as_mut().unwrap().top_node_key as u8;
            found_offsets[found] = tmp_ctx.current_container_offset as u32;
            tmp_ctx.last_top_char_seen = ocx.jump_context.as_mut().unwrap().top_node_key as u8;
            tmp_ctx.header.set_last_top_char_set(true);

            let mut successor_ptr = NonNull::new(successor);
            skipped = get_successor(node_head, &mut successor_ptr, ocx, &mut tmp_ctx);

            if skipped == 0 {
                break; // No successor
            }

            tmp_ctx.current_container_offset += skipped as i32;
            found += 1;
            node_head = &mut (*(successor_ptr.unwrap().as_ptr())).header as *mut NodeHeader;
        }

        if found < TOPLEVEL_JUMPTABLE_ENTRIES {
            return;
        }

        let current_jumptable_value = ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut().jump_table();

        if (current_jumptable_value < (TOPLEVEL_JUMPTABLE_INCREMENTS as u8))
            && (found >= (current_jumptable_value as usize * TOPLEVEL_JUMPTABLE_ENTRIES + TOPLEVEL_JUMPTABLE_ENTRIES))
        {
            ocx.flush_jump_context();
            let mut increment = (found / TOPLEVEL_JUMPTABLE_ENTRIES) - current_jumptable_value as usize;

            if increment <= 1 {
                increment = 1;
            } else if (increment + current_jumptable_value as usize) > TOPLEVEL_JUMPTABLE_INCREMENTS {
                increment = TOPLEVEL_JUMPTABLE_INCREMENTS - current_jumptable_value as usize;
            }

            required_max = size_of::<SubNodeJumpTable>() * increment;
            let free_size_left = ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut().free_bytes() as i32;
            let container_head_size = ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut().get_container_head_size();
            let bytes_to_move =
                ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut().size() as i32 - container_head_size + free_size_left;

            if (free_size_left as usize) < required_max {
                new_expand(ocx, ctx, required_max as u32);
            }

            let target = (ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut() as *mut Container as *mut c_void)
                .add(container_head_size as usize);
            shift_container(target, required_max, bytes_to_move as usize);
            ocx.embedded_traversal_context.as_mut().unwrap().embedded_container_depth = 0;
            let mut emb_ctx = ocx.embedded_traversal_context.take().unwrap();
            emb_ctx.root_container.as_mut().update_space_usage(size_of::<TopNodeJumpTable>() as i16, ocx, ctx);
            ocx.embedded_traversal_context = Some(emb_ctx);
            ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut().set_jump_table(current_jumptable_value + increment as u8);
        }

        let items = TOPLEVEL_JUMPTABLE_ENTRIES * ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut().jump_table() as usize;
        let interval: f32 = (found as f32) / (items as f32);
        assert!(interval < TOPLEVEL_NODE_JUMP_HWM as f32);
        let mut jumptable_entry = ocx.embedded_traversal_context.as_mut().unwrap().root_container.as_mut().get_jump_table_pointer();

        for i in 0..items {
            let tmp = (interval + interval * i as f32).floor() as usize;
            (*jumptable_entry).set_key(found_keys[tmp]);
            (*jumptable_entry).set_offset(found_offsets[tmp] + required_max as u32);
            jumptable_entry = jumptable_entry.add(1);
        }
    }
}
