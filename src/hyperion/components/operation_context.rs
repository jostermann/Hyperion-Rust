use crate::hyperion::components::container::{shift_container, update_space_usage, wrap_shift_container, Container, EmbeddedContainer, RootContainerEntryInner, CONTAINER_MAX_EMBEDDED_DEPTH};
use crate::hyperion::components::context::TraversalType::{EmptyOneCharTopNode, EmptyTwoCharTopNode, EmptyTwoCharTopNodeInFirstCharScope, FilledOneCharTopNode, FilledTwoCharTopNode, FilledTwoCharTopNodeInFirstCharScope};
use crate::hyperion::components::context::{ContainerInjectionContext, ContainerTraversalContext, EmbeddedTraversalContext, JumpContext, JumpTableSubContext, OperationCommand, PathCompressedEjectionContext, KEY_DELTA_STATES, SUBLEVEL_JUMPTABLE_HWM, TOPLEVEL_AGGRESSIVE_GROWTH__HWM, TOPLEVEL_JUMPTABLE_INCREMENTS};
use crate::hyperion::components::jump_table::{SubNodeJumpTable, TOPLEVEL_JUMPTABLE_ENTRIES, TOPLEVEL_NODE_JUMP_HWM};
use crate::hyperion::components::node::NodeType::{Invalid, LeafNodeWithValue};
use crate::hyperion::components::node::{get_sub_node_key, get_top_node_key, Node, NodeState, NodeValue};
use crate::hyperion::components::node_header::{as_sub_node, as_top_node, as_top_node_mut, compare_path_compressed_node, create_node, create_sublevel_jumptable, embed_or_link_child, get_child_container_pointer, get_jump_value, get_offset, get_offset_jump, get_offset_node_value, get_offset_sub_node, get_offset_top_node, get_successor, register_jump_context, safe_path_compressed_context, set_node_value, update_path_compressed_node, use_sub_node_jump_table, NodeHeader};
use crate::hyperion::components::operation_context::JumpStates::{JumpPoint1, JumpPoint2, NoJump};
use crate::hyperion::components::return_codes::ReturnCode;
use crate::hyperion::components::return_codes::ReturnCode::{UnknownOperation, OK};
use crate::hyperion::components::sub_node::ChildLinkType;
use crate::hyperion::components::sub_node::ChildLinkType::PathCompressed;
use crate::hyperion::components::top_node::TopNode;
use crate::hyperion::internals::atomic_pointer::{AtomicEmbContainer, CONTAINER_SIZE_TYPE_0};
use crate::hyperion::internals::core::{log_to_file, GLOBAL_CONFIG};
use crate::hyperion::internals::errors::{ERR_EMPTY_EMB_STACK, ERR_NO_ARENA, ERR_NO_CAST_MUT_REF, ERR_NO_INPUT_VALUE, ERR_NO_KEY, ERR_NO_NEXT_CONTAINER, ERR_NO_NODE, ERR_NO_RETURN_VALUE, ERR_NO_SUCCESSOR, ERR_NO_VALUE};
use crate::memorymanager::api::{get_pointer, reallocate, Arena, HyperionPointer};
use bitfield_struct::bitfield;
use std::cmp::Ordering;
use std::intrinsics::write_bytes;
use std::ptr::{null_mut, read_unaligned, write_unaligned};

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

#[bitfield(u8)]
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

#[derive(Default)]
#[repr(C)]
pub struct OperationContext {
    pub header: OperationContextHeader,
    pub chained_pointer_hook: u8,
    pub key_len_left: i32,
    pub key: Option<*mut u8>, //Option<AtomicChar>,
    pub jump_context: JumpContext,
    pub root_container_entry: Option<*mut RootContainerEntryInner>, //<Option<Box<RootContainerEntry>>,
    pub embedded_traversal_context: EmbeddedTraversalContext,
    pub jump_table_sub_context: JumpTableSubContext,
    pub next_container_pointer: Option<*mut HyperionPointer>, //Option<Box<HyperionPointer>>,
    pub arena: Option<*mut Arena>, //Option<Box<Arena>>,
    pub path_compressed_ejection_context: Option<PathCompressedEjectionContext>, //Option<PathCompressedEjectionContext>,
    pub return_value: Option<*mut NodeValue>, //Option<Box<NodeValue>>,
    pub input_value: Option<*mut NodeValue>, //Option<Box<NodeValue>>,
    pub container_injection_context: ContainerInjectionContext,
}

impl OperationContext {
    pub fn get_root_container(&mut self) -> &mut Container {
        unsafe { self.embedded_traversal_context.root_container.as_mut().expect(ERR_NO_CAST_MUT_REF) }
    }

    pub fn get_root_container_pointer(&mut self) -> *mut Container {
        self.embedded_traversal_context.root_container
    }

    pub fn get_arena(&mut self) -> &mut Arena {
        unsafe { self.arena.expect(ERR_NO_ARENA).as_mut().expect(ERR_NO_CAST_MUT_REF) }
    }

    pub fn get_root_container_hyp_pointer(&mut self) -> &mut HyperionPointer {
        unsafe { self.embedded_traversal_context.root_container_pointer.as_mut().expect(ERR_NO_CAST_MUT_REF) }
    }

    pub fn get_next_embedded_container(&mut self) -> &mut EmbeddedContainer {
        unsafe { self.embedded_traversal_context.next_embedded_container.expect(ERR_NO_NEXT_CONTAINER).as_mut().expect(ERR_NO_CAST_MUT_REF) }
    }

    pub fn get_next_embedded_container_pointer(&mut self) -> *mut EmbeddedContainer {
        self.get_next_embedded_container() as *mut EmbeddedContainer
    }

    pub fn get_next_embedded_container_offset(&mut self) -> &mut i32 {
        &mut self.embedded_traversal_context.next_embedded_container_offset
    }

    pub fn get_pc_ejection_context(&mut self) -> &mut PathCompressedEjectionContext {
        self.path_compressed_ejection_context.as_mut().expect(ERR_NO_VALUE)
    }

    pub fn get_injection_context(&mut self) -> &mut ContainerInjectionContext {
        &mut self.container_injection_context
    }

    pub fn get_injection_root_container_pointer(&mut self) -> *mut Container {
        self.container_injection_context.root_container.expect(ERR_NO_VALUE)
    }

    pub fn get_injection_root_container(&mut self) -> &mut Container {
        unsafe { self.get_injection_root_container_pointer().as_mut().expect(ERR_NO_CAST_MUT_REF) }
    }

    pub fn flush_jump_context(&mut self) {
        self.jump_context.flush()
    }

    pub fn flush_jump_table_sub_context(&mut self) {
        self.jump_table_sub_context.flush()
    }

    pub fn get_return_value_mut(&mut self) -> &mut NodeValue {
        unsafe { self.return_value.expect(ERR_NO_RETURN_VALUE).as_mut().expect(ERR_NO_CAST_MUT_REF) }
    }

    pub fn get_input_value_mut(&mut self) -> &mut NodeValue {
        unsafe { self.input_value.expect(ERR_NO_INPUT_VALUE).as_mut().expect(ERR_NO_CAST_MUT_REF) }
    }

    pub fn get_jump_context_mut(&mut self) -> &mut JumpContext {
        &mut self.jump_context
    }

    pub fn get_key_as_mut(&mut self) -> &mut u8 {
        unsafe { self.key.expect(ERR_NO_KEY).as_mut().expect(ERR_NO_CAST_MUT_REF) }
    }
}


pub fn new_expand(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, required: u32) -> *mut NodeHeader {
    let free_space_left: u32 = ocx.get_root_container().free_bytes() as u32;
    log_to_file(&format!("nex_expand: {} > {}", required, free_space_left));

    if required > free_space_left {
        let old_size: u32 = ocx.get_root_container().size();
        let new_size: u32 = ocx.get_root_container().increment_container_size((required - free_space_left) as i32);
        ocx.get_root_container().set_free_size_left(0);
        let root_container_ptr = ocx.get_root_container_pointer();

        let mut node_offset = 0;

        if let Some(top_node) = ocx.jump_table_sub_context.top_node.as_mut() {
            unsafe {
                node_offset = (*top_node as *mut u8).offset_from(root_container_ptr as *mut u8) as i32;
            }
        }
        log_to_file(&format!("inner: old: {}, new: {}, offset: {}", old_size, new_size, node_offset));

        assert_eq!(ocx.embedded_traversal_context.embedded_container_depth, 0);

        unsafe {
            *ocx.embedded_traversal_context.root_container_pointer = reallocate (
                ocx.arena.expect(ERR_NO_ARENA),
                ocx.embedded_traversal_context.root_container_pointer,
                new_size as usize,
                ocx.chained_pointer_hook,
            );
        }

        ocx.embedded_traversal_context.root_container =
            get_pointer(ocx.arena.expect(ERR_NO_ARENA), ocx.embedded_traversal_context.root_container_pointer, 1, ocx.chained_pointer_hook) as *mut Container;

        ocx.get_root_container().set_free_size_left((new_size - old_size) + free_space_left);

        let root_container_ptr = ocx.get_root_container_pointer();

        if let Some(predecessor) = ocx.jump_context.predecessor.as_mut() {
            unsafe {
                *predecessor = (root_container_ptr as *mut u8).add(ocx.jump_context.top_node_predecessor_offset_absolute as usize) as *mut NodeHeader;
            }
        }

        if node_offset > 0 {
            ocx.jump_table_sub_context.top_node = unsafe {
                Some((root_container_ptr as *mut u8).add(node_offset as usize) as *mut NodeHeader)
            };
        }
    }
    unsafe { (ocx.embedded_traversal_context.root_container as *mut u8).add(ctx.current_container_offset as usize) as *mut NodeHeader }
}

pub fn safe_sub_node_jump_table_context(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) {
    if ocx.jump_table_sub_context.top_node.as_mut().is_none() {
        return;
    }

    if as_top_node(ocx.jump_table_sub_context.top_node.expect(ERR_NO_NODE)).jump_table_present()
        && ocx.embedded_traversal_context.embedded_container_depth == 0
    {
        ocx.jump_table_sub_context.root_container_sub_char_set = true;
        ocx.jump_table_sub_context.root_container_sub_char = ctx.second_char;
    }
}

pub fn new_expand_embedded(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, required: u32) -> *mut NodeHeader {
    let free_space_left: u32 = ocx.get_root_container().free_bytes() as u32;
    log_to_file(&format!("new_expand_embedded: {} > {}", required, free_space_left));

    if required > free_space_left {
        let old_size: u32 = ocx.get_root_container().size();
        let new_size: u32 = ocx.get_root_container().increment_container_size((required - free_space_left) as i32);
        ocx.get_root_container().set_free_size_left(0);
        let root_container_ptr = ocx.get_root_container_pointer();

        let node_offset = unsafe {
            (ocx.jump_table_sub_context.top_node.expect(ERR_NO_NODE) as *mut u8).offset_from(root_container_ptr as *mut u8) as i32
        };
        log_to_file(&format!("inner: old: {}, new: {}, offset: {}", old_size, new_size, node_offset));

        let mut embedded_stack_offsets: [i32; CONTAINER_MAX_EMBEDDED_DEPTH] = [0; CONTAINER_MAX_EMBEDDED_DEPTH];

        if let Some(stack) = ocx.embedded_traversal_context.embedded_stack.as_mut() {
            for (i, container) in stack.iter_mut().enumerate().take(ocx.embedded_traversal_context.embedded_container_depth as usize).rev() {
                embedded_stack_offsets[i] = unsafe {
                    container.as_mut().expect(ERR_NO_NEXT_CONTAINER).get_as_mut_memory()
                        .offset_from(root_container_ptr as *mut u8) as i32
                };
            }
        }
        else { panic!("{}", ERR_EMPTY_EMB_STACK); }

        unsafe {
            *ocx.embedded_traversal_context.root_container_pointer = reallocate(
                ocx.get_arena(),
                ocx.get_root_container_hyp_pointer(),
                new_size as usize,
                ocx.chained_pointer_hook,
            );
        }

        ocx.embedded_traversal_context.root_container =
            get_pointer(ocx.get_arena(), ocx.get_root_container_hyp_pointer(), 1, ocx.chained_pointer_hook) as *mut Container;

        unsafe {
            let p_new: *mut u8 = (ocx.get_root_container_pointer() as *mut u8).add(old_size as usize);
            write_bytes(p_new, 0, (new_size - old_size) as usize);
            ocx.embedded_traversal_context.next_embedded_container = Some(
                (ocx.embedded_traversal_context.root_container as *mut u8).add(ocx.embedded_traversal_context.next_embedded_container_offset as usize) as *mut EmbeddedContainer
            );
        }

        ocx.get_root_container().set_free_size_left((new_size - old_size) + free_space_left);
        let root_container_ptr = ocx.embedded_traversal_context.root_container;

        if let Some(stack) = ocx.embedded_traversal_context.embedded_stack.as_mut() {
            for (i, container) in stack.iter_mut().enumerate().take(ocx.embedded_traversal_context.embedded_container_depth as usize).rev() {
                *container = Some(AtomicEmbContainer::new_from_pointer(
                    unsafe { (root_container_ptr as *mut u8).add(embedded_stack_offsets[i] as usize) as *mut EmbeddedContainer }
                ));
            }
        }
        else { panic!("{}", ERR_EMPTY_EMB_STACK); }

        if let Some(predecessor) = ocx.jump_context.predecessor.as_mut() {
            unsafe {
                *predecessor = (root_container_ptr as *mut u8)
                    .add(ocx.jump_context.top_node_predecessor_offset_absolute as usize) as *mut NodeHeader;
            }
        }

        if node_offset > 0 {
            unsafe {
                ocx.jump_table_sub_context.top_node = Some(
                    (root_container_ptr as *mut u8).add(node_offset as usize) as *mut NodeHeader,
                );
            }
        }
    }

    unsafe {
        (ocx.embedded_traversal_context.root_container as *mut u8)
            .add(ctx.current_container_offset as usize + ocx.embedded_traversal_context.next_embedded_container_offset as usize)
            as *mut NodeHeader
    }
}

pub fn insert_jump(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, jump_value: u16) -> *mut NodeHeader {
    log_to_file(&format!("insert_jump jump_value: {}", jump_value));
    new_expand(ocx, ctx, size_of::<NodeValue>() as u32);

    let node_head: *mut NodeHeader = unsafe {
        (ocx.get_root_container_pointer() as *mut u8)
            .add(ocx.jump_context.top_node_predecessor_offset_absolute as usize) as *mut NodeHeader
    };

    assert!(ocx.jump_context.top_node_predecessor_offset_absolute > 0);
    assert_eq!(as_top_node(node_head).container_type(), NodeState::TopNode);

    let free_size_left: usize = ocx.get_root_container().free_bytes() as usize;
    let node_offset_to_jump: usize = get_offset_jump(node_head);
    let shift_amount = ocx.get_root_container().size() as usize
        - (free_size_left + node_offset_to_jump + ocx.jump_context.top_node_predecessor_offset_absolute as usize);

    unsafe {
        let target: *mut u16 = (node_head as *mut u8).add(node_offset_to_jump) as *mut u16;
        shift_container(target as *mut u8, size_of::<u16>(), shift_amount);

        as_top_node_mut(node_head).set_jump_successor_present(true);
        let target = (node_head as *mut u8).add(get_offset_jump(node_head)) as *mut u16;
        let current_value = read_unaligned(target);
        log_to_file(&format!("before jump_insert: {}", current_value));
        write_unaligned(target, current_value + jump_value);
        log_to_file(&format!("after jump_insert: {}", read_unaligned(target)));
        update_space_usage(size_of::<u16>() as i16, ocx, ctx);
        ctx.current_container_offset += size_of::<u16>() as i32;
        (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset as usize) as *mut NodeHeader
    }
}

pub fn meta_expand(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, required: u32) -> *mut NodeHeader {
    if ocx.embedded_traversal_context.embedded_container_depth == 0 {
        return new_expand(ocx, ctx, required);
    }
    new_expand_embedded(ocx, ctx, required)
}

pub fn scan_put_embedded(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) -> ReturnCode {
    ctx.header.set_node_type(1);

    loop {
        let mut node_header: *mut NodeHeader = unsafe {
            (ocx.embedded_traversal_context.next_embedded_container.expect(ERR_NO_NEXT_CONTAINER) as *mut u8).add(ctx.current_container_offset as usize) as *mut NodeHeader
        };

        if ctx.current_container_offset >= unsafe { (*(ocx.embedded_traversal_context.next_embedded_container.expect(ERR_NO_NEXT_CONTAINER))).size() as i32 } {
            ctx.header.set_node_type(0);
        }

        match ctx.as_combined_header() {
            EmptyOneCharTopNode => {
                let key_delta_top = ctx.key_delta_top();
                create_node(node_header, ocx, ctx, NodeState::TopNode, key_delta_top == 0, true, key_delta_top, true);
                return OK;
            },
            FilledOneCharTopNode => {
                if as_top_node(node_header).container_type() == NodeState::TopNode {
                    let key = get_top_node_key(node_header as *mut Node, ctx);

                    match key.cmp(&ctx.first_char) {
                        Ordering::Less => {
                            ctx.header.set_last_top_char_set(true);
                            ctx.last_top_char_seen = key;
                        }
                        Ordering::Equal => {
                            return handle_embedded_expand(ocx, ctx, node_header);
                        }
                        Ordering::Greater => {
                            ctx.header.set_force_shift_before_insert(true);
                            ctx.header.set_in_first_char_scope(true);
                            let key_delta_top = ctx.key_delta_top();
                            create_node(node_header, ocx, ctx, NodeState::TopNode, key_delta_top == 0, true, key_delta_top, true);
                            return OK;
                        }
                    }
                    ctx.current_container_offset += get_offset_top_node(node_header) as i32;
                    log_to_file(&format!("scan_put_embedded (top) set current container offset to {}", ctx.current_container_offset));
                    continue;
                }
                ctx.current_container_offset += get_offset_sub_node(node_header) as i32;
                log_to_file(&format!("scan_put_embedded (sub) set current container offset to {}", ctx.current_container_offset));
                continue;
            },
            EmptyTwoCharTopNode => {
                let key_delta_top = ctx.key_delta_top();
                node_header = create_node(node_header, ocx, ctx, NodeState::TopNode, key_delta_top == 0, false, key_delta_top, true);
                ctx.header.set_in_first_char_scope(true);
                ctx.current_container_offset += get_offset_top_node(node_header) as i32;
                log_to_file(&format!("scan_put_embedded set current container offset to {}", ctx.current_container_offset));
            },
            FilledTwoCharTopNode => {
                if as_top_node(node_header).container_type() == NodeState::TopNode {
                    let key = get_top_node_key(node_header as *mut Node, ctx);

                    match key.cmp(&ctx.first_char) {
                        Ordering::Less => {
                            ctx.header.set_last_top_char_set(true);
                            ctx.last_top_char_seen = key;
                        }
                        Ordering::Equal => {
                            ctx.header.set_in_first_char_scope(true);
                        }
                        Ordering::Greater => {
                            ctx.header.set_force_shift_before_insert(true);
                            ctx.header.set_in_first_char_scope(true);
                            let key_delta_top = ctx.key_delta_top();
                            node_header = create_node(node_header, ocx, ctx, NodeState::TopNode, key_delta_top == 0, false, key_delta_top, true);
                        }
                    }
                    ctx.current_container_offset += get_offset_top_node(node_header) as i32;
                    log_to_file(&format!("scan_put_embedded (top) set current container offset to {}", ctx.current_container_offset));
                    continue;
                }
                ctx.current_container_offset += get_offset_sub_node(node_header) as i32;
                log_to_file(&format!("scan_put_embedded (sub) set current container offset to {}", ctx.current_container_offset));
                continue;
            },
            EmptyTwoCharTopNodeInFirstCharScope => {
                let key_delta_sub = ctx.key_delta_sub();
                create_node(node_header, ocx, ctx, NodeState::SubNode, key_delta_sub == 0, ctx.header.end_operation(), key_delta_sub, true);
                return OK;
            },
            FilledTwoCharTopNodeInFirstCharScope => {
                if as_top_node(node_header).container_type() == NodeState::SubNode {
                    let key = get_sub_node_key(node_header as *mut Node, ctx, false);

                    match key.cmp(&ctx.second_char) {
                        Ordering::Less => {
                            ctx.header.set_last_sub_char_set(true);
                            ctx.last_sub_char_seen = key;
                            ctx.current_container_offset += get_offset_sub_node(node_header) as i32;
                            log_to_file(&format!("scan_put_embedded set current container offset to {}", ctx.current_container_offset));
                            continue;
                        }
                        Ordering::Equal => {
                            return if ctx.header.end_operation() {
                                handle_embedded_expand(ocx, ctx, node_header)
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
                                    get_child_container_pointer(node_header, ocx, ctx, true);
                                }
                                OK
                            }
                        }
                        Ordering::Greater => {
                            ctx.header.set_force_shift_before_insert(true);
                            let key_delta_sub = ctx.key_delta_sub();
                            create_node(node_header, ocx, ctx, NodeState::SubNode, key_delta_sub == 0, ctx.header.end_operation(), key_delta_sub, true);
                            return OK;
                        }
                    }
                } else {
                    ctx.header.set_force_shift_before_insert(true);
                    let key_delta_sub = ctx.key_delta_sub();
                    create_node(node_header, ocx, ctx, NodeState::SubNode, key_delta_sub == 0, ctx.header.end_operation(), key_delta_sub, true);
                    return OK;
                }
            },
            _ => {
                return UnknownOperation;
            },
        }
    }
}

fn handle_embedded_expand(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, mut node_header: *mut NodeHeader) -> ReturnCode {
    if as_top_node(node_header).type_flag() != LeafNodeWithValue && ocx.input_value.is_some() {
        node_header = new_expand_embedded(ocx, ctx, size_of::<NodeValue>() as u32);
        let target: *mut u8 = unsafe { (node_header as *mut u8).add(get_offset_node_value(node_header)) };
        unsafe { wrap_shift_container(ocx.get_root_container_pointer(), target, size_of::<NodeValue>()); }
        update_space_usage(size_of::<NodeValue>() as i16, ocx, ctx);
    }
    set_node_value(node_header, ocx)
}

pub fn scan_put_single(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) -> ReturnCode {
    let mut node_head: *mut NodeHeader = null_mut();
    let mut key = 0;
    let mut jump_point = NoJump;

    ctx.safe_offset = ocx.get_root_container().size() as i32 - ocx.get_root_container().free_bytes() as i32;

    initialize_data_for_scan(ocx, ctx, node_head, &mut key, &mut jump_point);

    loop {
        let key_delta_top = if ctx.header.last_top_char_set() && ((ctx.first_char - ctx.last_top_char_seen) as usize) <= KEY_DELTA_STATES {
            ctx.first_char - ctx.last_top_char_seen
        }
        else { 0 };

        match jump_point {
            NoJump => {
                node_head = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset as usize) as *mut NodeHeader };

                if ctx.safe_offset > ctx.current_container_offset {
                    jump_point = JumpPoint1;
                    continue;
                }

                if ctx.current_container_offset >= ocx.get_root_container().size() as i32 || as_top_node(node_head).type_flag() == Invalid {
                    ocx.jump_context.top_node_key = ctx.first_char as i32;
                    create_node(node_head, ocx, ctx, NodeState::TopNode, key_delta_top == 0, true, key_delta_top, false);
                    return OK;
                }
                jump_point = JumpPoint1;
                continue;
            },
            JumpPoint1 => {
                jump_point = NoJump;
                if as_top_node(node_head).container_type() == NodeState::TopNode {
                    key = get_top_node_key(node_head as *mut Node, ctx);
                    jump_point = JumpPoint2;
                    continue;
                }
                ocx.jump_context.sub_nodes_seen += 1;
                ctx.current_container_offset += get_offset_sub_node(node_head) as i32;
            },
            JumpPoint2 => {
                ocx.jump_context.top_node_key = key as i32;

                match key.cmp(&ctx.first_char) {
                    Ordering::Less => {
                        ctx.header.set_last_top_char_set(true);
                        ctx.last_top_char_seen = key;
                    }
                    Ordering::Equal => {
                        register_jump_context(node_head, ctx, ocx);
                        return handle_expand(ocx, ctx, node_head);
                    }
                    Ordering::Greater => {
                        ocx.jump_context.predecessor = None;
                        ctx.header.set_force_shift_before_insert(true);
                        create_node(node_head, ocx, ctx, NodeState::TopNode, key_delta_top == 0, true, key_delta_top, false);
                        return OK;
                    }
                }

                if as_top_node(node_head).jump_successor_present() {
                    ctx.current_container_offset = get_jump_value(node_head) as i32;
                } else {
                    ctx.current_container_offset += get_offset_top_node(node_head) as i32;
                }
                ocx.jump_context.predecessor = Some(node_head);
                ocx.jump_context.top_node_predecessor_offset_absolute =
                    unsafe { (node_head as *mut u8).offset_from(ocx.get_root_container_pointer() as *mut u8) as i32 };
                ocx.jump_context.sub_nodes_seen = 0;
                jump_point = NoJump;
                continue;
            },
        }
    }
}

pub fn initialize_data_for_scan(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, mut node_head: *mut NodeHeader, key: &mut u8, jump_point: &mut JumpStates) {
    if ocx.get_root_container().jump_table() == 0 {
        ctx.current_container_offset = ocx.get_root_container().get_container_head_size();
    } else {
        *key = ocx.get_root_container().get_offset_with_jump_table(ctx.first_char, &mut ctx.current_container_offset);
        node_head = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset as usize) as *mut NodeHeader };

        if *key != 0 {
            *jump_point = JumpPoint2;
        }
    }
}

fn handle_expand(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, mut node_head: *mut NodeHeader) -> ReturnCode {
    if as_top_node(node_head).type_flag() != LeafNodeWithValue && ocx.input_value.is_some() {
        node_head = new_expand(ocx, ctx, size_of::<NodeValue>() as u32);
        unsafe {
            wrap_shift_container(ocx.get_root_container_pointer(), (node_head as *mut u8).add(get_offset_node_value(node_head)), size_of::<NodeValue>());
        }
        update_space_usage(size_of::<NodeValue>() as i16, ocx, ctx);
    }
    set_node_value(node_head, ocx)
}

pub fn scan_put_phase2(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) -> ReturnCode {
    let mut jump_point = NoJump;

    ctx.safe_offset = ocx.get_root_container().size() as i32 - ocx.get_root_container().free_bytes() as i32;
    log_to_file(&format!("scan_put_phase2 set safe offset to {}", ctx.safe_offset));

    let mut node_head = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset as usize) as *mut NodeHeader };

    loop {
        match jump_point {
            NoJump => {
                assert!(ctx.safe_offset > 0);

                if ctx.safe_offset > ctx.current_container_offset {
                    jump_point = JumpPoint1;
                    continue;
                }

                if ctx.current_container_offset >= ocx.get_root_container().size() as i32 || as_top_node(node_head).type_flag() == Invalid {
                    ctx.header.set_node_type(0);
                    let key_delta_sub = ctx.key_delta_sub();
                    create_node(node_head, ocx, ctx, NodeState::SubNode, key_delta_sub == 0, ctx.header.end_operation(), key_delta_sub, false);
                    return OK;
                }

                jump_point = JumpPoint1;
                continue;
            },
            JumpPoint1 => {
                jump_point = NoJump;
                if as_top_node(node_head).container_type() == NodeState::SubNode {
                    let key = get_sub_node_key(node_head as *mut Node, ctx, false);
                    log_to_file(&format!("scan_put_phase2 found key {}", key));

                    match key.cmp(&ctx.second_char) {
                        Ordering::Less => {
                            ctx.current_container_offset += get_offset_sub_node(node_head) as i32;
                            node_head =
                                unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset as usize) as *mut NodeHeader };
                            ctx.header.set_last_sub_char_set(true);
                            ctx.last_sub_char_seen = key;
                            ocx.jump_context.sub_nodes_seen += 1;

                            if ocx.jump_context.sub_nodes_seen >= SUBLEVEL_JUMPTABLE_HWM as i32 {
                                create_sublevel_jumptable(ocx.jump_table_sub_context.top_node.expect(ERR_NO_NODE), ocx, ctx);
                                ctx.flush();
                                ocx.flush_jump_context();
                                ocx.flush_jump_table_sub_context();
                                ctx.current_container_offset = ocx.get_root_container().get_container_head_size();
                                log_to_file(&format!("scan_put_phase2 set current container offset to {}", ctx.current_container_offset));
                                return scan_put(ocx, ctx);
                            }
                        }
                        Ordering::Equal => {
                            return handle_equal_keys(ocx, ctx, node_head);
                        }
                        Ordering::Greater => {
                            ctx.header.set_force_shift_before_insert(true);
                            if ctx.header.last_sub_char_set() && (ctx.second_char - ctx.last_sub_char_seen) as usize <= KEY_DELTA_STATES {
                                create_node(node_head, ocx, ctx, NodeState::SubNode, false, ctx.header.end_operation(), ctx.second_char - ctx.last_sub_char_seen, false);
                            } else {
                                if !ctx.header.last_sub_char_set() {
                                    ctx.header.set_last_sub_char_set(true);
                                    ctx.last_sub_char_seen = 0;
                                }
                                create_node(node_head, ocx, ctx, NodeState::SubNode, true, ctx.header.end_operation(), 0, false);
                            }
                            return OK;
                        }
                    }
                } else {
                    ctx.header.set_force_shift_before_insert(true);
                    let key_delta_sub = ctx.key_delta_sub();
                    create_node(node_head, ocx, ctx, NodeState::SubNode, key_delta_sub == 0, ctx.header.end_operation(), key_delta_sub, false);
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
    log_to_file("scan_put_phase2_withjt");
    let mut key = destination;
    let mut jump_point = NoJump;

    ctx.safe_offset = ocx.get_root_container().size() as i32 - ocx.get_root_container().free_bytes() as i32;

    let mut node_head = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset as usize) as *mut NodeHeader };

    if key != 0 {
        jump_point = JumpPoint2;
    }

    loop {
        let key_delta_sub = if ctx.header.last_sub_char_set() && ((ctx.second_char - ctx.last_sub_char_seen) as usize) <= KEY_DELTA_STATES {
            ctx.second_char - ctx.last_sub_char_seen
        }
        else { 0 };

        match jump_point {
            NoJump => {
                if ctx.safe_offset > ctx.current_container_offset {
                    jump_point = JumpPoint1;
                    continue;
                }

                if ctx.current_container_offset >= ocx.get_root_container().size() as i32 || as_top_node(node_head).type_flag() == Invalid {
                    ctx.header.set_node_type(0);
                    create_node(node_head, ocx, ctx, NodeState::SubNode, key_delta_sub == 0, ctx.header.end_operation(), key_delta_sub, false);
                    return OK;
                }
                jump_point = JumpPoint1;
                continue;
            },
            JumpPoint1 => {
                if as_top_node(node_head).container_type() == NodeState::SubNode {
                    key = get_sub_node_key(node_head as *mut Node, ctx, false);
                    jump_point = JumpPoint2;
                    continue;
                } else {
                    ctx.header.set_force_shift_before_insert(true);
                    create_node(node_head, ocx, ctx, NodeState::SubNode, key_delta_sub == 0, ctx.header.end_operation(), key_delta_sub, false);
                    return OK;
                }
            },
            JumpPoint2 => {
                jump_point = NoJump;

                match key.cmp(&ctx.second_char) {
                    Ordering::Less => {
                        ctx.current_container_offset += get_offset_sub_node(node_head) as i32;
                        node_head =
                            unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset as usize) as *mut NodeHeader };
                        ctx.header.set_last_sub_char_set(true);
                        ctx.last_sub_char_seen = key;
                    }
                    Ordering::Equal => {
                        return handle_equal_keys(ocx, ctx, node_head);
                    }
                    Ordering::Greater => {
                        ctx.header.set_force_shift_before_insert(true);
                        create_node(node_head, ocx, ctx, NodeState::SubNode, key_delta_sub == 0, ctx.header.end_operation(), key_delta_sub, false);
                        return OK;
                    }
                }
            }
        }
    }
}

fn handle_equal_keys(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, mut node_head: *mut NodeHeader) -> ReturnCode {
    if ctx.header.end_operation() {
        handle_expand(ocx, ctx, node_head);
    } else {
        match as_sub_node(node_head).child_container() {
            ChildLinkType::None => {
                node_head = embed_or_link_child(node_head, ocx, ctx);
            },
            PathCompressed => {
                if compare_path_compressed_node(node_head, ocx) {
                    node_head = update_path_compressed_node(node_head, ocx, ctx);
                } else {
                    safe_path_compressed_context(node_head, ocx);
                    node_head = embed_or_link_child(node_head, ocx, ctx);
                }
            },
            _ => {
                get_child_container_pointer(node_head, ocx, ctx, true);
            },
        }
    }
    OK
}


pub fn scan_put(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) -> ReturnCode {
    let mut node_head: *mut NodeHeader = null_mut();
    let mut toplevel_nodes = TOPLEVEL_NODE_JUMP_HWM as i32;
    let mut jump_point = NoJump;

    ctx.safe_offset = ocx.get_root_container().size() as i32 - ocx.get_root_container().free_bytes() as i32;
    log_to_file(&format!("scan_put set safe offset to {}", ctx.safe_offset));

    if ocx.get_root_container().jump_table() != 0 {
        if (ocx.get_root_container().jump_table() as usize) < TOPLEVEL_JUMPTABLE_INCREMENTS {
            toplevel_nodes = TOPLEVEL_AGGRESSIVE_GROWTH__HWM as i32;
        }

        ocx.jump_context.top_node_key = ocx.get_root_container().get_offset_with_jump_table(ctx.first_char, &mut ctx.current_container_offset) as i32;

        if ocx.jump_context.top_node_key != 0 {
            node_head = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset as usize) as *mut NodeHeader };
            jump_point = JumpPoint2;
        }
    }

    loop {
        match jump_point {
            NoJump => {
                node_head = unsafe { (ocx.embedded_traversal_context.root_container as *mut u8).add(ctx.current_container_offset as usize) as *mut NodeHeader };

                if ctx.safe_offset <= ctx.current_container_offset {
                    ocx.jump_context.top_node_key = ctx.first_char as i32;
                    let key_delta_top = ctx.key_delta_top();
                    node_head = create_node(node_head, ocx, ctx, NodeState::TopNode, key_delta_top == 0, false, key_delta_top, false);
                    ctx.current_container_offset += get_offset_top_node(node_head) as i32;
                    log_to_file(&format!("scan_put set current container offset to {}", ctx.current_container_offset));
                    node_head = unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset as usize) as *mut NodeHeader };
                    create_node(node_head, ocx, ctx, NodeState::SubNode, true, ctx.header.end_operation(), ctx.second_char, false);
                    return OK;
                }

                if as_top_node(node_head).container_type() == NodeState::SubNode {
                    ocx.jump_context.sub_nodes_seen += 1;
                    ctx.current_container_offset += get_offset_sub_node(node_head) as i32;
                    log_to_file(&format!("scan_put set current container offset to {}", ctx.current_container_offset));
                    /*node_head =
                        unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset as usize) as *mut NodeHeader };*/
                    jump_point = NoJump;
                    continue;
                }
                jump_point = JumpPoint1;
                continue;
            },
            JumpPoint1 => {
                if toplevel_nodes == 0 && (ocx.get_root_container().size() as usize) > CONTAINER_SIZE_TYPE_0 * 4 {
                    insert_top_level_jump_table(ocx, ctx);
                    ctx.flush();
                    ocx.flush_jump_context();
                    ocx.flush_jump_table_sub_context();
                    return scan_put(ocx, ctx);
                }
                ocx.jump_context.top_node_key = get_top_node_key(node_head as *mut Node, ctx) as i32;
                jump_point = JumpPoint2;
                continue;
            },
            JumpPoint2 => {
                toplevel_nodes -= 1;

                match ocx.jump_context.top_node_key.cmp(&(ctx.first_char as i32)) {
                    Ordering::Less => {
                        ctx.header.set_last_top_char_set(true);
                        ctx.last_top_char_seen = ocx.jump_context.top_node_key as u8;

                        let ret = handle_insert_jump(ocx, ctx, node_head);
                        node_head = ret;
                        ocx.jump_context.sub_nodes_seen = 0;

                        if as_top_node(node_head).jump_successor_present() {
                            ctx.current_container_offset += get_jump_value(node_head) as i32;
                            log_to_file(&format!("scan_put set current container offset to {}", ctx.current_container_offset));
                            ocx.jump_context.predecessor = Some(node_head);
                            ocx.jump_context.top_node_predecessor_offset_absolute =
                                unsafe { (node_head as *mut u8).offset_from(ocx.get_root_container_pointer() as *mut u8) as i32 };
                            node_head =
                                unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset as usize) as *mut NodeHeader };
                            jump_point = JumpPoint1;
                            continue;
                        }

                        ocx.jump_context.predecessor = Some(node_head);
                        ocx.jump_context.top_node_predecessor_offset_absolute =
                            unsafe { (node_head as *mut u8).offset_from(ocx.get_root_container_pointer() as *mut u8) as i32 };
                        ctx.current_container_offset += get_offset_top_node(node_head) as i32;
                        log_to_file(&format!("scan_put set current container offset to {}", ctx.current_container_offset));
                        /*node_head =
                            unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset as usize) as *mut NodeHeader };*/
                        jump_point = NoJump;
                    }
                    Ordering::Equal => {
                        ctx.header.set_in_first_char_scope(true);
                        let ret = handle_insert_jump(ocx, ctx, node_head);
                        node_head = ret;
                        ocx.jump_table_sub_context.top_node = Some(node_head);
                        ocx.jump_context.top_node_predecessor_offset_absolute =
                            unsafe { (node_head as *mut u8).offset_from(ocx.get_root_container_pointer() as *mut u8) as i32 };
                        ocx.jump_context.sub_nodes_seen = 0;
                        ocx.jump_context.predecessor = Some(node_head);

                        if as_top_node(node_head).jump_table_present() {
                            let destination = use_sub_node_jump_table(node_head, ctx);
                            return scan_put_phase2_withjt(ocx, ctx, destination);
                        }
                        ctx.current_container_offset += get_offset(node_head) as i32;
                        log_to_file(&format!("scan_put set current container offset to {}", ctx.current_container_offset));
                        return scan_put_phase2(ocx, ctx);
                    }
                    Ordering::Greater => {
                        ctx.header.set_force_shift_before_insert(true);
                        ocx.flush_jump_context();
                        let key_delta_top = ctx.key_delta_top();
                        node_head = create_node(node_head, ocx, ctx, NodeState::TopNode, key_delta_top == 0, false, key_delta_top, false);
                        ctx.current_container_offset += get_offset_top_node(node_head) as i32;
                        log_to_file(&format!("scan_put set current container offset to {}", ctx.current_container_offset));
                        node_head =
                            unsafe { (ocx.get_root_container_pointer() as *mut u8).add(ctx.current_container_offset as usize) as *mut NodeHeader };
                        create_node(node_head, ocx, ctx, NodeState::SubNode, true, ctx.header.end_operation(), ctx.second_char, false);
                        return OK;
                    }
                }
            },
        }
    }
}

fn handle_insert_jump(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext, node_head: *mut NodeHeader) -> *mut NodeHeader {
    if ocx.jump_context.sub_nodes_seen > (GLOBAL_CONFIG.read().top_level_successor_threshold as i32) {
        let jump_value = unsafe {
            ((node_head as *mut u8).offset_from(ocx.get_root_container_pointer() as *mut u8) as u16)
                - ocx.jump_context.top_node_predecessor_offset_absolute as u16
        };
        return insert_jump(ocx, ctx, jump_value);
    }
    node_head
}

pub fn insert_top_level_jump_table(ocx: &mut OperationContext, ctx: &mut ContainerTraversalContext) {
    log_to_file("insert_top_level_jump_table");
    let mut node_cache: Node = Node {
        header: NodeHeader::new_top_node(TopNode::default()),
        stored_value: 0,
    };

    let mut found_keys: [u8; 256] = [0; 256];
    let mut found_offsets: [u32; 256] = [0; 256];
    let mut found: usize = 0;
    let mut required_max = 0;

    let mut tmp_ctx = ContainerTraversalContext::default();
    tmp_ctx.header.set_last_top_char_set(false);
    tmp_ctx.current_container_offset = ocx.get_root_container().get_container_head_size() + ocx.get_root_container().get_jump_table_size();

    let successor: *mut Node = &mut node_cache;

    let mut node_head = unsafe {
        (ocx.get_root_container_pointer() as *mut u8).add(tmp_ctx.current_container_offset as usize) as *mut NodeHeader
    };

    while (ocx.get_root_container().size() as i32) > tmp_ctx.current_container_offset {
        if as_top_node(node_head).type_flag() == Invalid {
            break;
        }

        ocx.jump_context.top_node_key = get_top_node_key(node_head as *mut Node, &mut tmp_ctx) as i32;
        found_keys[found] = ocx.jump_context.top_node_key as u8;
        found_offsets[found] = tmp_ctx.current_container_offset as u32;
        tmp_ctx.last_top_char_seen = ocx.jump_context.top_node_key as u8;
        tmp_ctx.header.set_last_top_char_set(true);

        let mut successor_ptr: Option<*mut Node> = Some(successor);
        let skipped = get_successor(node_head, &mut successor_ptr, ocx, &mut tmp_ctx, false);

        if skipped == 0 {
            break; // No successor
        }

        tmp_ctx.current_container_offset += skipped as i32;
        found += 1;

        if let Some(successor) = successor_ptr {
            node_head = unsafe { &mut (*successor).header };
        }
        else { panic!("{}", ERR_NO_SUCCESSOR); }
    }

    if found < TOPLEVEL_JUMPTABLE_ENTRIES {
        return;
    }

    let current_jump_table_value = ocx.get_root_container().jump_table();
    let max_increment = TOPLEVEL_JUMPTABLE_INCREMENTS - current_jump_table_value as usize;
    let mut increment = (found / TOPLEVEL_JUMPTABLE_ENTRIES) - current_jump_table_value as usize;

    if (current_jump_table_value < (TOPLEVEL_JUMPTABLE_INCREMENTS as u8))
        && (found >= (current_jump_table_value as usize * TOPLEVEL_JUMPTABLE_ENTRIES + TOPLEVEL_JUMPTABLE_ENTRIES))
    {
        ocx.flush_jump_context();

        if increment <= 1 {
            increment = 1;
        } else if (increment + current_jump_table_value as usize) > TOPLEVEL_JUMPTABLE_INCREMENTS {
            increment = max_increment;
        }

        required_max = size_of::<SubNodeJumpTable>() * increment;
        let free_size_left = ocx.get_root_container().free_bytes() as i32;
        let container_head_size = ocx.get_root_container().get_container_head_size();
        let bytes_to_move = ocx.get_root_container().size() as i32 - (container_head_size + free_size_left);

        if (free_size_left as usize) < required_max {
            new_expand(ocx, ctx, required_max as u32);
        }

        let target = unsafe {
            (ocx.get_root_container_pointer() as *mut u8).add(container_head_size as usize)
        };
        unsafe { shift_container(target, required_max, bytes_to_move as usize) };
        ocx.embedded_traversal_context.embedded_container_depth = 0;
        update_space_usage(required_max as i16, ocx, ctx);
        ocx.get_root_container().set_jump_table(current_jump_table_value + increment as u8);
    }

    let items = TOPLEVEL_JUMPTABLE_ENTRIES * ocx.get_root_container().jump_table() as usize;
    let interval: f32 = (found as f32) / (items as f32);
    assert!(interval < TOPLEVEL_NODE_JUMP_HWM as f32);
    let mut jump_table_entry = ocx.get_root_container().get_jump_table_pointer();

    for i in 0..items {
        let tmp = (interval + interval * i as f32).floor() as usize;
        unsafe {
            (*jump_table_entry).set_key(found_keys[tmp]);
            (*jump_table_entry).set_offset(found_offsets[tmp] + required_max as u32);
            jump_table_entry = jump_table_entry.add(1);
        }
    }
}