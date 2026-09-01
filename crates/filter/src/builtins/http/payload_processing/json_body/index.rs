// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Compile-time trie index for JSON Pointer operations.

use std::collections::HashMap;

use smallvec::SmallVec;

use super::{
    config::{CompiledOp, OpKind},
};

// -----------------------------------------------------------------------------
// Path tokens
// -----------------------------------------------------------------------------

/// One segment of the walk path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum PathToken {
    /// Object member key (unescaped or decoded).
    Key(String),
    /// Array index.
    Index(usize),
}

/// Whether `path` equals decoded pointer `tokens`.
pub(super) fn path_eq_tokens(path: &[PathToken], tokens: &[String]) -> bool {
    if path.len() != tokens.len() {
        return false;
    }
    path.iter().zip(tokens).all(|(segment, token)| match segment {
        PathToken::Key(key) => key == token,
        PathToken::Index(idx) => array_index(token) == Some(*idx),
    })
}

// -----------------------------------------------------------------------------
// Trie
// -----------------------------------------------------------------------------

/// Trie node id.
type NodeId = u32;

/// One node in the compiled pointer trie.
#[derive(Clone, Debug, Default)]
struct PathNode {
    /// Any op extends strictly beyond this prefix.
    nested: bool,
    /// Extract op index at exactly this path.
    extract_idx: Option<u32>,
    /// Mutating op index at exactly this path.
    mutate_idx: Option<u32>,
    /// Any extract op passes through this prefix.
    extract_branch: bool,
    object_children: HashMap<String, NodeId>,
    array_children: HashMap<usize, NodeId>,
    array_append: Option<u32>,
}

/// Precompiled lookup structure for pointer ops.
#[derive(Clone, Debug)]
pub(super) struct OpPathIndex {
    nodes: Vec<PathNode>,
    /// Extract op indices in config order.
    extract_indices: SmallVec<[u32; 8]>,
}

/// RFC 6901 array index: unsigned integer with no leading zeros (`0` allowed).
pub(super) fn array_index(token: &str) -> Option<usize> {
    if token.is_empty() || (token.starts_with('0') && token.len() > 1) {
        return None;
    }
    if !token.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    token.parse().ok()
}

impl OpPathIndex {
    /// Build a trie from compiled ops.
    pub(super) fn build(ops: &[CompiledOp]) -> Self {
        let mut nodes = vec![PathNode::default()];
        let mut extract_indices = SmallVec::new();

        for (idx, op) in ops.iter().enumerate() {
            let idx_u32 = u32::try_from(idx).unwrap_or(u32::MAX);
            if op.kind == OpKind::Extract {
                extract_indices.push(idx_u32);
            }

            if op.tokens.is_empty() {
                let node = &mut nodes[0];
                if op.kind == OpKind::Extract {
                    node.extract_idx = Some(idx_u32);
                    node.extract_branch = true;
                } else if op.kind.is_mutating() {
                    node.mutate_idx = Some(idx_u32);
                }
                continue;
            }

            let mut node_id = 0u32;
            for (depth, token) in op.tokens.iter().enumerate() {
                let is_last = depth + 1 == op.tokens.len();

                if token == "-" {
                    if is_last && op.kind == OpKind::Add {
                        nodes[node_id as usize].array_append = Some(idx_u32);
                    }
                    break;
                }

                let parent_idx = node_id;
                node_id = if let Some(child_idx) = array_index(token) {
                    if let Some(&child) = nodes[parent_idx as usize].array_children.get(&child_idx) {
                        child
                    } else {
                        let child = u32::try_from(nodes.len()).unwrap_or(0);
                        nodes.push(PathNode::default());
                        nodes[parent_idx as usize].array_children.insert(child_idx, child);
                        child
                    }
                } else if let Some(&child) = nodes[parent_idx as usize].object_children.get(token) {
                    child
                } else {
                    let child = u32::try_from(nodes.len()).unwrap_or(0);
                    nodes.push(PathNode::default());
                    nodes[parent_idx as usize]
                        .object_children
                        .insert(token.clone(), child);
                    child
                };

                let parent = &mut nodes[parent_idx as usize];
                if !is_last {
                    parent.nested = true;
                }
                if op.kind == OpKind::Extract {
                    parent.extract_branch = true;
                }

                if is_last {
                    let node = &mut nodes[node_id as usize];
                    match op.kind {
                        OpKind::Extract => node.extract_idx = Some(idx_u32),
                        OpKind::Add | OpKind::Replace | OpKind::Remove => node.mutate_idx = Some(idx_u32),
                    }
                }
            }
        }

        Self {
            nodes,
            extract_indices,
        }
    }

    /// Extract op indices for this direction.
    pub(super) fn extract_indices(&self) -> &[u32] {
        self.extract_indices.as_slice()
    }

    /// Whether any extract op might match `path` or extend beyond it.
    pub(super) fn extract_branch_at(&self, path: &[PathToken]) -> bool {
        let node = self.node_at(path);
        node.extract_branch || node.extract_idx.is_some()
    }

    /// Whether any op is nested strictly under `path`, or targets a direct child.
    pub(super) fn has_descendant_ops(&self, path: &[PathToken]) -> bool {
        let node = self.node_at(path);
        node.nested
            || node.mutate_idx.is_some()
            || node.extract_idx.is_some()
            || !node.object_children.is_empty()
            || !node.array_children.is_empty()
            || node.array_append.is_some()
    }

    /// Whether `rewrite_value` must run for object child `key`.
    pub(super) fn child_needs_rewrite(&self, path: &[PathToken], key: &str) -> bool {
        match self.child_object_node(path, key) {
            Some(node_id) => Self::node_has_work(&self.nodes[node_id as usize]),
            None => false,
        }
    }

    /// Whether `rewrite_value` must run for array element `idx`.
    pub(super) fn child_index_needs_rewrite(&self, path: &[PathToken], idx: usize) -> bool {
        match self.child_array_node(path, idx) {
            Some(node_id) => Self::node_has_work(&self.nodes[node_id as usize]),
            None => false,
        }
    }

    fn node_has_work(node: &PathNode) -> bool {
        node.nested
            || node.mutate_idx.is_some()
            || node.extract_idx.is_some()
            || !node.object_children.is_empty()
            || !node.array_children.is_empty()
            || node.array_append.is_some()
    }

    /// Extract op index at exactly `path`.
    pub(super) fn extract_at(&self, path: &[PathToken]) -> Option<u32> {
        self.node_at(path).extract_idx
    }

    /// Mutating op index at `path` + object key `last`.
    pub(super) fn mutate_child_key(&self, path: &[PathToken], last: &str) -> Option<u32> {
        self.child_object_node(path, last)
            .and_then(|node_id| self.nodes[node_id as usize].mutate_idx)
    }

    /// Mutating op index at `path` + array index `idx`.
    pub(super) fn mutate_at_index(&self, path: &[PathToken], idx: usize) -> Option<u32> {
        self.child_array_node(path, idx)
            .and_then(|node_id| self.nodes[node_id as usize].mutate_idx)
    }

    /// Add targeting `/path/-`.
    pub(super) fn add_append(&self, path: &[PathToken]) -> Option<u32> {
        self.node_at(path).array_append
    }

    fn node_at(&self, path: &[PathToken]) -> &PathNode {
        let mut node_id = 0u32;
        for segment in path {
            let node = &self.nodes[node_id as usize];
            node_id = match segment {
                PathToken::Key(key) => node.object_children.get(key).copied(),
                PathToken::Index(idx) => node.array_children.get(idx).copied(),
            }
            .unwrap_or(node_id);
        }
        &self.nodes[node_id as usize]
    }

    fn child_object_node(&self, path: &[PathToken], key: &str) -> Option<NodeId> {
        let node = self.node_at(path);
        node.object_children.get(key).copied()
    }

    fn child_array_node(&self, path: &[PathToken], idx: usize) -> Option<NodeId> {
        let node = self.node_at(path);
        node.array_children.get(&idx).copied()
    }
}
