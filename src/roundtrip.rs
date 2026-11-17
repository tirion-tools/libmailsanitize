//! The output check: a defence in depth that does not depend on how the document was built. The
//! finished document is parsed again with html5ever (ammonia's parser) and must have the shape the
//! sanitizer meant:
//! - the root holds a head and a body; the head holds the frame only: one `<meta>`, then
//!   `<style>` elements;
//! - the body holds ammonia's elements, in the same order and nesting (ammonia's tree as html5ever
//!   parses its serialisation; the tree itself is not ammonia's public API);
//! - no `<style>` text contains `</`.
//!
//! A document that fails the check is replaced by the plain-text fallback (`crate::sanitize`).
use std::borrow::Cow;
use std::cell::RefCell;
use std::rc::Rc;

use html5ever::tendril::{StrTendril, TendrilSink};
use html5ever::tree_builder::{ElementFlags, NodeOrText, QuirksMode, TreeSink};
use html5ever::{
    Attribute, LocalName, ParseOpts, QualName, local_name, ns, parse_document, parse_fragment,
};

/// Elements in tree order (pre-order), each with its depth below the root.
pub type Elements = Vec<(usize, Rc<QualName>)>;

/// The elements of ammonia's output, parsed as ammonia parses its input (a fragment in a `<div>`).
pub fn expected(fragment: &str) -> Elements {
    let tree = parse_fragment(
        Tree::default(),
        ParseOpts::default(),
        QualName::new(None, ns!(html), local_name!("div")),
        vec![],
        false,
    )
    .one(fragment);
    let nodes = tree.nodes.into_inner();
    child(&nodes, 0, local_name!("html"))
        .map(|root| elements(&nodes, root))
        .unwrap_or_default()
}

/// Whether `document` parses to the sanitizer's frame around exactly the `expected` elements.
pub fn holds(expected: &Elements, document: &str) -> bool {
    let nodes = parse_document(Tree::default(), ParseOpts::default())
        .one(document)
        .nodes
        .into_inner();
    let Some(html) = child(&nodes, 0, local_name!("html")) else {
        return false;
    };
    let (Some(head), Some(body)) = (
        child(&nodes, html, local_name!("head")),
        child(&nodes, html, local_name!("body")),
    ) else {
        return false;
    };
    let frame = [local_name!("head"), local_name!("body")];
    let root_ok = element_children(&nodes, html).eq(frame.iter());
    let mut head_names = element_children(&nodes, head);
    let head_ok = head_names.next() == Some(&local_name!("meta"))
        && head_names.all(|n| *n == local_name!("style"));
    let styles_ok = nodes
        .iter()
        .filter(|n| {
            n.name
                .as_ref()
                .is_some_and(|q| q.local == local_name!("style"))
        })
        .all(|n| {
            let text: String = n
                .children
                .iter()
                .filter_map(|&c| nodes[c].text.as_deref())
                .collect();
            !text.contains("</")
        });
    root_ok && head_ok && styles_ok && elements(&nodes, body) == *expected
}

#[derive(Default)]
struct Node {
    name: Option<Rc<QualName>>,
    text: Option<String>,
    parent: Option<usize>,
    children: Vec<usize>,
    /// The contents fragment of a `<template>`.
    template: Option<usize>,
    mathml_annotation_xml_integration_point: bool,
}

/// An arena tree that keeps what the check needs: element names, nesting and text.
struct Tree {
    nodes: RefCell<Vec<Node>>,
}

impl Default for Tree {
    fn default() -> Self {
        Tree {
            nodes: RefCell::new(vec![Node::default()]), // 0: the document
        }
    }
}

#[derive(Clone)]
struct Handle {
    id: usize,
    name: Option<Rc<QualName>>,
}

fn is(nodes: &[Node], id: usize, local: &LocalName) -> bool {
    nodes[id]
        .name
        .as_ref()
        .is_some_and(|q| q.ns == ns!(html) && q.local == *local)
}

fn child(nodes: &[Node], parent: usize, local: LocalName) -> Option<usize> {
    nodes[parent]
        .children
        .iter()
        .copied()
        .find(|&c| is(nodes, c, &local))
}

fn element_children(nodes: &[Node], parent: usize) -> impl Iterator<Item = &LocalName> {
    nodes[parent]
        .children
        .iter()
        .filter_map(|&c| nodes[c].name.as_ref().map(|q| &q.local))
}

/// The elements below `root` (template contents included), without recursion: nesting depth is
/// the input's.
fn elements(nodes: &[Node], root: usize) -> Elements {
    let mut out = Vec::new();
    let mut stack: Vec<(usize, usize)> = Vec::new();
    let push_children = |stack: &mut Vec<(usize, usize)>, id: usize, depth: usize| {
        let n = &nodes[id];
        for &c in n.children.iter().chain(n.template.iter()).rev() {
            stack.push((c, depth));
        }
    };
    push_children(&mut stack, root, 0);
    while let Some((id, depth)) = stack.pop() {
        if let Some(name) = &nodes[id].name {
            out.push((depth, name.clone()));
        }
        push_children(&mut stack, id, depth + 1);
    }
    out
}

impl Tree {
    fn new_node(&self, node: Node) -> Handle {
        let mut nodes = self.nodes.borrow_mut();
        let name = node.name.clone();
        nodes.push(node);
        Handle {
            id: nodes.len() - 1,
            name,
        }
    }

    fn detach(nodes: &mut [Node], id: usize) {
        if let Some(p) = nodes[id].parent.take() {
            nodes[p].children.retain(|&c| c != id);
        }
    }

    /// Inserts `child` into `parent` at `index` (the end when `None`).
    fn insert(&self, parent: usize, index: Option<usize>, child: NodeOrText<Handle>) {
        let id = match child {
            NodeOrText::AppendNode(h) => h.id,
            NodeOrText::AppendText(t) => {
                self.new_node(Node {
                    text: Some(t.to_string()),
                    ..Node::default()
                })
                .id
            }
        };
        let mut nodes = self.nodes.borrow_mut();
        Self::detach(&mut nodes, id);
        let children = &mut nodes[parent].children;
        let at = index.unwrap_or(children.len()).min(children.len());
        children.insert(at, id);
        nodes[id].parent = Some(parent);
    }
}

impl TreeSink for Tree {
    type Handle = Handle;
    type Output = Self;
    type ElemName<'a> = &'a QualName;

    fn finish(self) -> Self {
        self
    }

    fn parse_error(&self, _msg: Cow<'static, str>) {}

    fn get_document(&self) -> Handle {
        Handle { id: 0, name: None }
    }

    fn elem_name<'a>(&'a self, target: &'a Handle) -> &'a QualName {
        target
            .name
            .as_deref()
            .expect("the tree builder names elements only")
    }

    fn create_element(&self, name: QualName, _: Vec<Attribute>, flags: ElementFlags) -> Handle {
        let template = flags.template.then(|| self.new_node(Node::default()).id);
        self.new_node(Node {
            name: Some(Rc::new(name)),
            template,
            mathml_annotation_xml_integration_point: flags.mathml_annotation_xml_integration_point,
            ..Node::default()
        })
    }

    fn create_comment(&self, _: StrTendril) -> Handle {
        self.new_node(Node::default())
    }

    fn create_pi(&self, _: StrTendril, _: StrTendril) -> Handle {
        self.new_node(Node::default())
    }

    fn append(&self, parent: &Handle, child: NodeOrText<Handle>) {
        self.insert(parent.id, None, child);
    }

    fn append_based_on_parent_node(
        &self,
        element: &Handle,
        prev_element: &Handle,
        child: NodeOrText<Handle>,
    ) {
        if self.nodes.borrow()[element.id].parent.is_some() {
            self.append_before_sibling(element, child);
        } else {
            self.append(prev_element, child);
        }
    }

    fn append_doctype_to_document(&self, _: StrTendril, _: StrTendril, _: StrTendril) {
        let doctype = self.new_node(Node::default());
        self.append(&self.get_document(), NodeOrText::AppendNode(doctype));
    }

    fn get_template_contents(&self, target: &Handle) -> Handle {
        let id = self.nodes.borrow()[target.id]
            .template
            .expect("the tree builder asks templates only");
        Handle { id, name: None }
    }

    fn same_node(&self, x: &Handle, y: &Handle) -> bool {
        x.id == y.id
    }

    fn set_quirks_mode(&self, _: QuirksMode) {}

    fn append_before_sibling(&self, sibling: &Handle, new_node: NodeOrText<Handle>) {
        let (parent, index) = {
            let nodes = self.nodes.borrow();
            let parent = nodes[sibling.id]
                .parent
                .expect("the tree builder inserts before attached nodes only");
            let index = nodes[parent].children.iter().position(|&c| c == sibling.id);
            (parent, index)
        };
        self.insert(parent, index, new_node);
    }

    fn add_attrs_if_missing(&self, _: &Handle, _: Vec<Attribute>) {}

    fn remove_from_parent(&self, target: &Handle) {
        Self::detach(&mut self.nodes.borrow_mut(), target.id);
    }

    fn reparent_children(&self, node: &Handle, new_parent: &Handle) {
        let mut nodes = self.nodes.borrow_mut();
        let moved = std::mem::take(&mut nodes[node.id].children);
        for &c in &moved {
            nodes[c].parent = Some(new_parent.id);
        }
        nodes[new_parent.id].children.extend(moved);
    }

    fn is_mathml_annotation_xml_integration_point(&self, handle: &Handle) -> bool {
        self.nodes.borrow()[handle.id].mathml_annotation_xml_integration_point
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FRAME: &str = "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><style>a{}</style></head><body class=\"gx-body\">";

    fn doc(body: &str) -> String {
        format!("{FRAME}{body}</body></html>")
    }

    #[test]
    fn the_frame_around_the_same_elements_holds() {
        let body = "<p>a<b>b</b></p><table><tr><td>c</td></tr></table><style>p{color:red}</style>";
        assert!(holds(&expected(body), &doc(body)));
    }

    #[test]
    fn markup_out_of_a_style_element_fails() {
        let ammonia = "<style>a{font-family:\"\\3c/style\\3e\\3cscript\\3e\"}</style><p>x</p>";
        let printed = "<style>a{font-family:\"</style><script>\"}</style><p>x</p>";
        assert!(!holds(&expected(ammonia), &doc(printed)));
    }

    #[test]
    fn a_style_text_with_an_end_tag_opener_fails() {
        let body = "<style>a{b:c}</style><p>x</p>";
        assert!(holds(&expected(body), &doc(body)));
        let odd = "<style>a{b:\"</p>\"}</style><p>x</p>";
        assert!(!holds(&expected(odd), &doc(odd)));
    }

    #[test]
    fn other_elements_in_the_frame_fail() {
        let body = "<p>x</p>";
        let e = expected(body);
        assert!(!holds(&e, &doc("<p>x</p><p>y</p>")));
        assert!(!holds(&e, &doc("<p><b>x</b></p>")));
        assert!(!holds(&e, &doc("<div>x</div>")));
        let head = "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><base href=\"https://e.test/\"></head><body><p>x</p></body></html>";
        assert!(!holds(&e, head));
        assert!(!holds(&e, "<p>x</p>"));
    }

    #[test]
    fn nesting_counts_not_only_order() {
        let e = expected("<div><p>x</p></div><p>y</p>");
        assert!(!holds(&e, &doc("<div><p>x</p><p>y</p></div>")));
    }

    #[test]
    fn deep_nesting_does_not_recurse() {
        let body = "<div>".repeat(10_000);
        let e = expected(&body);
        assert_eq!(e.len(), 10_000);
        assert!(holds(&e, &doc(&body)));
    }
}
