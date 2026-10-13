import type { Span } from "./api";

export interface SpanNode {
  span: Span;
  children: SpanNode[];
}

// Builds the parent-child tree from the flat span list. Orphaned spans
// (missing parent, late arrivals) attach at the root so nothing disappears.
export function buildTree(spans: Span[]): SpanNode[] {
  const nodes = new Map<string, SpanNode>();
  for (const span of spans) nodes.set(span.id, { span, children: [] });
  const roots: SpanNode[] = [];
  for (const node of nodes.values()) {
    const parentId = node.span.parent_span_id;
    const parent = parentId ? nodes.get(parentId) : undefined;
    if (parent) parent.children.push(node);
    else roots.push(node);
  }
  const byTime = (a: SpanNode, b: SpanNode) =>
    a.span.started_at < b.span.started_at ? -1 : 1;
  const sortAll = (list: SpanNode[]) => {
    list.sort(byTime);
    for (const n of list) sortAll(n.children);
  };
  sortAll(roots);
  return roots;
}

export function tokenTotal(spans: Span[]): { input: number; output: number } {
  let input = 0;
  let output = 0;
  for (const s of spans) {
    input += s.input_tokens ?? 0;
    output += s.output_tokens ?? 0;
  }
  return { input, output };
}
