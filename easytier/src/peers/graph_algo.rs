use core::cmp::Ordering;
use hashbrown::hash_map::{
    Entry::{Occupied, Vacant},
    HashMap,
};
use petgraph::{
    algo::Measure,
    visit::{EdgeRef as _, IntoEdges, VisitMap as _, Visitable},
};
use std::{collections::BinaryHeap, hash::Hash};

/// `MinScored<K, T>` holds a score `K` and a scored object `T` in
/// a pair for use with a `BinaryHeap`.
///
/// `MinScored` compares in reverse order by the score, so that we can
/// use `BinaryHeap` as a min-heap to extract the score-value pair with the
/// least score.
///
/// **Note:** `MinScored` implements a total order (`Ord`), so that it is
/// possible to use float types as scores.
#[derive(Copy, Clone, Debug)]
pub struct MinScored<K, T>(pub K, pub T);

impl<K: PartialOrd, T> PartialEq for MinScored<K, T> {
    #[inline]
    fn eq(&self, other: &MinScored<K, T>) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl<K: PartialOrd, T> Eq for MinScored<K, T> {}

impl<K: PartialOrd, T> PartialOrd for MinScored<K, T> {
    #[inline]
    fn partial_cmp(&self, other: &MinScored<K, T>) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<K: PartialOrd, T> Ord for MinScored<K, T> {
    #[inline]
    fn cmp(&self, other: &MinScored<K, T>) -> Ordering {
        let a = &self.0;
        let b = &other.0;
        if a == b {
            Ordering::Equal
        } else if a < b {
            Ordering::Greater
        } else if a > b {
            Ordering::Less
        } else if a.ne(a) && b.ne(b) {
            // these are the NaN cases
            Ordering::Equal
        } else if a.ne(a) {
            // Order NaN less, so that it is last in the MinScore order
            Ordering::Less
        } else {
            Ordering::Greater
        }
    }
}

pub fn dijkstra_with_first_hop<G, F, K>(
    graph: G,
    start: G::NodeId,
    mut edge_cost: F,
) -> (
    HashMap<G::NodeId, K>,
    HashMap<G::NodeId, (G::NodeId, usize)>,
)
where
    G: IntoEdges + Visitable,
    G::NodeId: Eq + Hash + Clone,
    F: FnMut(G::EdgeRef) -> K,
    K: Measure + Copy,
{
    let mut visited = graph.visit_map();
    let mut scores = HashMap::new();
    let mut first_hop = HashMap::new();
    let mut visit_next = BinaryHeap::new();
    let zero_score = K::default();
    scores.insert(start.clone(), zero_score);
    visit_next.push(MinScored(zero_score, start.clone()));
    first_hop.insert(start.clone(), (start.clone(), 0));

    while let Some(MinScored(node_score, node)) = visit_next.pop() {
        if visited.is_visited(&node) {
            continue;
        }
        for edge in graph.edges(node.clone()) {
            let next = edge.target();
            if visited.is_visited(&next) {
                continue;
            }
            let next_score = node_score + edge_cost(edge);
            match scores.entry(next.clone()) {
                Occupied(mut ent) => {
                    if next_score < *ent.get() {
                        *ent.get_mut() = next_score;
                        visit_next.push(MinScored(next_score, next.clone()));
                        // 继承前驱的 first_hop，或自己就是第一跳
                        let hop = if node == start {
                            (next.clone(), 0)
                        } else {
                            first_hop[&node].clone()
                        };
                        first_hop.insert(next.clone(), (hop.0, hop.1 + 1));
                    }
                }
                Vacant(ent) => {
                    ent.insert(next_score);
                    visit_next.push(MinScored(next_score, next.clone()));
                    let hop = if node == start {
                        (next.clone(), 0)
                    } else {
                        first_hop[&node].clone()
                    };
                    first_hop.insert(next.clone(), (hop.0, hop.1 + 1));
                }
            }
        }
        visited.visit(node);
    }

    (scores, first_hop)
}

#[cfg(test)]
mod tests {
    use super::*;
    use petgraph::graph::DiGraph;

    #[test]
    fn test_dijkstra_with_first_hop_4node() {
        let mut graph = DiGraph::<&str, u32>::new();
        let a = graph.add_node("a");
        let b = graph.add_node("b");
        let c = graph.add_node("c");
        let d = graph.add_node("d");

        graph.extend_with_edges(&[(a, b, 1)]);
        graph.extend_with_edges(&[(b, c, 1)]);
        graph.extend_with_edges(&[(c, d, 2)]);

        let (scores, first_hop) = dijkstra_with_first_hop(&graph, a, |edge| *edge.weight());

        assert_eq!(scores[&b], 1);
        assert_eq!(scores[&c], 2);
        assert_eq!(scores[&d], 4);

        assert_eq!(first_hop[&b], (b, 1));
        assert_eq!(first_hop[&c], (b, 2));
        assert_eq!(first_hop[&d], (b, 3));
    }

    #[test]
    fn test_dijkstra_with_first_hop() {
        let mut graph = DiGraph::<&str, u32>::new();
        let a = graph.add_node("a");
        let b = graph.add_node("b");
        let c = graph.add_node("c");
        let d = graph.add_node("d");
        let e = graph.add_node("e");

        graph.extend_with_edges(&[(a, b, 1), (a, c, 2), (b, d, 1), (c, d, 3), (d, e, 1)]);

        let (scores, first_hop) = dijkstra_with_first_hop(&graph, a, |edge| *edge.weight());

        assert_eq!(scores[&b], 1);
        assert_eq!(scores[&c], 2);
        assert_eq!(scores[&d], 2);
        assert_eq!(scores[&e], 3);

        assert_eq!(first_hop[&b], (b, 1));
        assert_eq!(first_hop[&c], (c, 1));
        assert_eq!(first_hop[&d], (b, 2)); // d is reached via b
        assert_eq!(first_hop[&e], (b, 3)); // e is reached via d
    }
}
