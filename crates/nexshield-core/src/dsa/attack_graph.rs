//! Graph data structure & algorithms for lateral movement and attack graph analysis.
//!
//! Provides BFS shortest attack paths and Tarjan's Articulation Points algorithm
//! to identify critical choke points for automated zero-trust host quarantine.

use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Default, Debug, Clone)]
pub struct AttackGraph {
    adj: HashMap<String, Vec<String>>,
}

impl AttackGraph {
    pub fn new() -> Self {
        Self {
            adj: HashMap::new(),
        }
    }

    /// Add a directed reachability or pivot edge from -> to
    pub fn add_edge(&mut self, from: &str, to: &str) {
        self.adj
            .entry(from.to_string())
            .or_default()
            .push(to.to_string());
        // Ensure destination node exists in graph
        self.adj.entry(to.to_string()).or_default();
    }

    /// Add an undirected network communication link between two nodes
    pub fn add_undirected_edge(&mut self, a: &str, b: &str) {
        self.add_edge(a, b);
        self.add_edge(b, a);
    }

    /// Find shortest lateral movement path using BFS: O(V + E)
    pub fn shortest_path(&self, start: &str, target: &str) -> Option<Vec<String>> {
        if start == target {
            return Some(vec![start.to_string()]);
        }
        if !self.adj.contains_key(start) || !self.adj.contains_key(target) {
            return None;
        }

        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        let mut parent: HashMap<String, String> = HashMap::new();

        queue.push_back(start.to_string());
        visited.insert(start.to_string());

        let mut found = false;
        while let Some(curr) = queue.pop_front() {
            if curr == target {
                found = true;
                break;
            }

            if let Some(neighbors) = self.adj.get(&curr) {
                for neighbor in neighbors {
                    if !visited.contains(neighbor) {
                        visited.insert(neighbor.clone());
                        parent.insert(neighbor.clone(), curr.clone());
                        queue.push_back(neighbor.clone());
                    }
                }
            }
        }

        if !found {
            return None;
        }

        // Reconstruct path
        let mut path = Vec::new();
        let mut curr = target.to_string();
        path.push(curr.clone());
        while let Some(p) = parent.get(&curr) {
            path.push(p.clone());
            curr = p.clone();
        }
        path.reverse();
        Some(path)
    }

    /// Identify Choke Points (Articulation Points) using Tarjan's Algorithm: O(V + E)
    ///
    /// An articulation point is a host whose quarantine fragments the network
    /// and prevents attackers from pivoting deeper into the infrastructure.
    pub fn find_choke_points(&self) -> Vec<String> {
        let mut disc: HashMap<String, usize> = HashMap::new();
        let mut low: HashMap<String, usize> = HashMap::new();
        let mut is_ap: HashSet<String> = HashSet::new();
        let mut timer = 0;

        for node in self.adj.keys() {
            if !disc.contains_key(node) {
                let mut children = 0;
                self.dfs_ap(node, None, &mut timer, &mut disc, &mut low, &mut is_ap, &mut children);
                if children > 1 {
                    is_ap.insert(node.clone());
                } else {
                    is_ap.remove(node);
                }
            }
        }

        is_ap.into_iter().collect()
    }

    fn dfs_ap(
        &self,
        u: &str,
        parent: Option<&str>,
        timer: &mut usize,
        disc: &mut HashMap<String, usize>,
        low: &mut HashMap<String, usize>,
        is_ap: &mut HashSet<String>,
        root_children: &mut usize,
    ) {
        *timer += 1;
        disc.insert(u.to_string(), *timer);
        low.insert(u.to_string(), *timer);

        if let Some(neighbors) = self.adj.get(u) {
            for v in neighbors {
                if let Some(p) = parent {
                    if v == p {
                        continue;
                    }
                }

                if disc.contains_key(v) {
                    // Back-edge
                    let low_u = low.get_mut(u).unwrap();
                    let disc_v = *disc.get(v).unwrap();
                    *low_u = (*low_u).min(disc_v);
                } else {
                    // Tree-edge
                    if parent.is_none() {
                        *root_children += 1;
                    }
                    self.dfs_ap(v, Some(u), timer, disc, low, is_ap, root_children);

                    let low_v = *low.get(v).unwrap();
                    let low_u = low.get_mut(u).unwrap();
                    *low_u = (*low_u).min(low_v);

                    if parent.is_some() && low_v >= *disc.get(u).unwrap() {
                        is_ap.insert(u.to_string());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shortest_pivot_path() {
        let mut graph = AttackGraph::new();
        graph.add_edge("192.168.1.10", "192.168.1.20");
        graph.add_edge("192.168.1.20", "10.0.0.5");
        graph.add_edge("192.168.1.10", "10.0.0.5"); // direct shortcut

        let path = graph.shortest_path("192.168.1.10", "10.0.0.5").unwrap();
        assert_eq!(path, vec!["192.168.1.10", "10.0.0.5"]);
    }

    #[test]
    fn test_tarjan_choke_point_detection() {
        // Linear bridge: Node A <--> Node B <--> Node C
        // Quarantining Node B cuts off Node C from Node A!
        let mut graph = AttackGraph::new();
        graph.add_undirected_edge("Host_A", "Host_B");
        graph.add_undirected_edge("Host_B", "Host_C");

        let choke_points = graph.find_choke_points();
        assert_eq!(choke_points, vec!["Host_B"]);
    }
}
