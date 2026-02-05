from typing import List, Dict, Any, Union, Set, Tuple
from data_structure.dns_entities import ZoneMap, ResourceRecord
from data_structure.label_graph import LabelGraph, LabelGraphNode, LabelGraphEdge

def construct_label_graph(zone_map: Union[Dict[str, Any], Any]) -> LabelGraph:
    """
    Constructs the Label Graph from the Zone Map.
    
    Args:
        zone_map: A dictionary mapping domain names to Zone objects, 
                  or a wrapper containing 'domain_to_zone'.
        
    Returns:
        label_graph: A graph data structure rooted at epsilon.
    """
    
    # 1: Initialize label_graph with a single root node representing epsilon (root)
    nodes: Dict[str, LabelGraphNode] = {}
    edges: List[LabelGraphEdge] = []
    
    # Helper set to avoid duplicate edges: stores (source_id, target_id, edge_type, label)
    existing_edges: Set[Tuple[str, str, str, str]] = set()
    
    # Root node (epsilon)
    root_id = "0"
    nodes[root_id] = {
        "id": root_id,
        "label": "",
        "is_wildcard": False,
        "is_root": True
    }
    
    # Adjacency list for quick lookup: parent_id -> label -> child_id
    # This helps in step 9 to check if child exists
    adj: Dict[str, Dict[str, str]] = {root_id: {}}
    
    # Counter for generating unique node IDs
    _next_id = 1
    def get_next_id() -> str:
        nonlocal _next_id
        nid = str(_next_id)
        _next_id += 1
        return nid

    # Helper to parse domain name into labels (TLD to leaf)
    def get_labels(domain: str) -> List[str]:
        if not domain or domain == ".":
            return []
        
        # Remove trailing dot if present
        s = domain[:-1] if domain.endswith('.') else domain
        if not s:
            return []
            
        # Split and reverse to get TLD -> Leaf order
        # e.g., "www.example.com" -> ["com", "example", "www"]
        return s.split('.')[::-1]

    # Helper to insert a path of labels into the graph
    def insert_path(labels: List[str]) -> str:
        current_node = root_id
        for label in labels:
            # 9: if current_node does not have a child connected by label
            if label not in adj[current_node]:
                # 10: Create a new node next_node
                new_id = get_next_id()
                nodes[new_id] = {
                    "id": new_id,
                    "label": label,
                    "is_wildcard": (label == "*")
                }
                adj[new_id] = {}
                
                # 11: Add a solid edge from current_node to next_node
                edge_key = (current_node, new_id, "child", label)
                if edge_key not in existing_edges:
                    edges.append({
                        "source_id": current_node,
                        "target_id": new_id,
                        "edge_type": "child",
                        "label": label
                    })
                    existing_edges.add(edge_key)
                
                # Update adjacency and move current_node
                adj[current_node][label] = new_id
                current_node = new_id
            else:
                # 14: Set current_node = existing child node connected by label
                current_node = adj[current_node][label]
        return current_node

    # 2: Initialize an empty list all_records
    all_records: List[Any] = []
    
    # 3: for each zone in zone_map values
    # Handle input format flexibility (Wrapper vs Direct Dict)
    zones_iterable = []
    if isinstance(zone_map, dict):
        if "domain_to_zone" in zone_map and isinstance(zone_map["domain_to_zone"], dict):
            zones_iterable = zone_map["domain_to_zone"].values()
        else:
            zones_iterable = zone_map.values()
    elif hasattr(zone_map, "domain_to_zone"):
        zones_iterable = zone_map.domain_to_zone.values()

    for zone in zones_iterable:
        # 4: Extend all_records with records from zone
        # Support both object with .records and dict with ["records"]
        z_records = []
        if isinstance(zone, dict):
            z_records = zone.get("records", [])
        elif hasattr(zone, "records"):
            z_records = zone.records
            
        if isinstance(z_records, list):
            all_records.extend(z_records)
        elif isinstance(z_records, dict):
            # If records are stored as Map<Name, List[RR]>
            for r_list in z_records.values():
                all_records.extend(r_list)
                
    # 5: for each record in all_records
    for record in all_records:
        # 6: Let labels be the sequence of labels in record["owner_name"]
        # Fallback to "name" if "owner_name" is missing. Support dict and object.
        if isinstance(record, dict):
            owner_name = record.get("owner_name", record.get("name", ""))
            rtype = record.get("type", "")
            target_name = record.get("target", record.get("rdata", ""))
        else:
            owner_name = getattr(record, "owner_name", getattr(record, "name", ""))
            rtype = getattr(record, "type", "")
            target_name = getattr(record, "target", getattr(record, "rdata", ""))

        labels = get_labels(owner_name)
        
        # 7-14: Perform path insertion
        current_node = insert_path(labels)
        
        # 15: if record["type"] is "DNAME"
        if rtype == "DNAME":
            # 16: Let target_labels be the sequence of labels in record["target"]
            target_labels = get_labels(target_name)
            
            # 17: Perform path insertion for target_labels to locate/create target_node
            target_node = insert_path(target_labels)
            
            # 18: Add a dashed (rewrite) edge from current_node to target_node
            # Avoid duplicate edges if multiple DNAME records exist for same node
            edge_key = (current_node, target_node, "dname", "")
            if edge_key not in existing_edges:
                edges.append({
                    "source_id": current_node,
                    "target_id": target_node,
                    "edge_type": "dname",
                    "label": ""
                })
                existing_edges.add(edge_key)
                
    # 19: Get a list of all nodes currently in label_graph
    # Use list() to create a snapshot of keys, as we will be adding new nodes
    existing_nodes = list(nodes.keys())
    
    # 20: for each node in nodes
    for node_id in existing_nodes:
        # 21: Create a new node alpha_child
        alpha_id = get_next_id()
        nodes[alpha_id] = {
            "id": alpha_id,
            "label": "alpha",
            "is_wildcard": True, # Represents arbitrary labels
            "is_alpha": True
        }
        # Initialize adjacency for safety
        adj[alpha_id] = {}
        
        # 22: Add an edge from node to alpha_child labeled "alpha"
        edge_key = (node_id, alpha_id, "child", "alpha")
        if edge_key not in existing_edges:
            edges.append({
                "source_id": node_id,
                "target_id": alpha_id,
                "edge_type": "child",
                "label": "alpha"
            })
            existing_edges.add(edge_key)
            
        # Update adjacency
        if node_id in adj:
            adj[node_id]["alpha"] = alpha_id
            
    # 23: return label_graph
    label_graph: LabelGraph = {
        "nodes": nodes,
        "edges": edges
    }
    
    return label_graph