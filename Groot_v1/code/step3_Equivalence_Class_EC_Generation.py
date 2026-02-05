import copy
from typing import List, Dict, Any, Union
from data_structure.label_graph import LabelGraph
from data_structure.equivalence_class import EquivalenceClass, EquivalenceClassList

MAX_DNS_LENGTH = 20
SUPPORTED_QUERY_TYPES = ['A', 'AAAA', 'NS', 'MX', 'TXT', 'CNAME', 'SOA']

def generate_equivalence_classes(label_graph: LabelGraph) -> EquivalenceClassList:
    """
    Traverse the Label Graph to enumerate paths starting from the root and generate Equivalence Classes.
    This function implements the algorithm described in Section 4.1 of the paper, handling DNAME loops
    and alpha labels.
    """
    ec_list: List[EquivalenceClass] = []
    
    # Pre-process graph for efficient lookup
    # Map: source_id -> list of target_ids (children)
    children_map: Dict[str, List[str]] = {}
    # Map: source_id -> target_id (dname)
    dname_map: Dict[str, str] = {}
    
    # Access nodes and edges safely, handling both dict and object access
    nodes = label_graph.get('nodes', {}) if isinstance(label_graph, dict) else getattr(label_graph, 'nodes', {})
    edges = label_graph.get('edges', []) if isinstance(label_graph, dict) else getattr(label_graph, 'edges', [])
    
    for edge in edges:
        src = edge['source_id']
        tgt = edge['target_id']
        e_type = edge['edge_type']
        
        if e_type == 'child':
            if src not in children_map:
                children_map[src] = []
            children_map[src].append(tgt)
        elif e_type == 'dname':
            dname_map[src] = tgt

    # Find root node (assuming label is '.' or empty string)
    root_node_id = None
    for nid, node in nodes.items():
        lbl = node.get('label', '')
        if lbl == '.' or lbl == '':
            root_node_id = nid
            break
            
    if root_node_id is None:
        # If no root found, return empty list
        return []

    # Initialize stack
    # State: {'node': node_id, 'path': list, 'history': dict}
    # history maps node_id -> path_length_at_visit
    # Path includes the root label initially
    root_label = nodes[root_node_id].get('label', '.')
    stack = [{
        'node': root_node_id,
        'path': [root_label],
        'history': {}
    }]
    
    ec_counter = 0

    while stack:
        state = stack.pop()
        current_node_id = state['node']
        current_path = state['path']
        node_history = state['history']
        
        # Infinite loop detection (Type 2 DNAME loop)
        # If we visit the same node with the same path length in the current traversal branch, it's a loop.
        if current_node_id in node_history and node_history[current_node_id] == len(current_path):
            continue # Backtrack
            
        node_history[current_node_id] = len(current_path)
        
        # Max length check (Type 1 DNAME loop termination)
        if len(current_path) > MAX_DNS_LENGTH:
            continue # Max length exceeded
            
        # Generate ECs for the current path
        # Convert path elements to string for EquivalenceClass compatibility
        # Reverse path to match DNS domain sequence (Leaf -> Root)
        domain_sequence_str: List[str] = []
        for segment in reversed(current_path):
            if isinstance(segment, dict) and segment.get('label') == 'alpha':
                # Format alpha constraint as string
                constraints = segment.get('constraints', [])
                c_str = ",".join(sorted(constraints))
                domain_sequence_str.append(f"alpha_except_[{c_str}]")
            else:
                domain_sequence_str.append(str(segment))

        for t in SUPPORTED_QUERY_TYPES:
            ec_counter += 1
            ec: EquivalenceClass = {
                'ec_id': f"EC_{ec_counter}",
                'domain_sequence': domain_sequence_str,
                'query_types': [t]
            }
            ec_list.append(ec)
            
        # Traverse children
        children_ids = children_map.get(current_node_id, [])
        
        # Collect labels to identify siblings for 'alpha' constraint
        child_info = []
        for child_id in children_ids:
            if child_id in nodes:
                lbl = nodes[child_id].get('label', '')
                child_info.append((child_id, lbl))
            
        sibling_labels = [lbl for _, lbl in child_info if lbl != 'alpha']
        
        for child_id, label in child_info:
            new_path = list(current_path)
            
            if label == 'alpha':
                constraint = list(sibling_labels)
                new_path.append({'label': 'alpha', 'constraints': constraint})
            else:
                new_path.append(label)
                
            stack.append({
                'node': child_id,
                'path': new_path,
                'history': node_history.copy()
            })
            
        # Handle DNAME edge
        # If there is a DNAME edge, we traverse it.
        # The path does NOT change (we don't append the target label), 
        # but we move to the target node to continue traversal.
        if current_node_id in dname_map:
            target_node_id = dname_map[current_node_id]
            if target_node_id in nodes:
                stack.append({
                    'node': target_node_id,
                    'path': current_path, # Path remains same for DNAME traversal
                    'history': node_history.copy()
                })
            
    return ec_list