from typing import List, Dict, Set, Any, Optional
from data_structure.interpretation_graph import InterpretationGraphList, InterpretationGraph, InterpretationEdge
from data_structure.jobs import JobsProperties
from data_structure.verification_results import VerificationResults, ViolationRecord

def verify_properties(interpretation_graphs: InterpretationGraphList, jobs_config: JobsProperties) -> List[ViolationRecord]:
        """
        Verifies properties on the generated Interpretation Graphs.
        
        Args:
            interpretation_graphs: List of Boost Graph objects (or dict wrapper).
            jobs_config: Dictionary specifying properties to check.
            
        Returns:
            List of ViolationRecord dictionaries representing detected violations.
        """
        verification_results: List[ViolationRecord] = []
        
        # SCoT Step 2-5: Determine active properties
        # If "properties" is in jobs_config, use it. Otherwise use default list.
        default_props = [
            "Rewrite Loop", 
            "Rewrite Blackholing", 
            "Lame Delegation", 
            "Delegation Inconsistency", 
            "Answer Inconsistency"
        ]
        active_props: List[str] = jobs_config.get("properties", default_props)

        # SCoT Step 6: Iterate graphs
        # Handle potential dictionary wrapper for the list of graphs
        graphs = interpretation_graphs.get('graphs', []) if isinstance(interpretation_graphs, dict) else interpretation_graphs

        for graph in graphs:
            # SCoT Step 7: Iterate properties
            for prop in active_props:
                
                # SCoT Step 8-12: Rewrite Loop
                if prop == "Rewrite Loop":
                    if _check_rewrite_loop(graph):
                        # SCoT Step 11: Create violation
                        violation: ViolationRecord = {
                            "type": "Rewrite Loop",
                            "details": "Cycle with rewrite detected",
                            "query": graph.get('ec_id', 'unknown')
                        }
                        verification_results.append(violation)

                # SCoT Step 13-17: Rewrite Blackholing
                elif prop == "Rewrite Blackholing":
                    if _check_rewrite_blackholing(graph):
                        # SCoT Step 16: Create violation
                        violation: ViolationRecord = {
                            "type": "Rewrite Blackholing",
                            "details": "Rewritten path ends in NXDOMAIN",
                            "query": graph.get('ec_id', 'unknown')
                        }
                        verification_results.append(violation)

                # SCoT Step 18-22: Lame Delegation
                elif prop == "Lame Delegation":
                    if _check_lame_delegation(graph):
                        # SCoT Step 21: Create violation
                        violation: ViolationRecord = {
                            "type": "Lame Delegation",
                            "details": "Node returned REFUSED",
                            "query": graph.get('ec_id', 'unknown')
                        }
                        verification_results.append(violation)

                # SCoT Step 23-27: Delegation Inconsistency
                elif prop == "Delegation Inconsistency":
                    if _check_delegation_inconsistency(graph):
                        # SCoT Step 26: Create violation
                        violation: ViolationRecord = {
                            "type": "Delegation Inconsistency",
                            "details": "Record mismatch between parent and child",
                            "query": graph.get('ec_id', 'unknown')
                        }
                        verification_results.append(violation)
                
                # Answer Inconsistency (From default list and Paper)
                elif prop == "Answer Inconsistency":
                    if _check_answer_inconsistency(graph):
                        violation: ViolationRecord = {
                            "type": "Answer Inconsistency",
                            "details": "Different sink nodes return different answers",
                            "query": graph.get('ec_id', 'unknown')
                        }
                        verification_results.append(violation)
                
        # SCoT Step 28
        return verification_results
def _check_rewrite_loop(graph: InterpretationGraph) -> bool:
        """
        Run cycle detection on graph.
        Return True if a cycle exists containing a rewrite operation.
        """
        adj: Dict[str, List[InterpretationEdge]] = {}
        edges = graph.get('edges', [])
        for edge in edges:
            adj.setdefault(edge['source_id'], []).append(edge)
        
        visited: Set[str] = set()
        recursion_stack: Set[str] = set()
        
        # DFS function to detect cycle and check for rewrite in the cycle
        def dfs(u: str, path_nodes: List[str], path_edges: List[InterpretationEdge]) -> bool:
            visited.add(u)
            recursion_stack.add(u)
            path_nodes.append(u)
            
            if u in adj:
                for edge in adj[u]:
                    v = edge['target_id']
                    
                    if v in recursion_stack:
                        # Cycle detected. 
                        # Identify the edges involved in the cycle
                        try:
                            start_index = path_nodes.index(v)
                            # Edges in the cycle are those from start_index to end of path_edges, plus the current edge
                            cycle_edges = path_edges[start_index:] + [edge]
                            
                            # Check if any edge in the cycle is a rewrite
                            if any(e.get('action') == 'rewrite' for e in cycle_edges):
                                return True
                        except ValueError:
                            pass
                    
                    elif v not in visited:
                        path_edges.append(edge)
                        if dfs(v, path_nodes, path_edges):
                            return True
                        path_edges.pop()
                            
            path_nodes.pop()
            recursion_stack.remove(u)
            return False

        nodes = graph.get('nodes', {})
        node_ids = list(nodes.keys()) if isinstance(nodes, dict) else list(nodes) # type: ignore

        for node_id in node_ids:
            if node_id not in visited:
                if dfs(node_id, [], []):
                    return True
        return False
def _check_rewrite_blackholing(graph: InterpretationGraph) -> bool:
        """
        Traverse paths in graph to sink nodes.
        Return True if a path contains a rewrite and ends at a node with tag "NX".
        """
        adj: Dict[str, List[InterpretationEdge]] = {}
        edges = graph.get('edges', [])
        for edge in edges:
            adj.setdefault(edge['source_id'], []).append(edge)
            
        nodes = graph.get('nodes', {})
        
        # Identify roots (nodes with no incoming edges)
        targets = {e['target_id'] for e in edges}
        all_nodes = list(nodes.keys()) if isinstance(nodes, dict) else list(nodes) # type: ignore
        roots = [n for n in all_nodes if n not in targets]
        if not roots and all_nodes:
            # If cycle covers all nodes, pick arbitrary start
            roots = [all_nodes[0]]
            
        # Stack for DFS: (node_id, has_rewrite_encountered)
        stack = [(root, False) for root in roots]
        visited_state = set() 
        
        while stack:
            u, has_rewrite = stack.pop()
            
            state_key = (u, has_rewrite)
            if state_key in visited_state:
                continue
            visited_state.add(state_key)
            
            # Check if current node has NX tag
            node_data = nodes.get(u) if isinstance(nodes, dict) else None
            if node_data:
                tags = node_data.get('tags', [])
                if 'NX' in tags and has_rewrite:
                    return True
            
            if u in adj:
                for edge in adj[u]:
                    v = edge['target_id']
                    is_rewrite = (edge.get('action') == 'rewrite')
                    new_has_rewrite = has_rewrite or is_rewrite
                    stack.append((v, new_has_rewrite))
                    
        return False
def _check_lame_delegation(graph: InterpretationGraph) -> bool:
        """
        Check if any node has tag "REFUSED".
        """
        nodes = graph.get('nodes', {})
        if isinstance(nodes, dict):
            for node_data in nodes.values():
                tags = node_data.get('tags', [])
                if 'REFUSED' in tags:
                    return True
        return False
def _check_delegation_inconsistency(graph: InterpretationGraph) -> bool:
        """
        Check parent nodes (REF tag) against child nodes (ANS tag).
        If NS or A records do not match.
        """
        nodes = graph.get('nodes', {})
        edges = graph.get('edges', [])
        
        if isinstance(nodes, dict):
            for edge in edges:
                u = edge['source_id']
                v = edge['target_id']
                
                node_u = nodes.get(u)
                node_v = nodes.get(v)
                
                if isinstance(node_u, dict) and isinstance(node_v, dict):
                    tags_u = node_u.get('tags', [])
                    tags_v = node_v.get('tags', [])
                    
                    # Check for REF tag in parent and ANS tag in child
                    if 'REF' in tags_u and 'ANS' in tags_v:
                        records_u = node_u.get('records', [])
                        records_v = node_v.get('records', [])
                        
                        # Compare NS and A records
                        # We convert records to string for comparison as a simplification
                        set_u = set(str(r) for r in records_u)
                        set_v = set(str(r) for r in records_v)
                        
                        if set_u != set_v:
                            return True
        return False
def _check_answer_inconsistency(graph: InterpretationGraph) -> bool:
        """
        Check if different sink nodes return different answers.
        """
        adj: Dict[str, List[InterpretationEdge]] = {}
        edges = graph.get('edges', [])
        for edge in edges:
            adj.setdefault(edge['source_id'], []).append(edge)
            
        answers = set()
        nodes = graph.get('nodes', {})
        
        if isinstance(nodes, dict):
            for node_id, node_data in nodes.items():
                if node_id not in adj:
                    # It's a sink node. Extract the answer.
                    if 'answer' in node_data:
                        answers.add(str(node_data['answer']))
                    
        return len(answers) > 1