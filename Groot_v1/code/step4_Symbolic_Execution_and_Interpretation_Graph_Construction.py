import uuid
from typing import List, Dict, Any, Optional, Tuple, Set

from data_structure.equivalence_class import EquivalenceClassList, EquivalenceClass
from data_structure.configuration import DNSConfigurationObject
from data_structure.dns_entities import ZoneMap, Zone, ResourceRecord
from data_structure.interpretation_graph import (
    InterpretationGraphList, InterpretationGraph, InterpretationNode, 
    InterpretationEdge, ResolutionState
)

def get_domain_from_sequence(sequence: List[str]) -> str:
    """
    Converts a domain sequence (list of labels) into a FQDN string.
    Assumes the sequence might end with '.' or empty string for root.
    """
    labels = [l for l in sequence if l and l != '.']
    return ".".join(labels) + "."

def find_authoritative_zone(server: str, query: str, dns_config: DNSConfigurationObject, zone_map: ZoneMap) -> Optional[Zone]:
        """
        Finds the most specific authoritative zone for the query on the given server.
        Uses Gamma (Server -> Zones) and ZoneMap (ZoneName -> Zone).
        """
        if server not in dns_config['Gamma']:
            return None
        
        served_zones = dns_config['Gamma'][server]
        best_zone = None
        longest_match_len = -1
        
        # Normalize query to ensure it ends with dot for comparison
        q_norm = query if query.endswith('.') else query + "."
        
        for zone_name in served_zones:
            # Normalize zone name
            z_name = zone_name if zone_name.endswith('.') else zone_name + "."
            
            # Check if query falls within this zone (zone is a suffix of query)
            # Must ensure label boundary matching
            is_match = False
            if z_name == '.':
                is_match = True
            else:
                # Match if exact match or if query ends with .z_name
                if q_norm == z_name:
                    is_match = True
                elif q_norm.endswith("." + z_name):
                    is_match = True
                
            if is_match:
                # Check if we actually have the zone data
                z_obj = None
                # Try various key formats in zone_map
                if zone_name in zone_map['domain_to_zone']:
                    z_obj = zone_map['domain_to_zone'][zone_name]
                elif z_name in zone_map['domain_to_zone']:
                    z_obj = zone_map['domain_to_zone'][z_name]
                elif z_name.rstrip('.') in zone_map['domain_to_zone']:
                     z_obj = zone_map['domain_to_zone'][z_name.rstrip('.')]
    
                if z_obj:
                    # We want the longest matching zone name (most specific)
                    # Count labels
                    z_len = len([l for l in z_name.split('.') if l])
                    if z_len > longest_match_len:
                        longest_match_len = z_len
                        best_zone = z_obj
    
        return best_zone
def symbolic_server_lookup(zone: Zone, query: str, types: List[str]) -> List[Dict[str, Any]]:
        """
        Performs a symbolic lookup in the zone following formal DNS semantics.
        Returns a list of outcome groups.
        Each group: {'types': List[str], 'answer': {'type': str, ...}, 'records': List[ResourceRecord]}
        Answer Types: REF (Referral), ANSQ (Rewrite), ANS (Answer), NX (NXDOMAIN), REFUSED.
        """
        # 0. Pre-process zone records for fast access
        records_map: Dict[str, Dict[str, List[ResourceRecord]]] = {}
        for r in zone['records']:
            r_name = r['name'] if r['name'].endswith('.') else r['name'] + "."
            if r_name not in records_map:
                records_map[r_name] = {}
            if r['type'] not in records_map[r_name]:
                records_map[r_name][r['type']] = []
            records_map[r_name][r['type']].append(r)
    
        q_norm = query if query.endswith('.') else query + "."
        z_origin = zone['origin'] if zone['origin'].endswith('.') else zone['origin'] + "."
        
        # 1. Find Closest Encloser
        closest_encloser = None
        q_labels = [l for l in q_norm.split('.') if l]
        
        if q_norm in records_map:
            closest_encloser = q_norm
        else:
            # Iteratively strip leftmost label
            for i in range(1, len(q_labels) + 1):
                sub_domain = ".".join(q_labels[i:]) + "."
                if not sub_domain: sub_domain = "."
                
                # Check if we went above zone origin
                if len(sub_domain) < len(z_origin) or not sub_domain.endswith(z_origin):
                    break
                    
                if sub_domain in records_map:
                    closest_encloser = sub_domain
                    break
            
            if closest_encloser is None:
                closest_encloser = z_origin
    
        # 2. Determine Outcome for each type
        outcomes: Dict[Tuple[str, Tuple[str, ...], str], Dict[str, Any]] = {}
        
        rrset = records_map.get(closest_encloser, {})
        rr_types = set(rrset.keys())
        
        has_dname = 'DNAME' in rr_types
        has_ns = 'NS' in rr_types
        has_soa = 'SOA' in rr_types
        is_delegation = has_ns and not has_soa
        
        for t in types:
            outcome_type = ''
            outcome_targets = tuple()
            outcome_new_query = ''
            used_records = []
            
            if closest_encloser == q_norm:
                # Exact Match
                if is_delegation:
                    # Delegation
                    outcome_type = 'REF'
                    ns_records = rrset.get('NS', [])
                    ns_targets = sorted([r['rdata'] for r in ns_records])
                    outcome_targets = tuple(ns_targets)
                    used_records = ns_records
                else:
                    # Authoritative Data
                    if 'CNAME' in rr_types and t != 'CNAME':
                        # CNAME Rewrite
                        outcome_type = 'ANSQ'
                        cname_records = rrset['CNAME']
                        cname_target = cname_records[0]['rdata']
                        outcome_new_query = cname_target if cname_target.endswith('.') else cname_target + "."
                        used_records = cname_records
                    elif t in rr_types:
                        outcome_type = 'ANS' # Data present
                        used_records = rrset[t]
                    else:
                        outcome_type = 'ANS' # NODATA
                        used_records = []
            else:
                # Ancestor Match
                if has_dname:
                    outcome_type = 'ANSQ'
                    dname_records = rrset['DNAME']
                    dname_target = dname_records[0]['rdata']
                    if not dname_target.endswith('.'): dname_target += "."
                    
                    suffix_len = len(closest_encloser)
                    prefix = q_norm[:-suffix_len]
                    outcome_new_query = prefix + dname_target
                    used_records = dname_records
                    
                elif is_delegation:
                    outcome_type = 'REF'
                    ns_records = rrset.get('NS', [])
                    ns_targets = sorted([r['rdata'] for r in ns_records])
                    outcome_targets = tuple(ns_targets)
                    used_records = ns_records
                    
                else:
                    # Wildcard Check
                    wildcard_name = "*." + closest_encloser
                    if wildcard_name in records_map:
                        w_rrset = records_map[wildcard_name]
                        w_types = set(w_rrset.keys())
                        
                        if 'CNAME' in w_types and t != 'CNAME':
                            outcome_type = 'ANSQ'
                            cname_records = w_rrset['CNAME']
                            cname_target = cname_records[0]['rdata']
                            outcome_new_query = cname_target if cname_target.endswith('.') else cname_target + "."
                            used_records = cname_records
                        elif t in w_types:
                            outcome_type = 'ANS' # Wildcard Data
                            used_records = w_rrset[t]
                        else:
                            outcome_type = 'ANS' # Wildcard NODATA
                            used_records = []
                    else:
                        outcome_type = 'NX'
                        used_records = []
            
            key = (outcome_type, outcome_targets, outcome_new_query)
            if key not in outcomes:
                outcomes[key] = {'types': [], 'records': []}
            outcomes[key]['types'].append(t)
            outcomes[key]['records'].extend(used_records)
            
        # 3. Construct Result List
        results = []
        for (otype, otargets, onewq), data in outcomes.items():
            res = {
                'types': data['types'],
                'answer': {'type': otype},
                'records': data['records']
            }
            if otype == 'REF':
                res['answer']['target_servers'] = list(otargets)
            if otype == 'ANSQ':
                res['answer']['new_query'] = onewq
            results.append(res)
                
        return results
def generate_interpretation_graphs(
        equivalence_classes: EquivalenceClassList,
        dns_config: DNSConfigurationObject,
        zone_map: ZoneMap
    ) -> InterpretationGraphList:
        
        interpretation_graphs: List[InterpretationGraph] = []
        
        for ec in equivalence_classes['classes']:
            ec_id = ec['ec_id']
            query_domain = get_domain_from_sequence(ec['domain_sequence'])
            
            # Initialize Graph
            graph_nodes: Dict[str, InterpretationNode] = {}
            graph_edges: List[InterpretationEdge] = []
            
            # State caching to prevent cycles and merge paths
            visited_states: Dict[Tuple[str, str, frozenset], str] = {}
            
            # Worklist: List of tuples (state_dict, parent_node_id, edge_action_from_parent)
            worklist = []
            
            # Initial states: Roots
            for root in dns_config['Theta']:
                initial_state = {
                    'server': root,
                    'query': query_domain,
                    'types': ec['query_types']
                }
                worklist.append((initial_state, None, None))
                
            while worklist:
                current_state, parent_id, edge_action = worklist.pop(0)
                
                server = current_state['server']
                query = current_state['query']
                current_types = current_state['types']
                
                # Create state key for caching
                state_key = (server, query, frozenset(current_types))
                
                if state_key in visited_states:
                    existing_node_id = visited_states[state_key]
                    if parent_id:
                        edge: InterpretationEdge = {
                            'source_id': parent_id,
                            'target_id': existing_node_id,
                            'action': edge_action if edge_action else 'unknown'
                        }
                        if edge not in graph_edges:
                            graph_edges.append(edge)
                    continue
                
                # Create New Node
                node_id = str(uuid.uuid4())
                visited_states[state_key] = node_id
                
                node: InterpretationNode = {
                    'node_id': node_id,
                    'state': {
                        'nameserver': server,
                        'current_query': query
                    },
                    'query_type_bitmap': current_types,
                    'tags': [],
                    'records': [],
                    'answer': None
                }
                graph_nodes[node_id] = node
                
                # Add Edge from parent
                if parent_id:
                    edge: InterpretationEdge = {
                        'source_id': parent_id,
                        'target_id': node_id,
                        'action': edge_action if edge_action else 'unknown'
                    }
                    graph_edges.append(edge)
                
                # Retrieve Zone
                zone = find_authoritative_zone(server, query, dns_config, zone_map)
                
                if not zone:
                    node['tags'].append('REFUSED')
                    continue
                    
                # Symbolic Lookup
                outcomes = symbolic_server_lookup(zone, query, current_types)
                
                all_tags = set()
                all_records = []
                
                for outcome in outcomes:
                    sub_types = outcome['types']
                    answer = outcome['answer']
                    ans_type = answer['type']
                    records = outcome.get('records', [])
                    
                    all_tags.add(ans_type)
                    all_records.extend(records)
                    
                    # Store answer for inconsistency check (store first ANS/NX)
                    if ans_type in ['ANS', 'NX'] and node['answer'] is None:
                        node['answer'] = answer
                    
                    if ans_type == 'REF':
                        # Referral
                        for ns in answer['target_servers']:
                            new_state = {
                                'server': ns,
                                'query': query,
                                'types': sub_types
                            }
                            worklist.append((new_state, node_id, 'referral'))
                            
                    elif ans_type == 'ANSQ':
                        # Rewrite (CNAME/DNAME)
                        new_query = answer['new_query']
                        # Restart at roots
                        for root in dns_config['Theta']:
                            new_state = {
                                'server': root,
                                'query': new_query,
                                'types': sub_types
                            }
                            worklist.append((new_state, node_id, 'rewrite'))
                            
                node['tags'] = list(all_tags)
                node['records'] = all_records
                        
            graph: InterpretationGraph = {
                'ec_id': ec_id,
                'nodes': graph_nodes,
                'edges': graph_edges
            }
            interpretation_graphs.append(graph)
            
        return {'graphs': interpretation_graphs}
    