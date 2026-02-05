
import collections
from dns_defs import Query

class Node:
    def __init__(self, label):
        self.label = label
        self.children = {} 
        self.dname_target = None
        self.is_record_owner = False
        self.is_wildcard = False

def build_label_graph(zones):
    root = Node("")
    def add_domain(domain):
        parts = domain.strip('.').split('.')
        parts.reverse() 
        curr = root
        for part in parts:
            if not part: continue
            if part == '*': curr.is_wildcard = True
            if part not in curr.children: curr.children[part] = Node(part)
            curr = curr.children[part]
        return curr

    for zone in zones:
        for r in zone.records:
            node = add_domain(r.name)
            node.is_record_owner = True
            if r.rtype == 'DNAME':
                target_node = add_domain(r.rdata)
                node.dname_target = target_node  
    return root

def generate_ecs(label_graph_root):
    ecs = []
    def dfs(node, current_path):
        domain_name = ".".join(reversed(current_path[1:])) + "."
        if node.is_record_owner or node == label_graph_root:
            ecs.append(domain_name)
        
        alpha_domain = f"~{{}}.{domain_name}"
        if domain_name == ".": alpha_domain = "~{}."
        ecs.append(alpha_domain)
        
        for label, child in node.children.items():
            current_path.append(label)
            dfs(child, current_path)
            current_path.pop()
    dfs(label_graph_root, [""])
    return list(set(ecs))

class GrootEngine:
    def __init__(self, top_ns, zones):
        self.top_ns = top_ns
        self.zone_map = {}
        for z in zones: self.zone_map[(z.server_name, z.name)] = z
        self.server_zones = collections.defaultdict(list)
        for z in zones: self.server_zones[z.server_name].append(z)

    def resolve(self, query_str, record_type='A'):
        if not query_str.endswith('.'): query_str += '.'
        q = Query(query_str, record_type)
        visited = set()
        graph = {} 
        external_ns_contacted = []
        
        queue = collections.deque()
        for ns in self.top_ns:
            node = (ns, q.name, q.qtype)
            queue.append(node)
            visited.add(node)
            
        final_states = []
        steps = 0
        
        while queue:
            steps += 1
            if steps > 1000: break
            curr_ns, curr_q_name, curr_q_type = queue.popleft()
            
            if curr_ns not in self.server_zones:
                if curr_ns not in external_ns_contacted: external_ns_contacted.append(curr_ns)
                final_states.append({'type': 'EXTERNAL', 'ns': curr_ns, 'query': curr_q_name})
                continue
            
            best_zone = None
            best_len = -1
            possible_zones = self.server_zones[curr_ns]
            for z in possible_zones:
                if curr_q_name.endswith(z.name):
                    if len(z.name) > best_len:
                        best_len = len(z.name)
                        best_zone = z
            
            if not best_zone:
                final_states.append({'type': 'REFUSED', 'ns': curr_ns, 'query': curr_q_name})
                continue
                
            records = best_zone.records
            matches = [r for r in records if r.name == curr_q_name]
            type_matches = [r for r in matches if r.rtype == curr_q_type]
            cname_matches = [r for r in matches if r.rtype == 'CNAME']
            ns_matches = [r for r in matches if r.rtype == 'NS']
            
            if type_matches:
                 final_states.append({'type': 'ANSWER', 'records': type_matches, 'ns': curr_ns})
            elif cname_matches:
                cname = cname_matches[0]
                new_q = cname.rdata
                for root in self.top_ns:
                     nn = (root, new_q, curr_q_type)
                     if nn not in visited:
                         visited.add(nn)
                         queue.append(nn)
                     if (curr_ns, curr_q_name) not in graph: graph[(curr_ns, curr_q_name)] = []
                     graph[(curr_ns, curr_q_name)].append({'action': 'REWRITE', 'target': nn})
            elif ns_matches:
                if curr_q_name == best_zone.name:
                    final_states.append({'type': 'NODATA', 'ns': curr_ns})
                else:
                    for ns_rec in ns_matches:
                        target_ns = ns_rec.rdata
                        nn = (target_ns, curr_q_name, curr_q_type)
                        if nn not in visited:
                            visited.add(nn)
                            queue.append(nn)
            else:
                parts = curr_q_name.split('.')
                wildcard_match = None
                for i in range(len(parts)):
                    suffix = ".".join(parts[i:])
                    w_query = "*." + suffix
                    w_recs = [r for r in records if r.name == w_query]
                    if w_recs:
                        wildcard_match = w_recs
                        break
                if wildcard_match:
                    wc_cname = [r for r in wildcard_match if r.rtype == 'CNAME']
                    if wc_cname:
                        new_q = wc_cname[0].rdata
                        for root in self.top_ns:
                             nn = (root, new_q, curr_q_type)
                             if nn not in visited:
                                 visited.add(nn)
                                 queue.append(nn)
                             if (curr_ns, curr_q_name) not in graph: graph[(curr_ns, curr_q_name)] = []
                             graph[(curr_ns, curr_q_name)].append({'action': 'REWRITE', 'target': nn})
                    else:
                        wc_ans = [r for r in wildcard_match if r.rtype == curr_q_type]
                        if wc_ans:
                            final_states.append({'type': 'ANSWER', 'records': wc_ans, 'ns': curr_ns})
                        else:
                             final_states.append({'type': 'NODATA', 'ns': curr_ns})
                else:
                    found_cut = False
                    q_parts = curr_q_name.strip('.').split('.')
                    z_parts = best_zone.name.strip('.').split('.')
                    for i in range(1, len(q_parts) - len(z_parts) + 1):
                        sub = ".".join(q_parts[i:]) + "."
                        cuts = [r for r in records if r.name == sub and r.rtype == 'NS']
                        if cuts:
                            for ns_rec in cuts:
                                target_ns = ns_rec.rdata
                                nn = (target_ns, curr_q_name, curr_q_type)
                                if nn not in visited:
                                    visited.add(nn)
                                    queue.append(nn)
                            found_cut = True
                            break
                    if not found_cut:
                        final_states.append({'type': 'NXDOMAIN', 'ns': curr_ns})
        
        return final_states, graph, visited, external_ns_contacted
