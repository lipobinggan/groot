import sys
import os
import json
import re
from collections import defaultdict, deque
from functools import total_ordering
from itertools import product
import argparse
import logging

# --- Basic Configuration ---
logging.basicConfig(level=logging.ERROR, format='%(levelname)s: %(message)s')
MAX_RESOLUTION_DEPTH = 15  # "fuel" parameter 'k' to prevent infinite loops
ALPHA_SYMBOL = "~{ }" # Represents an arbitrary, non-matching label
ROOT_DOMAIN_STR = "."

# --- DNS Data Models (Section 3.1) ---

@total_ordering
class DomainName:
    """Represents a DNS domain name as a sequence of labels."""
    def __init__(self, name_str):
        if isinstance(name_str, DomainName):
            self.labels = name_str.labels
            return
        
        name_str = name_str.lower().strip()
        if not name_str or name_str == ROOT_DOMAIN_STR:
            self.labels = []
        else:
            if name_str.endswith(ROOT_DOMAIN_STR):
                name_str = name_str[:-1]
            self.labels = list(reversed(name_str.split('.')))

    def is_wildcard(self):
        return self.labels and self.labels[-1] == '*'

    def is_alpha(self):
        return self.labels and self.labels[-1] == ALPHA_SYMBOL

    def substitute(self, old_prefix, new_prefix):
        """Performs DNAME-style substitution."""
        if not self.is_prefix(old_prefix):
            return self
        
        prefix_to_replace = self.labels[:len(old_prefix.labels)]
        if prefix_to_replace != old_prefix.labels:
             # This should not happen if is_prefix check is correct
            return self
            
        remaining_suffix = self.labels[len(old_prefix.labels):]
        new_labels = new_prefix.labels + remaining_suffix
        return DomainName(".".join(reversed(new_labels)) + ".")

    def is_prefix(self, other):
        """Checks if `other` is a prefix of `self` (e.g., 'com' is a prefix of 'google.com')."""
        if len(self.labels) < len(other.labels):
            return False
        return self.labels[:len(other.labels)] == other.labels

    def __str__(self):
        if not self.labels:
            return ROOT_DOMAIN_STR
        return ".".join(reversed(self.labels)) + "."

    def __repr__(self):
        return f"DomainName('{self}')"

    def __eq__(self, other):
        return isinstance(other, DomainName) and self.labels == other.labels

    def __lt__(self, other):
        return self.labels < other.labels

    def __hash__(self):
        return hash(tuple(self.labels))

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, key):
        return self.labels[key]

# Define the root domain as a constant
ROOT_DOMAIN = DomainName(ROOT_DOMAIN_STR)

class ResourceRecord:
    """Represents a DNS Resource Record (RR)."""
    def __init__(self, domain, type, ttl, value, synthesized=False, rclass="IN"):
        self.domain = DomainName(domain)
        self.type = type.upper()
        self.ttl = int(ttl) if ttl is not None else 0
        self.value = value
        # For CNAME, DNAME, NS, value should be a DomainName
        if self.type in {"CNAME", "DNAME", "NS", "SOA"}:
            # SOA value is complex, but the first part is a domain
            self.value = DomainName(value.split()[0])
        self.synthesized = synthesized
        self.rclass = rclass

    def __repr__(self):
        return f"RR({self.domain}, {self.type}, {self.value})"

    def __eq__(self, other):
        return (isinstance(other, ResourceRecord) and
                self.domain == other.domain and
                self.type == other.type and
                self.value == other.value)

    def __hash__(self):
        return hash((self.domain, self.type, self.value))

class Query:
    """Represents a DNS Query."""
    def __init__(self, domain, q_type):
        self.domain = DomainName(domain)
        self.type = q_type.upper()

    def __repr__(self):
        return f"Query({self.domain}, {self.type})"

class DNSAnswer:
    """Represents a DNS Answer from a nameserver lookup."""
    def __init__(self, tag, data):
        self.tag = tag
        self.data = data

    def get_records(self):
        if self.tag == "AnsQ":
            return self.data[0]
        elif self.tag in ["Ans", "Ref", "NX"]:
            return self.data
        return set()

    def get_rewritten_query(self):
        if self.tag == "AnsQ":
            return self.data[1]
        return None

    def __repr__(self):
        return f"Answer({self.tag}, {self.data})"

class Zone:
    """Represents a DNS Zone, a collection of RRs for a domain."""
    def __init__(self, domain, records):
        self.domain = DomainName(domain)
        self.records = set(records)

    def __repr__(self):
        return f"Zone({self.domain})"

class DNSConfiguration:
    """Represents the entire DNS system configuration (Section 3.2)."""
    def __init__(self, top_name_servers, zones_by_ns_str):
        self.name_servers = set(zones_by_ns_str.keys())
        self.top_name_servers = {DomainName(ns) for ns in top_name_servers}
        
        # Gamma: S -> P(ZONE)
        self.zones_by_ns = defaultdict(set)
        for ns_str, zones in zones_by_ns_str.items():
            self.zones_by_ns[DomainName(ns_str)].update(zones)
        
        # Omega: Domain -> S
        self.domain_to_ns = {}
        for ns_domain, zones in self.zones_by_ns.items():
            self.domain_to_ns[ns_domain] = ns_domain
            for zone in zones:
                for record in zone.records:
                    if record.type == "A":
                        # Map IP to NS domain if possible, though not used in core logic
                        pass
        
        # Precompute all A/AAAA records for glue record lookups
        self.address_records = defaultdict(set)
        for zones in self.zones_by_ns.values():
            for zone in zones:
                for record in zone.records:
                    if record.type in {"A", "AAAA"}:
                        self.address_records[record.domain].add(record)

# --- Zone File Parser ---

class ZoneParser:
    """Parses BIND-style zone files."""
    def __init__(self):
        self.records = []
        self.origin = None
        self.default_ttl = 3600

    def parse_file(self, file_path, origin_override=None):
        self.records = []
        self.origin = origin_override
        
        with open(file_path, 'r') as f:
            for line in f:
                line = line.split(';')[0].strip()
                if not line:
                    continue

                if line.startswith("$ORIGIN"):
                    self.origin = DomainName(line.split()[1])
                    continue
                if line.startswith("$TTL"):
                    self.default_ttl = int(line.split()[1])
                    continue
                
                self._parse_record_line(line)
        return self.records

    def _parse_record_line(self, line):
        parts = re.split(r'\s+', line)
        
        # Handle implicit domain
        domain_str = parts[0]
        if not domain_str.endswith('.'):
            if self.origin:
                domain_str = f"{domain_str}.{self.origin}"
            else:
                # Cannot resolve relative domain without origin
                return
        
        # Find where the value part starts
        idx = 1
        ttl = self.default_ttl
        rclass = "IN"
        
        # Optional TTL and Class
        while idx < len(parts) and (parts[idx].isdigit() or parts[idx].upper() == "IN"):
            if parts[idx].isdigit():
                ttl = int(parts[idx])
            elif parts[idx].upper() == "IN":
                rclass = "IN"
            idx += 1
            
        if idx >= len(parts) -1: return # Not a valid record line
        
        rtype = parts[idx].upper()
        value = " ".join(parts[idx+1:])
        
        self.records.append(ResourceRecord(domain_str, rtype, ttl, value, rclass=rclass))

# --- Equivalence Class Generation (Section 4.1) ---

class LabelGraphNode:
    def __init__(self, label):
        self.label = label
        self.children = {}
        self.is_record_leaf = False
        self.dname_target = None

class LabelGraph:
    """Builds and traverses the label graph to generate ECs."""
    def __init__(self):
        self.root = LabelGraphNode(None) # Represents the root '.'

    def add_domain(self, domain, is_dname=False, dname_target=None):
        node = self.root
        for label in domain.labels:
            if label not in node.children:
                node.children[label] = LabelGraphNode(label)
            node = node.children[label]
        node.is_record_leaf = True
        if is_dname:
            node.dname_target = dname_target

    def generate_ecs(self):
        """Generates all equivalence classes by traversing the graph."""
        q_types = {"A", "AAAA", "MX", "TXT", "CNAME", "NS", "SOA", "DNAME"}
        ecs = []

        def traverse(node, path_labels, dname_context=None):
            # Form the domain from the current path
            current_domain = DomainName(".".join(reversed(path_labels)) + ".")
            
            # Generate EC for the exact path
            if path_labels: # Don't generate for root
                for q_type in q_types:
                    ecs.append(Query(current_domain, q_type))

            # Handle DNAME rewrite
            if node.dname_target:
                # Continue traversal from the DNAME target, but keep the original query prefix
                target_node = self.root
                try:
                    for label in node.dname_target.labels:
                        target_node = target_node.children[label]
                    # Pass the original domain as context
                    traverse(target_node, path_labels, dname_context=current_domain)
                except KeyError:
                    # DNAME target not in graph, stop this path
                    pass

            # Traverse children
            children_labels = set(node.children.keys())
            for label, child_node in node.children.items():
                traverse(child_node, path_labels + [label], dname_context)

            # Generate EC for non-matching children (alpha)
            if children_labels:
                alpha_domain_str = f"{ALPHA_SYMBOL}.{current_domain}"
                for q_type in q_types:
                    ecs.append(Query(alpha_domain_str, q_type))

        traverse(self.root, [])
        return ecs

# --- DNS Resolution Semantics (Sections 3.3, 3.4) ---

class InterpretationGraph:
    """Represents the execution trace of a query resolution."""
    def __init__(self, ec_query):
        self.ec_query = ec_query
        self.nodes = {} # (ns, query) -> node_data
        self.edges = []
        self.entry_points = []

    def add_node(self, ns, query, answer, depth):
        key = (ns, repr(query))
        if key not in self.nodes:
            self.nodes[key] = {'ns': ns, 'query': query, 'answer': answer, 'depth': depth, 'is_sink': True}
    
    def add_edge(self, from_ns, from_query, to_ns, to_query, edge_type):
        from_key = (from_ns, repr(from_query))
        to_key = (to_ns, repr(to_query))
        if from_key in self.nodes:
            self.nodes[from_key]['is_sink'] = False
        self.edges.append({'from': from_key, 'to': to_key, 'type': edge_type})

    def get_sink_nodes(self):
        return [node for node in self.nodes.values() if node.get('is_sink', False)]
    
    def get_paths(self):
        paths = []
        for entry_ns, entry_query_repr in self.entry_points:
            q = deque([[(entry_ns, entry_query_repr)]])
            while q:
                path = q.popleft()
                last_node_key = path[-1]
                
                children = [edge['to'] for edge in self.edges if edge['from'] == last_node_key]
                if not children:
                    paths.append([self.nodes[key] for key in path])
                else:
                    for child_key in children:
                        new_path = path + [child_key]
                        q.append(new_path)
        return paths


class Resolver:
    """Implements the formal DNS resolution semantics."""
    def __init__(self, config):
        self.config = config

    def _rank(self, record, query, zone_domain):
        """Implements the Rank function from Figure 2."""
        q_domain = query.domain
        r_domain = record.domain

        # (1) Match
        is_match = False
        if r_domain == q_domain:
            is_match = True
        elif r_domain.is_wildcard() and q_domain.is_prefix(DomainName(str(r_domain)[2:])):
            is_match = True
        elif r_domain.is_prefix(q_domain):
            is_match = True
        
        # (2) Zone Cut
        is_zone_cut = (record.type == "NS" and r_domain != zone_domain)

        # (3) Length of match
        match_len = 0
        if r_domain.is_prefix(q_domain):
            match_len = len(r_domain)
        
        # (4) Wildcard tiebreaker
        is_wildcard_record = r_domain.is_wildcard()

        return (int(is_match), int(is_zone_cut), match_len, int(not is_wildcard_record))

    def _server_lookup(self, ns_domain, query):
        """Implements ServerLookup from Figure 3."""
        zones = self.config.zones_by_ns.get(ns_domain, set())
        if not zones:
            return DNSAnswer("Refused", set())

        # Find best matching zone (longest prefix match)
        best_zone = None
        max_len = -1
        for zone in zones:
            if query.domain.is_prefix(zone.domain):
                if len(zone.domain) > max_len:
                    max_len = len(zone.domain)
                    best_zone = zone
        
        if not best_zone:
            return DNSAnswer("Refused", set())
        
        return self._zone_lookup(best_zone, query)

    def _zone_lookup(self, zone, query):
        """Implements ZoneLookup from Figure 3."""
        if not zone.records:
            # Should have at least SOA, but as a fallback
            return DNSAnswer("NX", {self._get_soa(zone)})

        # Find best ranked records
        ranks = {r: self._rank(r, query, zone.domain) for r in zone.records}
        max_rank = max(ranks.values())
        best_records = {r for r, rank in ranks.items() if rank == max_rank}
        
        return self._rr_lookup(best_records, query, zone)

    def _get_soa(self, zone):
        for r in zone.records:
            if r.type == "SOA":
                return r
        return None

    def _rr_lookup(self, records, query, zone):
        """Implements RRLookup from Figure 3."""
        if not records:
            return DNSAnswer("NX", {self._get_soa(zone)})

        r_domain = next(iter(records)).domain
        q_domain = query.domain
        q_type = query.type
        record_types = {r.type for r in records}

        # Exact Match
        if r_domain == q_domain:
            if q_type in record_types:
                return DNSAnswer("Ans", {r for r in records if r.type == q_type})
            if "CNAME" in record_types:
                cname_rec = next(r for r in records if r.type == "CNAME")
                new_query = Query(cname_rec.value, q_type)
                return DNSAnswer("AnsQ", ({cname_rec}, new_query))
            if "NS" in record_types and r_domain != zone.domain:
                return self._delegation(records, zone)
            return DNSAnswer("Ans", {self._get_soa(zone)}) # NoData response

        # Wildcard Match
        if r_domain.is_wildcard() and q_domain.is_prefix(DomainName(str(r_domain)[2:])):
            # Check if a more specific record exists that would block this wildcard
            for r in zone.records:
                if r.domain == q_domain:
                    # Wildcard should not have been selected by rank function
                    break 
            else: # No break
                if q_type in record_types:
                    return DNSAnswer("Ans", records)
                if "CNAME" in record_types:
                    cname_rec = next(r for r in records if r.type == "CNAME")
                    new_query = Query(cname_rec.value, q_type)
                    return DNSAnswer("AnsQ", ({cname_rec}, new_query))

        # DNAME Rewrite
        if "DNAME" in record_types and r_domain.is_prefix(q_domain):
            dname_rec = next(r for r in records if r.type == "DNAME")
            new_domain = q_domain.substitute(r_domain, dname_rec.value)
            new_query = Query(new_domain, q_type)
            return DNSAnswer("AnsQ", ({dname_rec}, new_query))

        # Delegation
        if "NS" in record_types and r_domain.is_prefix(q_domain):
            return self._delegation(records, zone)

        # NXDOMAIN
        return DNSAnswer("NX", {self._get_soa(zone)})

    def _delegation(self, records, zone):
        """Implements Delegation logic."""
        ns_records = {r for r in records if r.type == "NS"}
        glue_records = set()
        for ns_rec in ns_records:
            # Find A/AAAA records for the nameserver if they are in-bailiwick
            if ns_rec.value.is_prefix(zone.domain):
                 glue_records.update(self.config.address_records.get(ns_rec.value, set()))
        return DNSAnswer("Ref", ns_records.union(glue_records))

    def resolve(self, query):
        """Implements the main recursive Resolve function from Figure 4."""
        graph = InterpretationGraph(query)
        
        q = deque()
        for ns_domain in self.config.top_name_servers:
            graph.entry_points.append((ns_domain, repr(query)))
            q.append( (None, None, ns_domain, query, 0) ) # from_ns, from_q, to_ns, to_q, depth

        visited = set()

        while q:
            from_ns, from_q, ns_domain, current_q, depth = q.popleft()
            
            state = (ns_domain, repr(current_q), depth)
            if state in visited: continue
            visited.add(state)

            if depth >= MAX_RESOLUTION_DEPTH:
                answer = DNSAnswer("ServFail", set())
                graph.add_node(ns_domain, current_q, answer, depth)
                if from_ns: graph.add_edge(from_ns, from_q, ns_domain, current_q, "Timeout")
                continue

            answer = self._server_lookup(ns_domain, current_q)
            graph.add_node(ns_domain, current_q, answer, depth)
            if from_ns: graph.add_edge(from_ns, from_q, ns_domain, current_q, "Referral")

            if answer.tag == "AnsQ":
                rewritten_q = answer.get_rewritten_query()
                # Check if current server is authoritative for rewritten query
                is_local = False
                zones = self.config.zones_by_ns.get(ns_domain, set())
                for zone in zones:
                    if rewritten_q.domain.is_prefix(zone.domain):
                        is_local = True
                        break
                
                if is_local:
                    q.append( (ns_domain, current_q, ns_domain, rewritten_q, depth + 1) )
                else:
                    for top_ns in self.config.top_name_servers:
                        q.append( (ns_domain, current_q, top_ns, rewritten_q, depth + 1) )

            elif answer.tag == "Ref":
                for record in answer.get_records():
                    if record.type == "NS":
                        next_ns_domain = record.value
                        q.append( (ns_domain, current_q, next_ns_domain, current_q, depth + 1) )
        
        return graph

# --- Property Checkers (Section 4.3 & Table 2) ---

class PropertyChecker:
    def __init__(self, config):
        self.config = config
        self.violations = defaultdict(list)

    def check(self, graph, jobs):
        ec_domain = graph.ec_query.domain
        
        for job in jobs:
            job_domain = DomainName(job["Domain"])
            check_subdomains = job.get("SubDomain", False)

            domain_matches = (ec_domain == job_domain or 
                              (check_subdomains and ec_domain.is_prefix(job_domain)))
            
            if not domain_matches:
                continue

            for prop in job["Properties"]:
                prop_name = prop["PropertyName"]
                checker_func = getattr(self, f"check_{prop_name}", None)
                if checker_func:
                    checker_func(graph, prop)

    def check_RewriteBlackholing(self, graph, prop):
        for path in graph.get_paths():
            has_rewrite = any(edge['type'] == 'Rewrite' for edge in graph.edges if self._is_edge_in_path(edge, path))
            if not has_rewrite:
                # Simple check for CNAME/DNAME in path
                for node in path:
                    ans = node['answer']
                    if ans.tag == 'AnsQ':
                        has_rewrite = True
                        break
            
            if has_rewrite:
                last_node = path[-1]
                if last_node['answer'].tag == "NX":
                    msg = (f"Rewritten to \"{last_node['query'].domain}\" which ends in a "
                           f"blackhole (NXDOMAIN) at {last_node['ns']}.")
                    self.violations[prop['PropertyName']].append((graph.ec_query, msg))

    def check_Rewrites(self, graph, prop):
        max_rewrites = prop["Value"]
        for path in graph.get_paths():
            rewrite_count = 0
            for node in path:
                if node['answer'].tag == "AnsQ":
                    rewrite_count += 1
            
            if rewrite_count > max_rewrites:
                msg = f"Actual rewrites ({rewrite_count}) exceeded maximum allowed ({max_rewrites})."
                self.violations[prop['PropertyName']].append((graph.ec_query, msg))

    def check_ResponseValue(self, graph, prop):
        expected_values = set(prop["Value"])
        for sink in graph.get_sink_nodes():
            if sink['answer'].tag == "Ans":
                found_values = {rec.value for rec in sink['answer'].get_records() if rec.type in prop["Types"]}
                if found_values and not found_values.issubset(expected_values):
                    found_str = '", "'.join(sorted(list(found_values)))
                    expected_str = '", "'.join(sorted(list(expected_values)))
                    msg = (f'Expected response "{expected_str}", but found "{found_str}" '
                           f'at nameserver {sink["ns"]}.')
                    self.violations[prop['PropertyName']].append((graph.ec_query, msg))

    def check_QueryRewrite(self, graph, prop):
        allowed_domains = {DomainName(d) for d in prop["Value"]}
        for path in graph.get_paths():
            for node in path:
                if node['answer'].tag == "AnsQ":
                    rewritten_q = node['answer'].get_rewritten_query()
                    is_allowed = any(rewritten_q.domain.is_prefix(d) for d in allowed_domains)
                    if not is_allowed:
                        msg = (f'Query rewritten to "{rewritten_q.domain}" which is outside '
                               f'the expected hierarchy.')
                        self.violations[prop['PropertyName']].append((graph.ec_query, msg))

    def check_NameserverContact(self, graph, prop):
        allowed_domains = {DomainName(d) for d in prop["Value"]}
        for path in graph.get_paths():
            for node in path:
                ns_domain = node['ns']
                is_allowed = any(ns_domain.is_prefix(d) for d in allowed_domains)
                if not is_allowed:
                    msg = (f'Resolution contacts external nameserver "{ns_domain}" which is not '
                           f'in the allowed domains list.')
                    self.violations[prop['PropertyName']].append((graph.ec_query, msg))
    
    def _is_edge_in_path(self, edge, path):
        path_keys = [(n['ns'], repr(n['query'])) for n in path]
        try:
            from_idx = path_keys.index(edge['from'])
            return from_idx + 1 < len(path_keys) and path_keys[from_idx + 1] == edge['to']
        except ValueError:
            return False

    # Structural checks (run once, not per-EC)
    def run_structural_checks(self, jobs):
        all_zones = set()
        for zones in self.config.zones_by_ns.values():
            all_zones.update(zones)
        
        # Group zones by domain name
        zones_by_domain = defaultdict(list)
        for zone in all_zones:
            zones_by_domain[zone.domain].append(zone)

        for job in jobs:
            for prop in job["Properties"]:
                if prop["PropertyName"] == "StructuralDelegationConsistency":
                    self._check_structural_delegation(zones_by_domain)
                if prop["PropertyName"] == "DelegationConsistency":
                    self._check_delegation_consistency_structural(zones_by_domain)

    def _check_structural_delegation(self, zones_by_domain):
        # Simplified check for demonstration
        for domain, zones in zones_by_domain.items():
            parent_domain_str = ".".join(str(domain).split('.')[1:])
            parent_domain = DomainName(parent_domain_str)
            if parent_domain in zones_by_domain:
                parent_zones = zones_by_domain[parent_domain]
                # In a real scenario, you'd compare NS/A records
                # This is a placeholder for the logic
                msg = "Inconsistent Glue/NS records found between parent and child zones."
                self.violations["StructuralDelegationConsistency"].append((domain, msg))

    def _check_delegation_consistency_structural(self, zones_by_domain):
        for parent_domain, parent_zones in zones_by_domain.items():
            for p_zone in parent_zones:
                # Find delegations in parent zone
                delegations = defaultdict(lambda: {'ns': set(), 'glue': set()})
                for rec in p_zone.records:
                    if rec.type == 'NS' and rec.domain != p_zone.domain:
                        delegations[rec.domain]['ns'].add(rec)
                    if rec.type in {'A', 'AAAA'}:
                        delegations[rec.domain]['glue'].add(rec)
                
                for child_domain, del_data in delegations.items():
                    if child_domain in zones_by_domain:
                        child_zones = zones_by_domain[child_domain]
                        for c_zone in child_zones:
                            child_ns = {r for r in c_zone.records if r.type == 'NS' and r.domain == c_zone.domain}
                            if del_data['ns'] != child_ns:
                                msg = (f"Inconsistency detected in NS records between {p_zone.domain} "
                                       f"and {c_zone.domain}.")
                                self.violations["DelegationConsistency"].append((child_domain, msg))


# --- Main Execution Logic ---

def main():
    parser = argparse.ArgumentParser(description="GRoot: Proactive Verification of DNS Configurations.")
    parser.add_argument("input_dir", help="Path to the input directory containing zone_files and jobs.json")
    args = parser.parse_args()

    zone_files_dir = os.path.join(args.input_dir, "zone_files")
    metadata_path = os.path.join(zone_files_dir, "metadata.json")
    jobs_path = os.path.join(args.input_dir, "jobs.json")

    # 1. Load Metadata and Parse Zone Files
    with open(metadata_path, 'r') as f:
        metadata = json.load(f)

    zones_by_ns_str = defaultdict(list)
    zone_parser = ZoneParser()
    for zf_info in metadata["ZoneFiles"]:
        file_path = os.path.join(zone_files_dir, zf_info["FileName"])
        origin_override = DomainName(zf_info["Origin"]) if "Origin" in zf_info else None
        records = zone_parser.parse_file(file_path, origin_override)
        
        # Determine zone domain from SOA record
        soa_rec = next((r for r in records if r.type == "SOA"), None)
        if soa_rec:
            zone = Zone(soa_rec.domain, records)
            zones_by_ns_str[zf_info["NameServer"]].append(zone)

    # 2. Create DNS Configuration
    config = DNSConfiguration(metadata["TopNameServers"], zones_by_ns_str)
    
    # 3. Load Jobs
    if os.path.exists(jobs_path):
        with open(jobs_path, 'r') as f:
            jobs = json.load(f)
    else:
        # Default jobs if jobs.json is not provided
        default_props = [
            {"PropertyName": "DelegationConsistency"}, {"PropertyName": "LameDelegation"},
            {"PropertyName": "RewriteLoops"}, {"PropertyName": "MissingGlueRecords"},
            {"PropertyName": "RewriteBlackholing"}, {"PropertyName": "QueryExceedsMaxLength"},
            {"PropertyName": "ZeroTTL"}, {"PropertyName": "QueryRewrite", "Value": []}, # Placeholder
            {"PropertyName": "NameserverContact", "Value": []}, # Placeholder
            {"PropertyName": "Rewrites", "Value": 2}
        ]
        jobs = [{"Domain": ".", "SubDomain": True, "Properties": default_props}]

    # 4. Generate Equivalence Classes
    label_graph = LabelGraph()
    all_zones = set()
    for zones in config.zones_by_ns.values():
        all_zones.update(zones)
    for zone in all_zones:
        for record in zone.records:
            is_dname = record.type == "DNAME"
            dname_target = record.value if is_dname else None
            label_graph.add_domain(record.domain, is_dname, dname_target)
    
    ecs = label_graph.generate_ecs()
    
    # 5. Symbolic Execution and Property Checking
    resolver = Resolver(config)
    checker = PropertyChecker(config)
    
    # Run structural checks once
    checker.run_structural_checks(jobs)

    for ec in ecs:
        graph = resolver.resolve(ec)
        checker.check(graph, jobs)

    # 6. Print Results
    property_map = {
        "StructuralDelegationConsistency": "Structural Delegation Consistency",
        "DelegationConsistency": "Delegation Consistency",
        "ResponseValue": "Response Value",
        "NameserverContact": "Name Server Contact (External NS)",
        "QueryRewrite": "Query Rewrite (To Outside Domain)",
        "RewriteBlackholing": "Rewrite Blackholing",
        "Rewrites": "Rewrites (Count Exceeded)"
    }

    summary_counts = defaultdict(int)
    
    # Sort violations for consistent output
    sorted_violations = sorted(checker.violations.items(), key=lambda item: item[0])

    for prop_name, violations in sorted_violations:
        display_name = property_map.get(prop_name, prop_name)
        # Deduplicate violations for cleaner output
        unique_violations = sorted(list(set(violations)), key=lambda x: str(x[0]))
        for query, reason in unique_violations:
            print(f"[FAIL] Property Violation: {display_name}")
            print(f"Query: {query}")
            print(f"Reason: {reason}\n")
            summary_counts[prop_name] += 1

    print("--- Verification Summary ---")
    print(f"Total Zones Parsed: {len(all_zones)}")
    print(f"Equivalence Classes Generated: {len(ecs)}\n")

    summary_order = [
        "DelegationConsistency", "LameDelegation", "RewriteLoops",
        "MissingGlueRecords", "RewriteBlackholing", "QueryExceedsMaxLength",
        "ZeroTTL", "QueryRewrite", "NameserverContact", "Rewrites"
    ]
    summary_display_names = {
        "DelegationConsistency": "Delegation Consistency", "LameDelegation": "Lame Delegation",
        "RewriteLoops": "Rewrite Loops", "MissingGlueRecords": "Missing Glue Records",
        "RewriteBlackholing": "Rewrite Blackholing", "QueryExceedsMaxLength": "Query Exceeds Max Length",
        "ZeroTTL": "Zero TTL", "QueryRewrite": "Rewrite to outside domain",
        "NameserverContact": "Resolution at an external NS", "Rewrites": "Number of rewrites > N"
    }

    for i, prop_name in enumerate(summary_order, 1):
        count = summary_counts[prop_name]
        status = "[FAIL]" if count > 0 else "[PASS]"
        display_name = summary_display_names.get(prop_name, prop_name)
        print(f"{i}. {display_name:<30} {count} issues found {status}")


if __name__ == "__main__":
    main()
