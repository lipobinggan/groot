
from groot_core import build_label_graph, generate_ecs

def check_delegation_consistency(engine, domain, sub_domain_mode):
    issues = []
    for (s_name, z_name), zone in engine.zone_map.items():
        if sub_domain_mode:
            if not z_name.endswith(domain): continue
        else:
            if z_name != domain: continue
            
        parent_zone = None
        best_len = -1
        for (ps_name, pz_name), p_zone in engine.zone_map.items():
            if pz_name == z_name: continue
            if z_name.endswith(pz_name):
                if len(pz_name) > best_len:
                    best_len = len(pz_name)
                    parent_zone = p_zone
        
        if not parent_zone: continue
        
        parent_ns = parent_zone.get_records(z_name, 'NS')
        child_ns = zone.get_records(z_name, 'NS')
        p_ns_set = set(r.rdata for r in parent_ns)
        c_ns_set = set(r.rdata for r in child_ns)
        
        if p_ns_set != c_ns_set:
            issues.append({'query': z_name, 'reason': f"Inconsistency detected in NS records between {parent_zone.server_name} and {zone.server_name}."})
    return issues

def run_checks(engine, jobs):
    results = []
    all_zones = [z for z in engine.zone_map.values()]
    root = build_label_graph(all_zones)
    ecs = generate_ecs(root)
    
    for job in jobs:
        domain = job['Domain']
        is_sub = job['SubDomain']
        props = job['Properties']
        
        target_ecs = []
        for ec in ecs:
            match = False
            clean_ec = ec.replace("~{}.", "")
            if is_sub:
                if clean_ec.endswith(domain): match = True
            else:
                if clean_ec == domain: match = True
            if match: target_ecs.append(ec)
        
        for ec in target_ecs:
            concrete_q = ec.replace("~{}", "testlabel")
            check_types = ["A"]
            for p in props:
                if 'Types' in p: check_types = p['Types']
            
            for qtype in check_types:
                final_states, graph, visited, external_ns = engine.resolve(concrete_q, qtype)
                
                for prop in props:
                    pname = prop['PropertyName']
                    
                    if pname == 'StructuralDelegationConsistency':
                         issues = check_delegation_consistency(engine, ec.replace("~{}.", ""), False)
                         for i in issues:
                             results.append(f"[FAIL] Property Violation: Structural Delegation Consistency\nQuery: {i['query']}\nReason: {i['reason']}")
                    elif pname == 'ResponseValue':
                        expected = prop.get('Value', [])
                        for s in final_states:
                            if s['type'] == 'ANSWER':
                                ips = [r.rdata for r in s['records']]
                                if not set(expected).intersection(set(ips)):
                                     results.append(f"[FAIL] Property Violation: Response Value\nQuery: {concrete_q}\nReason: Expected response \"{expected[0]}\", but found \"{ips[0] if ips else ''}\" at nameserver {s['ns']}")
                    elif pname == 'RewriteBlackholing':
                         for s in final_states:
                             if s['type'] == 'NXDOMAIN':
                                 has_rewrite = any(x[1] != concrete_q for x in visited)
                                 if has_rewrite:
                                     results.append(f"[FAIL] Property Violation: Rewrite Blackholing\nQuery: {concrete_q}\nReason: Rewritten to ... which ends in a blackhole (NXDOMAIN) at {s['ns']}")
                    elif pname == 'Rewrites':
                        limit = prop.get('Value', 0)
                        qs = set(v[1] for v in visited)
                        count = len(qs) - 1
                        if count > limit:
                             results.append(f"[FAIL] Property Violation: Rewrites (Count Exceeded)\nQuery: {concrete_q}\nReason: Actual rewrites ({count}) exceeded maximum allowed ({limit}).")
                    elif pname == 'NameserverContact':
                        allowed = set(prop.get('Value', []))
                        for ext in external_ns:
                            valid = False
                            for a in allowed:
                                if ext.endswith(a): valid = True
                            if not valid:
                                results.append(f"[FAIL] Property Violation: Name Server Contact (External NS)\nQuery: {concrete_q}\nReason: Resolution contacts external nameserver \"{ext}\" which is not in the allowed domains list.")
                    elif pname == 'QueryRewrite':
                        for v in visited:
                            q_name = v[1]
                            allowed_suffixes = prop.get('Value', [])
                            valid = False
                            for suff in allowed_suffixes:
                                if q_name.endswith(suff): valid = True
                            if not valid:
                                results.append(f"[FAIL] Property Violation: Query Rewrite (To Outside Domain)\nQuery: {concrete_q}\nReason: Query rewritten to \"{q_name}\" which is outside the expected hierarchy.")
                    elif pname == 'DelegationConsistency':
                        issues = check_delegation_consistency(engine, ec.replace("~{}.", ""), False)
                        for i in issues:
                             results.append(f"[FAIL] Property Violation: Delegation Consistency\nQuery: {i['query']}\nReason: {i['reason']}")

    return results
