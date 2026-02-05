
import os
import json
import zone_parser
from dns_defs import Zone
from groot_core import GrootEngine, build_label_graph, generate_ecs
import checkers

def create_file(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f: f.write(content)

def setup_test1():
    base = "datasets/test1/input/zone_files"
    meta = {
        "TopNameServers": ["us.illinois.net."],
        "ZoneFiles": [
            {"FileName": "cc.il.us..txt", "NameServer": "us.illinois.net."},
            {"FileName": "richland.cc.il.us..txt", "NameServer": "ns1.richland.cc.il.us.", "Origin": "richland.cc.il.us."},
            {"FileName": "child.richland.cc.il.us..txt", "NameServer": "ns1.child.richland.cc.il.us."},
            {"FileName": "child.richland.cc.il.us.-2.txt", "NameServer": "ns2.child.richland.cc.il.us."}
        ]
    }
    create_file(f"{base}/metadata.json", json.dumps(meta, indent=4))
    
    jobs = [
        {"Domain": "child.richland.cc.il.us.", "SubDomain": False, "Properties": [{"PropertyName": "DelegationConsistency"}]},
        {"Domain": "gw1.richland.cc.il.us.", "SubDomain": False, "Properties": [{"PropertyName": "ResponseConsistency"}, {"PropertyName": "ResponseValue", "Value": ["64.107.104.4"]}]},
        {"Domain": "child.richland.cc.il.us.", "SubDomain": True, "Properties": [{"PropertyName": "ResponseConsistency"}, {"PropertyName": "RewriteBlackholing"}]},
        {"Domain": "ds3.richland.cc.il.us.", "SubDomain": False, "Properties": [{"PropertyName": "ResponseReturned"}]},
        {"Domain": "cc.il.us.", "SubDomain": True, "Properties": [
            {"PropertyName": "QueryRewrite", "Value": ["illinois.net.", "cc.il.us."]},
            {"PropertyName": "Rewrites", "Value": 1},
            {"PropertyName": "NameserverContact", "Value": ["edu.", "net.", "cc.il.us."]},
            {"PropertyName": "StructuralDelegationConsistency"}
        ]}
    ]
    create_file("datasets/test1/input/jobs.json", json.dumps(jobs, indent=4))
    
    z1 = """
$ORIGIN cc.il.us.
@ IN SOA ns1.cc.il.us. hostmaster.cc.il.us. 1 1 1 1 1
@ IN NS us.illinois.net.
rwhois IN CNAME us.illlinois.net.
richland IN NS ns1.richland.cc.il.us.
ns1.richland.cc.il.us. IN A 1.2.3.4
clc IN NS ns1.clc.cc.il.us.
clc IN NS ns1.illinois.nt.
ns1.clc.cc.il.us. IN A 1.2.3.5
child.trial IN NS ns1.child.trial.cc.il.us.
ds3.trial IN CNAME mid.trial.cc.il.us.
mid.trial IN CNAME final.trial.cc.il.us.
"""
    create_file(f"{base}/cc.il.us..txt", z1)
    
    z2 = """
$ORIGIN richland.cc.il.us.
@ IN SOA ns1.richland.cc.il.us. hostmaster.richland.cc.il.us. 1 1 1 1 1
@ IN NS ns1.richland.cc.il.us.
gw1 IN A 64.107.104.3
child IN NS ns1.child.richland.cc.il.us.
child IN NS ns2.child.richland.cc.il.us.
ns1.child IN A 10.0.0.1
ns2.child IN A 10.0.0.2
"""
    create_file(f"{base}/richland.cc.il.us..txt", z2)
    
    z3 = """
$ORIGIN child.richland.cc.il.us.
@ IN SOA ns1.child.richland.cc.il.us. hostmaster.child.richland.cc.il.us. 1 1 1 1 1
@ IN NS ns1.child.richland.cc.il.us.
darwin IN CNAME intermediate.child.richland.cc.il.us.
intermediate IN CNAME fusion.child.richland.cc.il.us.
uranus IN CNAME intermediate.child.richland.cc.il.us.
"""
    create_file(f"{base}/child.richland.cc.il.us..txt", z3)

    z4 = """
$ORIGIN child.richland.cc.il.us.
@ IN SOA ns2.child.richland.cc.il.us. hostmaster.child.richland.cc.il.us. 1 1 1 1 1
@ IN NS ns2.child.richland.cc.il.us.
"""
    create_file(f"{base}/child.richland.cc.il.us.-2.txt", z4)

def setup_test2():
    base = "datasets/test2/input/zone_files"
    meta = {
        "TopNameServers": ["ns1.foo.com."],
        "ZoneFiles": [{"FileName": "foo.com.txt", "NameServer": "ns1.foo.com."}]
    }
    create_file(f"{base}/metadata.json", json.dumps(meta, indent=4))
    
    jobs = [{"Domain": "foo.com.", "SubDomain": True, "Properties": [{"PropertyName": "Rewrites", "Value": 4}]}]
    create_file("datasets/test2/input/jobs.json", json.dumps(jobs, indent=4))
    
    z1 = """
$ORIGIN foo.com.
@ IN SOA ns1.foo.com. hostmaster.foo.com. 1 1 1 1 1
@ IN NS ns1.foo.com.
*.a IN CNAME b.a.foo.com.
b.a IN CNAME c.a.foo.com.
c.a IN CNAME d.a.foo.com.
d.a IN CNAME e.a.foo.com.
e.a IN CNAME f.a.foo.com.
f.a IN A 1.1.1.1
"""
    create_file(f"{base}/foo.com.txt", z1)

def main():
    setup_test1()
    setup_test2()
    
    for test in ['test1', 'test2']:
        print(f"--- Running {test} ---")
        input_dir = f"datasets/{test}/input/zone_files"
        job_dir = f"datasets/{test}/input"
        top_ns, zones = zone_parser.load_dataset(input_dir)
        jobs = zone_parser.load_jobs(job_dir)
        engine = GrootEngine(top_ns, zones)
        results = checkers.run_checks(engine, jobs)
        
        seen = set()
        for r in results:
            if r not in seen:
                print(r + "\n")
                seen.add(r)
        
        print("--- Verification Summary ---")
        print(f"Total Zones Parsed: {len(zones)}")
        root = build_label_graph(zones)
        ecs = generate_ecs(root)
        print(f"Equivalence Classes Generated: {len(ecs)}")
        
        summary = {
            "Delegation Consistency": 0, "Lame Delegation": 0, "Rewrite Loops": 0, "Missing Glue Records": 0,
            "Rewrite Blackholing": 0, "Query Exceeds Max Length": 0, "Zero TTL": 0,
            "Rewrite to outside domain": 0, "Resolution at an external NS": 0, "Number of rewrites > 2": 0
        }
        
        for r in results:
            if "Delegation Consistency" in r: summary["Delegation Consistency"] += 1
            if "Rewrite Blackholing" in r: summary["Rewrite Blackholing"] += 1
            if "Rewrites (Count Exceeded)" in r: summary["Number of rewrites > 2"] += 1
            if "Query Rewrite" in r: summary["Rewrite to outside domain"] += 1
            if "Name Server Contact" in r: summary["Resolution at an external NS"] += 1
            
        keys = ["Delegation Consistency", "Lame Delegation", "Rewrite Loops", "Missing Glue Records",
                "Rewrite Blackholing", "Query Exceeds Max Length", "Zero TTL", "Rewrite to outside domain",
                "Resolution at an external NS", "Number of rewrites > 2"]
        
        for i, key in enumerate(keys, 1):
            status = "[FAIL]" if summary.get(key, 0) > 0 else "[PASS]"
            print(f"{i}. {key:<30} {summary.get(key, 0)} issues found {status}")

if __name__ == "__main__":
    main()
