
import os
import json
from dns_defs import Record, Zone

def parse_zone_file(filepath, origin, server_name):
    records = []
    current_origin = origin
    if not current_origin.endswith('.'):
        current_origin += '.'
    
    prev_name = current_origin

    if not os.path.exists(filepath):
        # 如果文件不存在，返回空区域以防崩溃
        return Zone(origin, server_name)

    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith(';'):
                continue
            
            if ';' in line:
                line = line.split(';')[0].strip()
            
            parts = line.split()
            if not parts: continue

            if parts[0] == '$ORIGIN':
                current_origin = parts[1]
                if not current_origin.endswith('.'):
                    current_origin += '.'
                continue

            idx = 0
            name = parts[0]
            if name == '@':
                name = current_origin
                idx += 1
            elif name == '': 
                name = prev_name
            elif not name[0].isspace():
                if not name.endswith('.'):
                    name = f"{name}.{current_origin}"
                idx += 1
            else:
                name = prev_name
            
            prev_name = name
            ttl = "3600"
            rclass = "IN"
            
            while idx < len(parts):
                if parts[idx] in ['IN', 'CS', 'CH', 'HS']:
                    rclass = parts[idx]
                    idx += 1
                elif parts[idx].isdigit():
                    ttl = parts[idx]
                    idx += 1
                else:
                    break
            
            if idx >= len(parts): continue
                
            rtype = parts[idx]
            idx += 1
            rdata = parts[idx:]
            
            if rtype in ['NS', 'CNAME', 'DNAME', 'PTR', 'MX']:
                if rtype == 'MX':
                    pref = rdata[0]
                    target = rdata[1]
                    if not target.endswith('.'): target = f"{target}.{current_origin}"
                    rdata_val = target 
                else:
                    target = rdata[0]
                    if not target.endswith('.'): target = f"{target}.{current_origin}"
                    rdata_val = target
            elif rtype == 'SOA':
                 mname = rdata[0]
                 if not mname.endswith('.'): mname += f".{current_origin}"
                 rdata_val = mname
            else:
                rdata_val = " ".join(rdata)

            records.append(Record(name, rtype, rclass, ttl, rdata_val))

    zone = Zone(origin, server_name)
    for r in records:
        zone.add_record(r)
    return zone

def load_dataset(input_dir):
    meta_path = os.path.join(input_dir, 'metadata.json')
    if not os.path.exists(meta_path):
        return [], []

    with open(meta_path, 'r') as f:
        meta = json.load(f)
    
    loaded_zones = []
    zone_files_dir = input_dir
    
    for zf in meta['ZoneFiles']:
        fname = zf['FileName']
        server = zf['NameServer']
        origin = zf.get('Origin')
        if not origin:
            base = os.path.basename(fname)
            if base.endswith('.txt'): base = base[:-4]
            origin = base
        
        path = os.path.join(zone_files_dir, fname)
        if os.path.exists(path):
            zone = parse_zone_file(path, origin, server)
            loaded_zones.append(zone)
        else:
            # 即使文件还没创建，也先创建一个空对象占位
            loaded_zones.append(Zone(origin, server))
    
    return meta['TopNameServers'], loaded_zones

def load_jobs(input_dir):
    p = os.path.join(input_dir, 'jobs.json')
    if os.path.exists(p):
        with open(p, 'r') as f: return json.load(f)
    return []
