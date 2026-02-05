import json
import os
from typing import List, Dict, Set, Tuple, Union

from data_structure.configuration import DNSConfigurationObject
from data_structure.dataset_input import Metadata
from data_structure.dns_entities import ZoneMap, Zone, ResourceRecord

def parse_zone_file(file_path: str) -> List[ResourceRecord]:
        """
        Parses a zone file into a list of ResourceRecord dictionaries.
        Handles standard RFC-style zone file lines, including parentheses for multiline records.
        """
        import shlex
        
        records: List[ResourceRecord] = []
        if not os.path.exists(file_path):
            print(f"Warning: Zone file not found: {file_path}")
            return records

        RR_TYPES = {"A", "AAAA", "NS", "CNAME", "SOA", "MX", "TXT", "PTR", "SRV", "DNAME"}
        
        last_name = ""
        default_ttl = 0
        
        try:
            with open(file_path, 'r') as f:
                raw_content = f.read()
                
            # Pre-process to handle parentheses (multiline records)
            processed_lines = []
            
            lines = raw_content.split('\n')
            
            buffer = []
            paren_balance = 0
            
            for line in lines:
                # Remove comments (simple split on ';')
                if ';' in line:
                    line = line.split(';', 1)[0]
                
                stripped = line.strip()
                if not stripped:
                    continue
                
                open_count = line.count('(')
                close_count = line.count(')')
                
                if paren_balance == 0 and open_count == 0:
                    processed_lines.append(line)
                    continue
                
                if paren_balance == 0:
                    buffer = [line]
                else:
                    buffer.append(line)
                    
                paren_balance += (open_count - close_count)
                
                if paren_balance <= 0:
                    full_line = " ".join(buffer)
                    # Remove parentheses tokens safely
                    full_line = full_line.replace('(', ' ').replace(')', ' ')
                    processed_lines.append(full_line)
                    buffer = []
                    paren_balance = 0

            for line in processed_lines:
                # Handle directives
                if line.upper().strip().startswith("$TTL"):
                    parts = line.split()
                    if len(parts) > 1 and parts[1].isdigit():
                        default_ttl = int(parts[1])
                    continue
                if line.upper().strip().startswith("$ORIGIN"):
                    continue

                # Use shlex to handle quoted strings correctly
                try:
                    parts = shlex.split(line, posix=True)
                except ValueError:
                    parts = line.split()

                if not parts:
                    continue

                name = ""
                current_idx = 0
                
                # Heuristic: Check if first part is a keyword (Type, Class, TTL)
                first = parts[0].upper()
                is_keyword = (first in RR_TYPES) or (first in ["IN", "CH", "HS"]) or (first.isdigit())
                
                if is_keyword:
                    name = last_name
                else:
                    name = parts[0]
                    last_name = name
                    current_idx = 1
                
                if current_idx >= len(parts):
                    continue

                ttl = default_ttl
                rr_class = "IN"
                rr_type = ""
                
                type_index = -1
                for i in range(current_idx, len(parts)):
                    if parts[i].upper() in RR_TYPES:
                        type_index = i
                        break
                
                if type_index != -1:
                    rr_type = parts[type_index].upper()
                    
                    for token in parts[current_idx:type_index]:
                        if token.isdigit():
                            ttl = int(token)
                        elif token.upper() in ["IN", "CH", "HS"]:
                            rr_class = token.upper()
                    
                    rdata_parts = parts[type_index+1:]
                    rdata = " ".join(rdata_parts)
                else:
                    continue

                rr: ResourceRecord = {
                    "name": name,
                    "ttl": ttl,
                    "class_": rr_class,
                    "type": rr_type,
                    "rdata": rdata
                }
                records.append(rr)

        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
            
        return records
def input_parsing_and_configuration_initialization(dataset_path: str) -> Tuple[DNSConfigurationObject, ZoneMap]:
        """
        Parses the metadata and zone files to construct the DNS Configuration Object and ZoneMap.
        Follows the formal definition C = <S, Theta, Gamma, Omega>.
        """
        s_set: Set[str] = set()
        theta_set: Set[str] = set()
        gamma_dict: Dict[str, List[Zone]] = {}
        omega_dict: Dict[str, str] = {}
        domain_to_zone: Dict[str, Zone] = {}

        metadata_path = os.path.join(dataset_path, "metadata.json")
        meta: Dict = {}
        
        if os.path.exists(metadata_path):
            try:
                with open(metadata_path, 'r') as f:
                    meta = json.load(f)
            except json.JSONDecodeError as e:
                print(f"Error decoding metadata.json: {e}")
                return {"S": [], "Theta": [], "Gamma": {}, "Omega": {}}, {}
        else:
            print(f"Metadata file not found at {metadata_path}")
            return {"S": [], "Theta": [], "Gamma": {}, "Omega": {}}, {}

        def get_key(data: Dict, keys: List[str], default=None):
            for k in keys:
                if k in data:
                    return data[k]
            return default

        root_servers = get_key(meta, ["root_nameservers", "TopNameServers"], [])
        for root_server in root_servers:
            theta_set.add(root_server)
            s_set.add(root_server)

        zones_list = get_key(meta, ["zones", "ZoneFiles"], [])
        for zone_info in zones_list:
            z_name = get_key(zone_info, ["domain_name", "Origin"], "")
            file_name = get_key(zone_info, ["file_name", "FileName"], "")
            
            if not z_name or not file_name:
                continue

            z_file_path = os.path.join(dataset_path, file_name)
            parsed_records = parse_zone_file(z_file_path)

            zone_obj: Zone = {
                "origin": z_name,
                "records": parsed_records
            }
            domain_to_zone[z_name] = zone_obj

            ns_val = get_key(zone_info, ["authoritative_servers", "NameServer"])
            ns_list: List[str] = []
            if isinstance(ns_val, list):
                ns_list = ns_val
            elif isinstance(ns_val, str) and ns_val:
                ns_list = [ns_val]

            for ns_id in ns_list:
                s_set.add(ns_id)
                if ns_id not in gamma_dict:
                    gamma_dict[ns_id] = []
                
                if zone_obj not in gamma_dict[ns_id]:
                    gamma_dict[ns_id].append(zone_obj)

        for ns_name in s_set:
            omega_dict[ns_name] = ns_name

        config: DNSConfigurationObject = {
            "S": list(s_set),
            "Theta": list(theta_set),
            "Gamma": gamma_dict,
            "Omega": omega_dict
        }

        return config, domain_to_zone