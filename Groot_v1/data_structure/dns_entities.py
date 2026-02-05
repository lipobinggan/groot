from typing import TypedDict, List, Dict, Optional

class ResourceRecord(TypedDict):
    """
    This is a TypedDict. Instantiate using dict literals (e.g. {'key': val}).
    Access fields using brackets (e.g. obj['key']), NOT dot notation.
    
    Represents a single DNS Resource Record (RR).
    """
    name: str
    type: str
    ttl: int
    rdata: str
    class_: str

class Zone(TypedDict):
    """
    This is a TypedDict. Instantiate using dict literals (e.g. {'key': val}).
    Access fields using brackets (e.g. obj['key']), NOT dot notation.
    
    Represents a parsed DNS Zone containing multiple resource records.
    """
    origin: str
    records: List[ResourceRecord]

class ZoneMap(TypedDict):
    """
    This is a TypedDict. Instantiate using dict literals (e.g. {'key': val}).
    Access fields using brackets (e.g. obj['key']), NOT dot notation.
    
    Represents the mapping of Domain Names to their parsed Zones.
    Used by Step1 (Output) and Step2 (Input).
    """
    domain_to_zone: Dict[str, Zone]
