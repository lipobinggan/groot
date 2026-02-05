from typing import TypedDict, List, Dict

class LabelGraphNode(TypedDict):
    """
    This is a TypedDict. Instantiate using dict literals (e.g. {'key': val}).
    Access fields using brackets (e.g. obj['key']), NOT dot notation.
    
    Represents a node in the Label Graph (a domain label).
    """
    id: str
    label: str
    is_wildcard: bool

class LabelGraphEdge(TypedDict):
    """
    This is a TypedDict. Instantiate using dict literals (e.g. {'key': val}).
    Access fields using brackets (e.g. obj['key']), NOT dot notation.
    
    Represents an edge in the Label Graph (parent-child or DNAME).
    """
    source_id: str
    target_id: str
    edge_type: str  # 'child' or 'dname'

class LabelGraph(TypedDict):
    """
    This is a TypedDict. Instantiate using dict literals (e.g. {'key': val}).
    Access fields using brackets (e.g. obj['key']), NOT dot notation.
    
    Represents the constructed Label Graph.
    Used by Step2 (Output) and Step3 (Input).
    """
    nodes: Dict[str, LabelGraphNode]
    edges: List[LabelGraphEdge]
