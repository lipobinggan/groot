from typing import TypedDict, List, Dict, Any, Optional

class ResolutionState(TypedDict):
    """
    This is a TypedDict. Instantiate using dict literals (e.g. {'key': val}).
    Access fields using brackets (e.g. obj['key']), NOT dot notation.
    
    Represents the state of resolution at a specific node.
    """
    nameserver: str
    current_query: str

class InterpretationNode(TypedDict):
    """
    This is a TypedDict. Instantiate using dict literals (e.g. {'key': val}).
    Access fields using brackets (e.g. obj['key']), NOT dot notation.
    
    Represents a node in the Interpretation Graph.
    """
    node_id: str
    state: ResolutionState
    # Bitset represented as integer or list of active types
    query_type_bitmap: List[str]
    # Verification fields
    tags: List[str]
    records: List[Any]
    answer: Optional[Dict[str, Any]]

class InterpretationEdge(TypedDict):
    """
    This is a TypedDict. Instantiate using dict literals (e.g. {'key': val}).
    Access fields using brackets (e.g. obj['key']), NOT dot notation.
    
    Represents a transition in the Interpretation Graph (referral, rewrite, etc.).
    """
    source_id: str
    target_id: str
    action: str  # 'referral', 'rewrite', 'answer', 'nxdomain'

class InterpretationGraph(TypedDict):
    """
    This is a TypedDict. Instantiate using dict literals (e.g. {'key': val}).
    Access fields using brackets (e.g. obj['key']), NOT dot notation.
    
    Represents the symbolic execution graph for a single Equivalence Class.
    """
    ec_id: str
    nodes: Dict[str, InterpretationNode]
    edges: List[InterpretationEdge]

class InterpretationGraphList(TypedDict):
    """
    This is a TypedDict. Instantiate using dict literals (e.g. {'key': val}).
    Access fields using brackets (e.g. obj['key']), NOT dot notation.
    
    Container for all Interpretation Graphs.
    Used by Step4 (Output) and Step5 (Input).
    """
    graphs: List[InterpretationGraph]