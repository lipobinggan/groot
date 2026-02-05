from typing import TypedDict, List

class EquivalenceClass(TypedDict):
    """
    This is a TypedDict. Instantiate using dict literals (e.g. {'key': val}).
    Access fields using brackets (e.g. obj['key']), NOT dot notation.
    
    Represents a set of queries that resolve identically.
    """
    ec_id: str
    domain_sequence: List[str]
    query_types: List[str]

class EquivalenceClassList(TypedDict):
    """
    This is a TypedDict. Instantiate using dict literals (e.g. {'key': val}).
    Access fields using brackets (e.g. obj['key']), NOT dot notation.
    
    Container for the list of generated Equivalence Classes.
    Used by Step3 (Output) and Step4 (Input).
    """
    classes: List[EquivalenceClass]
