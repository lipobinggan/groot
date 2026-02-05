from typing import TypedDict, List, Optional, Union, Any

class PropertyDetail(TypedDict):
    """
    This is a TypedDict. Instantiate using dict literals (e.g. {'key': val}).
    Access fields using brackets (e.g. obj['key']), NOT dot notation.
    
    Represents a specific property check configuration.
    """
    PropertyName: str
    Types: Optional[List[str]]
    Value: Optional[Union[List[str], int, str]]

class JobEntry(TypedDict):
    """
    This is a TypedDict. Instantiate using dict literals (e.g. {'key': val}).
    Access fields using brackets (e.g. obj['key']), NOT dot notation.
    
    Represents a job entry in jobs.json.
    """
    Domain: str
    SubDomain: bool
    Properties: List[PropertyDetail]

class JobsProperties(TypedDict):
    """
    This is a TypedDict. Instantiate using dict literals (e.g. {'key': val}).
    Access fields using brackets (e.g. obj['key']), NOT dot notation.
    
    Represents the parsed jobs.json structure.
    Used by Step5 (Input).
    """
    jobs: List[JobEntry]
