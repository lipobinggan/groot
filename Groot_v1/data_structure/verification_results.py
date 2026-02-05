from typing import TypedDict, List, Dict, Optional

class ViolationRecord(TypedDict):
    """
    This is a TypedDict. Instantiate using dict literals (e.g. {'key': val}).
    Access fields using brackets (e.g. obj['key']), NOT dot notation.
    
    Represents a single property violation found during verification.
    """
    property_name: str
    query: str
    reason: str
    trace: Optional[str]
    status: str  # 'FAIL' or 'PASS'

class VerificationResults(TypedDict):
    """
    This is a TypedDict. Instantiate using dict literals (e.g. {'key': val}).
    Access fields using brackets (e.g. obj['key']), NOT dot notation.
    
    Container for all verification results.
    Used by Step5 (Output) and Step6 (Input).
    """
    violations: List[ViolationRecord]

class FinalReport(TypedDict):
    """
    This is a TypedDict. Instantiate using dict literals (e.g. {'key': val}).
    Access fields using brackets (e.g. obj['key']), NOT dot notation.
    
    Represents the aggregated data for the final text/console report.
    Used by Step6 (Output).
    """
    total_zones_parsed: int
    total_ecs_generated: int
    property_stats: Dict[str, Dict[str, int]]  # e.g. {'Delegation Consistency': {'FAIL': 4, 'PASS': 0}}
    detailed_violations: List[ViolationRecord]
