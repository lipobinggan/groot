from typing import TypedDict, List, Dict

class DNSConfigurationObject(TypedDict):
    """
    This is a TypedDict. Instantiate using dict literals (e.g. {'key': val}).
    Access fields using brackets (e.g. obj['key']), NOT dot notation.
    
    Represents the formal Configuration tuple C = <S, Theta, Gamma, Omega>.
    Used by Step1 (Output) and Step4 (Input).
    """
    # S: Set of nameservers
    S: List[str]
    # Theta: Root nameservers
    Theta: List[str]
    # Gamma: Maps servers to the list of zones they serve
    Gamma: Dict[str, List[str]]
    # Omega: Maps domain names to authoritative nameservers
    Omega: Dict[str, str]
