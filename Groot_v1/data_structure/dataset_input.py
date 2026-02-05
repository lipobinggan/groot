from typing import TypedDict, List, Dict, Optional

class MetadataZoneFileEntry(TypedDict):
    """
    This is a TypedDict. Instantiate using dict literals (e.g. {'key': val}).
    Access fields using brackets (e.g. obj['key']), NOT dot notation.
    
    Represents a single zone file entry in metadata.json.
    """
    FileName: str
    NameServer: str
    Origin: Optional[str]

class Metadata(TypedDict):
    """
    This is a TypedDict. Instantiate using dict literals (e.g. {'key': val}).
    Access fields using brackets (e.g. obj['key']), NOT dot notation.
    
    Represents the parsed content of metadata.json.
    """
    TopNameServers: List[str]
    ZoneFiles: List[MetadataZoneFileEntry]

class RawDataset(TypedDict):
    """
    This is a TypedDict. Instantiate using dict literals (e.g. {'key': val}).
    Access fields using brackets (e.g. obj['key']), NOT dot notation.
    
    Represents the raw input dataset containing metadata and paths to zone files.
    Used by Step1.
    """
    metadata: Metadata
    # Maps filename to absolute file path
    zone_file_paths: Dict[str, str]
