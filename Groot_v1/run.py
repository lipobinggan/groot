import sys
import os
import json
from typing import List, Dict, Any

# Import Data Structures
from data_structure.configuration import DNSConfigurationObject
from data_structure.dataset_input import RawDataset, Metadata
from data_structure.dns_entities import ZoneMap
from data_structure.label_graph import LabelGraph
from data_structure.equivalence_class import EquivalenceClassList
from data_structure.interpretation_graph import InterpretationGraphList
from data_structure.jobs import JobsProperties
from data_structure.verification_results import VerificationResults, FinalReport

# FIX: Add 'code' directory to sys.path to allow direct imports.
# The directory name 'code' conflicts with the Python standard library module 'code'.
# By adding it to sys.path, we can import the step modules directly without the 'code.' prefix.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'code'))

# Import Code Modules
# Note: 'code.' prefix removed due to sys.path modification to avoid stdlib conflict
from step1_Input_Parsing_and_Configuration_Initialization import input_parsing_and_configuration_initialization
from step2_Label_Graph_Construction import construct_label_graph
from step3_Equivalence_Class_EC_Generation import generate_equivalence_classes
from step4_Symbolic_Execution_and_Interpretation_Graph_Construction import generate_interpretation_graphs
from step5_Property_Verification import verify_properties
from step6_Result_Aggregation_and_Reporting import generate_final_report

def validate_contract(data: Any, required_keys: List[str], step_name: str):
    """
    Validates that the data is a dictionary and contains the required keys.
    Raises AssertionError if validation fails.
    """
    if not isinstance(data, dict):
        raise AssertionError(f"Contract Violation at {step_name}: Output must be a dictionary (TypedDict). Got {type(data)}.")
    
    for key in required_keys:
        assert key in data, f"Contract Violation at {step_name}: Missing required key '{key}'."

def main():
    # 0. Pipeline Setup and Dummy Data Initialization
    if len(sys.argv) < 2:
        print("Usage: python run.py <dataset_path>")
        sys.exit(1)
        
    dataset_path = sys.argv[1]
    
    # Requirement 4: Initialize Dummy Data strictly adhering to RawDataset
    # This demonstrates compliance with the input contract of Step 1
    dummy_metadata: Metadata = {
        "TopNameServers": ["ns.root."],
        "ZoneFiles": [{"FileName": "root.txt", "NameServer": "ns.root.", "Origin": "."}]
    }
    dummy_input: RawDataset = {
        "metadata": dummy_metadata,
        "zone_file_paths": {"root.txt": "/dummy/path/root.txt"}
    }
    
    # Resolve paths for actual execution
    # Based on dataset structure, metadata.json is likely in a 'zone_files' subdirectory
    zone_files_path = os.path.join(dataset_path, "zone_files")
    if not os.path.exists(os.path.join(zone_files_path, "metadata.json")):
        if os.path.exists(os.path.join(dataset_path, "metadata.json")):
            zone_files_path = dataset_path
        else:
            print(f"Warning: metadata.json not found in {zone_files_path} or {dataset_path}")

    # --- Step 1: Input Parsing ---
    print("Executing Step 1: Input Parsing...")
    try:
        config, zone_map_raw = input_parsing_and_configuration_initialization(zone_files_path)
    except Exception as e:
        print(f"Step 1 Execution Failed: {e}")
        return

    # Wrap raw output to match ZoneMap TypedDict
    zone_map_wrapper: ZoneMap = {"domain_to_zone": zone_map_raw}

    # Contract Validation Step 1
    try:
        validate_contract(config, ["S", "Theta", "Gamma", "Omega"], "Step 1 (Config)")
        validate_contract(zone_map_wrapper, ["domain_to_zone"], "Step 1 (ZoneMap)")
        assert isinstance(config["S"], list), "Step 1: 'S' must be a list."
    except AssertionError as e:
        print(f"{e}")
        raise
    print("Step 1 completed successfully.")

    # --- Step 2: Label Graph Construction ---
    print("Executing Step 2: Label Graph Construction...")
    try:
        # Step 2 accepts the ZoneMap wrapper
        label_graph = construct_label_graph(zone_map_wrapper)
    except Exception as e:
        print(f"Step 2 Execution Failed: {e}")
        return

    # Contract Validation Step 2
    try:
        validate_contract(label_graph, ["nodes", "edges"], "Step 2")
        assert isinstance(label_graph["nodes"], dict), "Step 2: 'nodes' must be a dictionary."
    except AssertionError as e:
        print(f"{e}")
        raise
    print("Step 2 completed successfully.")

    # --- Step 3: EC Generation ---
    print("Executing Step 3: EC Generation...")
    try:
        ec_list_raw = generate_equivalence_classes(label_graph)
    except Exception as e:
        print(f"Step 3 Execution Failed: {e}")
        return

    # Wrap raw list to match EquivalenceClassList TypedDict
    ec_wrapper: EquivalenceClassList = {"classes": ec_list_raw}

    # Contract Validation Step 3
    try:
        validate_contract(ec_wrapper, ["classes"], "Step 3")
        assert isinstance(ec_wrapper["classes"], list), "Step 3: 'classes' must be a list."
    except AssertionError as e:
        print(f"{e}")
        raise
    print("Step 3 completed successfully.")

    # --- Step 4: Interpretation Graph Construction ---
    print("Executing Step 4: Interpretation Graph Construction...")
    try:
        # Step 4 expects the EquivalenceClassList wrapper and ZoneMap wrapper
        interp_graphs_wrapper = generate_interpretation_graphs(ec_wrapper, config, zone_map_wrapper)
    except Exception as e:
        print(f"Step 4 Execution Failed: {e}")
        return

    # Contract Validation Step 4
    try:
        validate_contract(interp_graphs_wrapper, ["graphs"], "Step 4")
        assert isinstance(interp_graphs_wrapper["graphs"], list), "Step 4: 'graphs' must be a list."
    except AssertionError as e:
        print(f"{e}")
        raise
    print("Step 4 completed successfully.")

    # --- Step 5: Property Verification ---
    print("Executing Step 5: Property Verification...")
    
    # Load jobs.json to construct JobsProperties
    jobs_file = os.path.join(dataset_path, "jobs.json")
    jobs_config: JobsProperties = {"jobs": []}
    
    if os.path.exists(jobs_file):
        try:
            with open(jobs_file, 'r') as f:
                content = json.load(f)
                if isinstance(content, list):
                    jobs_config["jobs"] = content
                elif isinstance(content, dict):
                    jobs_config["jobs"] = [content]
        except Exception as e:
            print(f"Warning: Failed to load jobs.json: {e}")

    try:
        # Step 5 returns a list of violations
        violations_raw = verify_properties(interp_graphs_wrapper, jobs_config)
    except Exception as e:
        print(f"Step 5 Execution Failed: {e}")
        return

    # Wrap raw list to match VerificationResults TypedDict
    results_wrapper: VerificationResults = {"violations": violations_raw}

    # Contract Validation Step 5
    try:
        validate_contract(results_wrapper, ["violations"], "Step 5")
        assert isinstance(results_wrapper["violations"], list), "Step 5: 'violations' must be a list."
    except AssertionError as e:
        print(f"{e}")
        raise
    print("Step 5 completed successfully.")

    # --- Step 6: Result Aggregation ---
    print("Executing Step 6: Result Aggregation...")
    try:
        # Step 6 expects the raw list of violations
        final_report = generate_final_report(violations_raw)
    except Exception as e:
        print(f"Step 6 Execution Failed: {e}")
        return

    # Contract Validation Step 6
    # Output is text/console output (str), not a TypedDict struct
    try:
        assert isinstance(final_report, str), "Contract Violation at Step 6: Output must be a string."
    except AssertionError as e:
        print(f"{e}")
        raise
    print("Step 6 completed successfully.")

    print("\n" + "="*30)
    print(final_report)
    print("="*30)

if __name__ == "__main__":
    main()