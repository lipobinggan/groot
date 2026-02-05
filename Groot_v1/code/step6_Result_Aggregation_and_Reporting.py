from data_structure.verification_results import VerificationResults
from typing import List, Dict, Any, Optional, Tuple, Set

def generate_final_report(verification_results: List[Dict[str, Any]]) -> str:
        """
        Aggregate the verification results and generate the final summary statistics.
        
        Input: verification_results: A list of dictionaries representing verification outcomes.
        Output: final_report: a formatted text string.
        """
        # 1: Initialize `stats` dictionary with keys "total_ecs", "passed", "failed" set to 0
        stats = {"total_ecs": 0, "passed": 0, "failed": 0}
        
        # 2: Initialize `violation_logs` as an empty list
        violation_logs = []
        
        # 3: for each `record` in `verification_results`
        for record in verification_results:
            # 4: Increment `stats`["total_ecs"] by 1
            stats["total_ecs"] += 1
            
            # 5: if `record`["has_violation"] is True
            # Using .get() to safely access the dictionary key, defaulting to False if missing.
            if record.get("has_violation", False):
                # 6: Increment `stats`["failed"] by 1
                stats["failed"] += 1
                
                # 7: Format string `log_entry` using `record`["property"], `record`["query"], and `record`["reason"]
                prop = record.get("property", "Unknown Property")
                query = record.get("query", "Unknown Query")
                reason = record.get("reason", "Unknown Reason")
                
                log_entry = f"Property: {prop}, Query: {query}, Reason: {reason}"
                
                # 8: Append `log_entry` to `violation_logs`
                violation_logs.append(log_entry)
            else:
                # 9: else:
                # 10: Increment `stats`["passed"] by 1
                stats["passed"] += 1
                
        # 11: Generate `summary_section` string using `stats`["total_ecs"], `stats`["passed"], and `stats`["failed"]
        summary_section = (
            f"Total ECs: {stats['total_ecs']}\n"
            f"Passed: {stats['passed']}\n"
            f"Failed: {stats['failed']}"
        )
        
        # 12: Concatenate `violation_logs` and `summary_section` into `final_report`
        if violation_logs:
            final_report = "\n".join(violation_logs) + "\n\n" + summary_section
        else:
            final_report = summary_section
            
        # 13: return `final_report`
        return final_report