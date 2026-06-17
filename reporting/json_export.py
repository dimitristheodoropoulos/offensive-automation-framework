import json
import os

def export_to_json(data, filename="osaf_report.json"):
    """Exports the automated security assessment data to a formatted JSON file."""
    filepath = os.path.join(os.getcwd(), filename)
    
    with open(filepath, "w") as f:
        json.dump(data, f, indent=4)
        
    print(f"[+] Report successfully saved to: {filepath}")