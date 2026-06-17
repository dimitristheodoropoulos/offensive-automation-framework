# OSAF (Offensive Security Automation Framework) v2.0

An automation-driven, modular Python framework designed to streamline offensive security workflows, automate asset reconnaissance, and simulate safe adversary emulation within lab environments. 

This project was built from scratch to demonstrate secure coding practices, tool integration, and structural software engineering applied directly to Red Team and penetration testing methodologies.

---

## 🎯 Core Features & Core Competencies Covered

* **Automated Recon & Tool Integration:** Leverages industry-standard tools (`Nmap`) via Python subprocess orchestration, handling raw XML parsing dynamically to extract active hosts and open services.
* **Vulnerability Enrichment:** Automatically correlates discovered services with a simulated open-source threat intelligence database to flag active CVEs and assign risk scoring.
* **Adversary Simulation (Post-Exploitation):** Features a safe, localized environment enumeration module that probes system internals, environment configurations, and privilege levels to mimic threat actor behaviors post-compromise.
* **Continuous Integration (CI/CD):** Integrated with GitHub Actions to automate testing pipelines via `pytest`, ensuring modularity, reliability, and code stability before deployment.

---

## 📂 Project Architecture

The repository follows a clean, modular, and object-oriented package structure to ensure maintainability:


offensive-automation-framework/
│
├── cli/
│   └── main.py                  # Core orchestrator and CLI entrypoint
│
├── scanner/
│   └── nmap_integration.py      # Subprocess wrapper and XML parsing logic for Nmap
│
├── enrichment/
│   └── cve_lookup.py            # Threat intelligence simulation & CVE mapping
│
├── post_exploitation/
│   └── adversary_sim.py         # Local reconnaissance & system internals probe
│
├── reporting/
│   └── json_export.py           # Structured JSON output engine
│
├── .github/
│   └── workflows/
│       └── ci.yml               # GitHub Actions CI pipeline configuration
│
├── requirements.txt             # Project dependencies
└── README.md                    # Project documentation

Installation & Setup
Prerequisites
Ensure you are running a Linux environment (tested on Lubuntu/Ubuntu) and have nmap installed:
sudo apt update && sudo apt install nmap -y

Setup Locally
Clone the repository (or navigate to your local folder):
cd offensive-automation-framework

(Optional) Set up a virtual environment and execute tests:
python3 -m venv venv
source venv/bin/activate
pip install pytest pytest-cov

Usage Guide
To execute a full automated evaluation against a specific target host, run the cli/main.py entrypoint passing the target IP address:
python3 cli/main.py -t 127.0.0.1

Tip for Testing CVE Enrichment: If the target has no open ports, the infrastructure vulnerabilities array will be empty. To test the enrichment engine locally, spin up a temporary python server in another terminal (python3 -m http.server 8080) and re-run the scan against 127.0.0.1.

Structured Artifact Sample (osaf_report.json)
Upon completion, OSAF exports a structured, machine-readable JSON log perfectly tailored for ingestions into analytics platforms or SIEMs (like LogIQ-SIEM):

{
    "target_host": "127.0.0.1",
    "infrastructure_vulnerabilities": [
        {
            "port": 8080,
            "service": "http",
            "cves": [
                "CVE-2021-41773 (Path Traversal)",
                "CVE-2022-22965"
            ],
            "severity": "Critical"
        }
    ],
    "post_exploitation_recon": {
        "os_platform": "Linux-6.17.0-29-generic-x86_64",
        "current_user": "dimitris",
        "current_directory": "/home/dimitris/Desktop/offensive-automation-framework",
        "writable_tmp": true,
        "environment_vars_count": 72,
        "privilege_level": "Standard User (Privilege Escalation Required)"
    }
}

Security & Ethical Disclaimer
This framework is developed strictly for educational, authorization-based testing, and defensive engineering evaluation purposes. It does not deliver operational exploits, malware payloads, or destructive actions. It is designed to empower security professionals to automate threat visibility and benchmark network defenses. Always obtain proper authorization before scanning any infrastructure.

