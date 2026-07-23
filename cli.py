#!/usr/bin/env python3
import argparse
import sys
import os

# Προσθήκη του root directory στο PYTHONPATH
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from orchestration.graph import agent_app
from database import init_db, save_scan_result, get_recent_scans

console = Console()

def main():
    init_db()

    parser = argparse.ArgumentParser(
        description="OSAF (Offensive Security Automation Framework) - Autonomous Pentesting Agent CLI",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False
    )
    
    parser.add_argument(
        "--target", 
        type=str, 
        default="127.0.0.1", 
        help="Target IP address or domain name to scan (default: 127.0.0.1)"
    )
    
    parser.add_argument(
        "--profile", 
        type=str, 
        default="full", 
        choices=["full", "web", "infra", "websocket"],
        help="Assessment profile/scope (default: full)"
    )

    parser.add_argument(
        "--history", 
        action="store_true", 
        help="Show recent scan history from local database"
    )

    parser.add_argument(
        "--mobile-manifest",
        type=str,
        default=None,
        help="Path to an AndroidManifest.xml to run Mobile SAST against (optional)"
    )

    parser.add_argument(
        "--mobile-source",
        type=str,
        default=None,
        help="Path to a mobile source/strings file to scan for hardcoded secrets (optional, requires --mobile-manifest)"
    )

    parser.add_argument(
        "-h", "--help", 
        action="store_true", 
        help="Show help message and exit"
    )

    args = parser.parse_args()

    if args.help:
        console.print(Panel.fit(
            "[bold cyan]OSAF (Offensive Security Automation Framework)[/bold cyan]\n"
            "[dim]Autonomous Pentesting Agent CLI (LangGraph)[/dim]",
            border_style="cyan"
        ))
        
        table = Table(title="Available Options", show_header=True, header_style="bold magenta")
        table.add_column("Argument", style="green")
        table.add_column("Description", style="white")
        table.add_column("Default", style="yellow")
        
        table.add_row("--target TARGET", "Target IP address or domain name to scan", "127.0.0.1")
        table.add_row("--profile", "Assessment profile (full, web, infra, websocket)", "full")
        table.add_row("--history", "Display recent scans stored in local DB", "False")
        table.add_row("--mobile-manifest PATH", "AndroidManifest.xml to run Mobile SAST against", "None")
        table.add_row("--mobile-source PATH", "Mobile source/strings file to scan for secrets", "None")
        table.add_row("-h, --help", "Show this help message and exit", "-")
        
        console.print(table)
        sys.exit(0)

    if args.history:
        scans = get_recent_scans(limit=5)
        if not scans:
            console.print("[yellow]No previous scan history found in database.[/yellow]")
        else:
            hist_table = Table(title="Recent Scan History", show_header=True, header_style="bold blue")
            hist_table.add_column("ID", style="dim")
            hist_table.add_column("Timestamp", style="cyan")
            hist_table.add_column("Target", style="green")
            hist_table.add_column("Profile", style="magenta")
            hist_table.add_column("Vulns", style="red")

            for scan in scans:
                hist_table.add_row(
                    str(scan["id"]),
                    scan["timestamp"],
                    scan["target"],
                    scan["profile"],
                    str(scan["vulnerabilities_count"])
                )
            console.print(hist_table)
        sys.exit(0)

    console.print(Panel(
        f"[bold green]🛡️ OSAF - Offensive Security Automation Framework[/bold green]\n"
        f"[*] Target Scope : [cyan]{args.target}[/cyan]\n"
        f"[*] Scan Profile : [yellow]{args.profile}[/yellow]\n"
        f"[*] Initializing autonomous state machine...",
        border_style="green"
    ))

    mobile_manifest_content = ""
    mobile_source_content = ""
    if args.mobile_manifest:
        try:
            with open(args.mobile_manifest, "r", encoding="utf-8") as f:
                mobile_manifest_content = f.read()
            console.print(f"[*] Mobile manifest loaded from: [cyan]{args.mobile_manifest}[/cyan]")
        except Exception as e:
            console.print(f"[!] Warning: could not read --mobile-manifest ({e}). Skipping Mobile SAST.", style="yellow")

    if args.mobile_source and mobile_manifest_content:
        try:
            with open(args.mobile_source, "r", encoding="utf-8") as f:
                mobile_source_content = f.read()
        except Exception as e:
            console.print(f"[!] Warning: could not read --mobile-source ({e}). Continuing without it.", style="yellow")

    initial_state = {
        "target": args.target,
        "history": [],
        "scan_results": [],
        "enriched_cves": [],
        "web_vulnerabilities": [],
        "next_action": "",
        "mobile_manifest": mobile_manifest_content,
        "mobile_source": mobile_source_content
    }

    try:
        with console.status("[bold green]Executing multi-agent workflow pipeline...", spinner="dots"):
            final_state = agent_app.invoke(initial_state)

        vuln_count = len(final_state.get('web_vulnerabilities', []))
        
        # Αυτόματη αποθήκευση αποτελέσματος στη βάση δεδομένων SQLite
        save_scan_result(
            target=args.target,
            profile=args.profile,
            vulnerabilities_count=vuln_count,
            report_data=final_state
        )

        console.print("\n" + "=" * 65, style="bold cyan")
        console.print("📊 [EXECUTION SUMMARY]", style="bold cyan")
        console.print("=" * 65, style="bold cyan")
        console.print(f"• Target Evaluated           : [cyan]{final_state.get('target')}[/cyan]")
        console.print(f"• Total Log Entries          : {len(final_state.get('history', []))}")
        console.print(f"• Total Vulnerabilities Found: [red]{vuln_count}[/red]")
        console.print(f"• Final State Status         : '[yellow]{final_state.get('next_action')}[/yellow]'")
        
        report_filename = f"reports/pentest_report_{final_state.get('target')}.md"
        if os.path.exists(report_filename):
            console.print(f"• Report Successfully Saved  : [green]{report_filename}[/green]")
        
        console.print("=" * 65, style="bold cyan")
        console.print("[[bold green]✓[/bold green]] Assessment pipeline completed successfully and saved to DB.")

    except Exception as e:
        console.print(f"\n[!] Critical Error during pipeline execution: {e}", style="bold red")
        sys.exit(1)

if __name__ == "__main__":
    main()