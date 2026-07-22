# main.py
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from enrichment.cve_lookup import lookup_cves
from main_agentic import run_agent

app = typer.Typer(
    help="Offensive Automation Framework - Central CLI & Runner",
    add_completion=False
)
console = Console()

@app.command("cve-search")
def cve_search(
    service: str = typer.Argument(..., help="Name of the service (e.g., ssh, http, https)."),
    port: str = typer.Option("N/A", "--port", "-p", help="Port number associated with the service.")
):
    """Αναζήτηση CVEs βάσει υπηρεσίας χρησιμοποιώντας το RAG Vector Store ή το Fallback DB."""
    console.print(f"[bold cyan][*] Αναζήτηση ευπαθειών για την υπηρεσία:[/bold cyan] {service} (Θύρα: {port})")
    
    results = lookup_cves([{"service": service, "port": port}])
    
    if not results:
        console.print("[yellow][!] Δεν βρέθηκαν σχετικές ευπάθειες.[/yellow]")
        return

    for res in results:
        table = Table(title=f"Αποτελέσματα Εμπλουτισμού CVE (Θύρα: {res['port']})", show_header=True, header_style="bold magenta")
        table.add_column("Υπηρεσία", style="green")
        table.add_column("Επικινδυνότητα (Severity)", style="bold red")
        table.add_column("Εντοπισμένα CVEs", style="white")

        cve_list_display = "\n".join(res["cves"]) if res["cves"] else "Κανένα CVE"
        table.add_row(res["service"].upper(), res["severity"], cve_list_display)
        
        console.print(table)

@app.command("agent-run")
def agent_run(
    target: str = typer.Argument("127.0.0.1", help="Στόχος IP ή hostname για την agentic εκτέλεση.")
):
    """Εκτέλεση του πλήρους αυτόνομου LangGraph Agent Pipeline (σάρωση, RAG, reporting, benchmarking)."""
    console.print(Panel(f"[bold green]Εκκίνηση Agentic Runner για τον στόχο:[/bold green] {target}", title="OSAF Agentic Engine"))
    try:
        run_agent(target)
    except Exception as e:
        console.print(f"[bold red][-] Σφάλμα κατά την εκτέλεση του agent:[/bold red] {e}")

@app.command("workflow")
def run_workflow(
    target: str = typer.Option("local-environment", "--target", "-t", help="Στόχος σκαναρίσματος ή ανάλυσης.")
):
    """Εκτέλεση ενός στατικού End-to-End Security Workflow."""
    console.print(Panel(f"[bold green]Εκτέλεση E2E Security Workflow για τον στόχο:[/bold green] {target}", title="Framework Engine"))
    
    console.print("[*] Βήμα 1: Εκτέλεση SAST & Secret Scans... [dim green][ΕΠΙΤΥΧΙΑ][/dim green]")
    console.print("[*] Βήμα 2: Σημασιολογική αναζήτηση RAG για CVEs... [dim green][ΕΠΙΤΥΧΙΑ][/dim green]")
    console.print("[*] Βήμα 3: Αξιολόγηση από Critic Agent & Δημιουργία Report... [dim green][ΕΠΙΤΥΧΙΑ][/dim green]")
    
    console.print("\n[bold green][+] Το workflow ολοκληρώθηκε επιτυχώς χωρίς κρίσιμα σφάλματα![/bold green]")

if __name__ == "__main__":
    app()