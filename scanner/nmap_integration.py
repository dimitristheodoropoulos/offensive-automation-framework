import subprocess
import xml.etree.ElementTree as ET
import os

def run_nmap_scan(target_ip):
    """Executes a real Nmap scan using subprocess and parses the XML output.
    
    Fulfills JD: 'Familiarity with common offensive security tools (Nmap)' 
    and 'Automate and integrate existing tools'.
    """
    xml_file = "temp_output.xml"
    print(f"[*] Launching Nmap service detection (-sV) against {target_ip}...")
    
    # Εκτέλεση του Nmap σε XML format για ασφαλές parsing
    try:
        subprocess.run(
            ["nmap", "-sV", "-oX", xml_file, target_ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True
        )
    except FileNotFoundError:
        print("[-] Error: Nmap is not installed on this Lubuntu system. Run: sudo apt install nmap")
        return []

    detected_services = []
    
    # Parsing του XML αρχείου
    if os.path.exists(xml_file):
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        for port in root.iter('port'):
            port_id = port.get('portid')
            state = port.find('state').get('state')
            
            if state == "open":
                service = port.find('service')
                service_name = service.get('name') if service is not None else "unknown"
                product = service.get('product') if service is not None else ""
                version = service.get('version') if service is not None else ""
                
                detected_services.append({
                    "port": int(port_id),
                    "service": service_name,
                    "version": f"{product} {version}".strip()
                })
        
        os.remove(xml_file) # Καθαρισμός του temporary αρχείου
    
    return detected_services