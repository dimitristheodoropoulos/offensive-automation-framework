import socket

def scan_ports(ip, ports=[22, 80, 443, 8080]):
    """Native Python socket scanner for basic port enumeration."""
    detected_services = []
    
    for port in ports:
        # Δημιουργία TCP socket με timeout 1 δευτερόλεπτο για γρήγορο scan
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        
        # Η connect_ex επιστρέφει 0 αν η πόρτα είναι ανοιχτή
        result = sock.connect_ex((ip, port))
        if result == 0:
            # Βασικό mapping υπηρεσιών βάσει θύρας
            service_name = "unknown"
            if port == 22: service_name = "ssh"
            elif port == 80: service_name = "http"
            elif port == 443: service_name = "https"
            elif port == 8080: service_name = "http-proxy"
            
            detected_services.append({"port": port, "service": service_name})
        sock.close()
        
    return detected_services