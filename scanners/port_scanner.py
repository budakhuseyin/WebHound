import socket
import concurrent.futures

def grab_banner(ip, port, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
        if port in [80, 443, 8080, 8443, 5000]:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        if banner.startswith("HTTP/"):
            for line in banner.split('\n'):
                if line.lower().startswith('server:'):
                    return line.split(':', 1)[1].strip()
            return "HTTP Server"
            
        return banner[:60] if banner else "Unknown Service"
    except Exception:
        return "Unknown Service"

def scan_ports(ip):
    ports_to_scan = [
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 
        1433, 3306, 3389, 5000, 5432, 5900, 6379, 
        8080, 8443, 9000, 9200, 27017
    ]    
    
    def check_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                banner_info = grab_banner(ip, port)
                return {"port": port, "banner": banner_info}
        except:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        results = list(executor.map(check_port, ports_to_scan))
    
    open_ports = [p for p in results if p is not None]
    
    return sorted(open_ports, key=lambda x: x["port"])
