import socket
import concurrent.futures


def scan_ports(ip):
    ports_to_scan = [
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 
        1433, 3306, 3389, 5000, 5432, 5900, 6379, 
        8080, 8443, 9000, 9200, 27017
    ]    
    open_ports = []
    
    def check_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return port
        except:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        results = list(executor.map(check_port, ports_to_scan))
    
    open_ports = [p for p in results if p is not None]
    return sorted(open_ports)
