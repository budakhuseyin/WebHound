import socket
import concurrent.futures

def grab_banner(ip, port, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
        # Web (HTTP) bazlı banner alması gereken portlar
        if port in [80, 443, 8000, 8080, 8443, 8888, 5000, 9000, 9200, 5601]:
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
    # Klasik portlar + Modern DevOps ve Veritabanı portları eklendi
    ports_to_scan = [
        # Standart Servisler
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
        # Veritabanları
        1433, 1521, 3306, 5432, 27017, 6379, 11211,
        # Yönetim ve Uzak Masaüstü
        2082, 2083, 2086, 2087, 3389, 5900,
        # Modern Uygulamalar ve DevOps (Docker, K8s, Elastic, CI/CD)
        2375, 2376, 5000, 5601, 8000, 8080, 8443, 8888, 9000, 9200, 9443, 10250
    ]
    
    def check_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.8) # 2 saniyeden 0.8'e düşürüldü - Asenkron bloklamayı engeller
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                banner_info = grab_banner(ip, port, timeout=1.5)
                return {"port": port, "banner": banner_info}
        except:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        results = list(executor.map(check_port, ports_to_scan))
    
    open_ports = [p for p in results if p is not None]
    
    return sorted(open_ports, key=lambda x: x["port"])
