import socket
from urllib.parse import urlparse
import requests
import concurrent.futures # makes all functions work together


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


def find_subdomains(domain):
    try:
        crt_url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(crt_url, timeout=15) 
        
        if response.status_code == 200:
            data = response.json()
            unique_subdomains = set()
            
            for entry in data:
                name_value = entry['name_value']
                for sub in name_value.split('\n'):
                    if '*' not in sub:
                        unique_subdomains.add(sub.strip())
                        
            return sorted(list(unique_subdomains))
        else:
            return ["API Error: crt.sh did not respond properly."]
            
    except Exception as e:
        return [f"Connection Error: {str(e)}"]




def run_recon(target_url):
    
    parsed_url= urlparse(target_url)
    domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path.split('/')[0]
    domain = domain.split(':')[0]

    try:
        target_ip= socket.gethostbyname(domain)
    
    except socket.gaierror:
        return {"error" : f"Domain resolved failed. check the url: {domain}"}
    

    with concurrent.futures.ThreadPoolExecutor() as executor:
        
        #submit the tasks
        future_ports= executor.submit(scan_ports,target_ip)
        future_subdomains=executor.submit(find_subdomains,domain)



        #founded tasks

        founded_ports=future_ports.result()
        founded_subdomains=future_subdomains.result()

    
    return {
        "domain": domain,
        "ip": target_ip,
        "open_ports": founded_ports,
        "subdomains": founded_subdomains
    }    
