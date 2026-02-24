import socket
from urllib.parse import urlparse
import requests
import concurrent.futures # makes all functions work together


def scan_ports(ip):

    ports_to_scan=[21,22,23,25,53,80,110,443,445,3306,3389,8080]
    open_ports =[]
    
    for port in ports_to_scan:

        sock= socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.settimeout(0.5)

        if sock.connect_ex((ip,port))==0:
            open_ports.append(port)
        
        sock.close()
    
    return open_ports


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
    domain= parsed_url.netloc if parsed_url.netloc else parsed_url.path 

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
