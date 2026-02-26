import socket
from urllib.parse import urlparse
import concurrent.futures # makes all functions work together
from scanners.port_scanner import scan_ports
from scanners.subdomain import find_subdomains
from scanners.header import check_security_headers
from scanners.directory_scanner import scan_directories


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
        future_headers=executor.submit(check_security_headers,domain)
        future_directories=executor.submit(scan_directories,domain)



        #founded tasks

        founded_ports=future_ports.result()
        founded_subdomains=future_subdomains.result()
        founded_headers=future_headers.result()
        founded_directories=future_directories.result()

    
    return {
        "domain": domain,
        "ip": target_ip,
        "open_ports": founded_ports,
        "subdomains": founded_subdomains,
        "security_headers": founded_headers,
        "directories": founded_directories
    }    
