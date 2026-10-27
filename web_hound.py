import socket
from urllib.parse import urlparse
import concurrent.futures # makes all functions work together
import logging
from scanners.port_scanner import scan_ports
from scanners.subdomain import find_subdomains
from scanners.header import check_security_headers
from scanners.directory_scanner import scan_directories
from scanners.tech_detector import detect_technologies
from scanners.ssl_scanner import check_ssl
from scanners.whois_scanner import get_whois_info
from scanners.dns_scanner import scan_dns_records

def safe_result(future, default_val=None, timeout=30):
    """Her modül için bir zaman aşımı (timeout) belirler. Eğer modül 30 saniye
    içinde cevap vermezse tüm sistemi kitlememek için varsayılan değeri döner."""
    try:
        return future.result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        return default_val if default_val is not None else {"error": "Scan timed out (30s limit)"}
    except Exception as e:
        return default_val if default_val is not None else {"error": f"Internal scan error: {str(e)}"}

def run_recon(target_url):
    parsed_url = urlparse(target_url)
    domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path.split('/')[0]
    domain = domain.split(':')[0]

    try:
        target_ip = socket.gethostbyname(domain)
    except socket.gaierror:
        return {"error": f"Domain resolution failed. Please check the URL: {domain}"}

    with concurrent.futures.ThreadPoolExecutor() as executor:
        # Modülleri paralel olarak başlat
        future_ports        = executor.submit(scan_ports, target_ip)
        future_subdomains   = executor.submit(find_subdomains, domain)
        future_headers      = executor.submit(check_security_headers, domain)
        future_directories  = executor.submit(scan_directories, domain)
        future_tech         = executor.submit(detect_technologies, target_url)
        future_ssl          = executor.submit(check_ssl, domain)
        future_whois        = executor.submit(get_whois_info, domain)
        future_dns          = executor.submit(scan_dns_records, domain)

        # Sonuçları güvenli şekilde topla (timeout korumalı)
        found_ports       = safe_result(future_ports,       default_val=[])
        found_subdomains  = safe_result(future_subdomains,  default_val=[])
        found_headers     = safe_result(future_headers,     default_val={"error": "Headers scan failed or timed out"})
        found_directories = safe_result(future_directories, default_val={"robots_count": 0, "discovered": []})
        found_tech        = safe_result(future_tech,        default_val={"error": "Tech detection timed out"})
        found_ssl         = safe_result(future_ssl,         default_val={"error": "SSL check timed out"})
        found_whois       = safe_result(future_whois,       default_val={"error": "WHOIS scan timed out"})
        found_dns         = safe_result(future_dns,         default_val={"error": "DNS scan timed out"})

    return {
        "domain":           domain,
        "ip":               target_ip,
        "open_ports":       found_ports,
        "subdomains":       found_subdomains,
        "security_headers": found_headers,
        "directories":      found_directories,
        "tech_stack":       found_tech,
        "ssl_info":         found_ssl,
        "whois_data":       found_whois,
        "dns_records":      found_dns,
    }
