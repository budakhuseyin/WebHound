import ssl
import socket
from datetime import datetime

def check_ssl(domain):
    ssl_info = {
        "issuer": "Not Found",
        "subject": "Not Found",
        "valid_from": "Not Found",
        "valid_to": "Not Found",
        "days_left": "Not Found",
        "is_expired": True,
        "protocol": "Not Found"
    }

    context = ssl.create_default_context()
    
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                ssl_info["protocol"] = ssock.version()
                
                if cert:
                    # Extract the Issuer information
                    dict_issuer = dict(x[0] for x in cert.get('issuer', []))
                    ssl_info["issuer"] = dict_issuer.get('organizationName', dict_issuer.get('commonName', 'Not Found'))
                    
                    # Subject
                    dict_subject = dict(x[0] for x in cert.get('subject', []))
                    ssl_info["subject"] = dict_subject.get('commonName', 'Not Found')
                    
                    # Time calculations
                    valid_from = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    valid_to = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    
                    ssl_info["valid_from"] = valid_from.strftime('%Y-%m-%d %H:%M:%S')
                    ssl_info["valid_to"] = valid_to.strftime('%Y-%m-%d %H:%M:%S')
                    
                    now = datetime.utcnow()
                    days_left = (valid_to - now).days
                    ssl_info["days_left"] = days_left
                    ssl_info["is_expired"] = days_left < 0

    except ssl.SSLCertVerificationError as e:
        # Certificate is expired or self-signed. This is a security vulnerability.
        ssl_info["error"] = "Certificate is invalid, expired, or untrusted! (MITM Risk)"
        ssl_info["is_expired"] = True
    except ConnectionRefusedError:
        ssl_info["error"] = "Target refused connection on port 443 (HTTPS)."
    except Exception as e:
        ssl_info["error"] = f"Connection could not be established or SSL not supported."

    return ssl_info
