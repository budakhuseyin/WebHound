import requests


def check_security_headers(domain):
    # Protokol tespiti (Daha esnek çalışma için)
    base_url = None
    for proto in ["https://", "http://"]:
        try:
            r = requests.head(f"{proto}{domain}", timeout=5, allow_redirects=True)
            base_url = r.url.rstrip('/')
            break
        except:
            continue
    
    if not base_url:
        base_url = f"http://{domain}"

    url = base_url

    headers_to_check=[
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-Frame-Options',
        'X-Content-Type-Options',
        'X-XSS-Protection',
        'Referrer-Policy',
        'Permissions-Policy',
        'Expect-CT',
        'Cross-Origin-Opener-Policy',
        'Cross-Origin-Embedder-Policy',
        'Cross-Origin-Resource-Policy'
    ]

    results={
        "present": {},
        "missing": []
    }

    # per-header short assessments to help interpret presence/absence
    results.setdefault("assessments", {})

    try:
        response= requests.head(url,timeout=5,allow_redirects=True)
        server_headers= response.headers

        for header in headers_to_check:
            if header.lower() in (h.lower() for h in server_headers.keys()):
                # fetch header value case-insensitively
                value = next((server_headers[h] for h in server_headers.keys() if h.lower() == header.lower()), None)
                results["present"][header] = value

                # simple, conservative assessment notes
                note = "Present"
                if header == 'X-XSS-Protection':
                    note = 'Deprecated in modern browsers'
                elif header == 'Strict-Transport-Security':
                    note = 'HSTS enabled' if value else 'HSTS header present'
                elif header == 'Content-Security-Policy':
                    note = 'CSP present — inspect policy for quality'
                elif header == 'X-Frame-Options':
                    note = 'Provides clickjacking protection'
                elif header == 'X-Content-Type-Options':
                    note = 'Prevents MIME sniffing'
                elif header == 'Referrer-Policy':
                    note = 'Controls referrer information'
                elif header == 'Permissions-Policy':
                    note = 'Controls powerful features (Feature-Policy)'
                elif header == 'Expect-CT':
                    note = 'Certificate transparency policy'
                elif header == 'Cross-Origin-Opener-Policy':
                    note = 'COOP header (isolation)'
                elif header == 'Cross-Origin-Embedder-Policy':
                    note = 'COEP header (isolation)'
                elif header == 'Cross-Origin-Resource-Policy':
                    note = 'Controls cross-origin resource access'

                results['assessments'][header] = note
            else:
                results["missing"].append(header)
        

        return results
    
    except Exception as e:
        return {"error": f"no connection: {str(e)}"}
