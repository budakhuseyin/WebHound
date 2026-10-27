import requests


# Okunabilirlik için header açıklamaları sabit olarak tanımlandı
HEADER_NOTES = {
    'Strict-Transport-Security':      'HSTS enabled',
    'Content-Security-Policy':        'CSP present — inspect policy for quality',
    'X-Frame-Options':                'Provides clickjacking protection',
    'X-Content-Type-Options':         'Prevents MIME sniffing',
    'X-XSS-Protection':               'Deprecated in modern browsers',
    'Referrer-Policy':                'Controls referrer information',
    'Permissions-Policy':             'Controls powerful features (Feature-Policy)',
    'Expect-CT':                      'Certificate transparency policy',
    'Cross-Origin-Opener-Policy':     'COOP header (isolation)',
    'Cross-Origin-Embedder-Policy':   'COEP header (isolation)',
    'Cross-Origin-Resource-Policy':   'Controls cross-origin resource access',
}

HEADERS_TO_CHECK = list(HEADER_NOTES.keys())


def check_security_headers(domain):
    results = {
        "present":     {},
        "missing":     [],
        "assessments": {},
    }

    # Protokol tespiti + header okuma tek request'te yapılıyor (duplicate istek kaldırıldı)
    response = None
    for proto in ["https://", "http://"]:
        try:
            response = requests.head(
                f"{proto}{domain}",
                timeout=5,
                allow_redirects=True,
            )
            break
        except requests.RequestException:
            continue

    if response is None:
        return {"error": f"Could not connect to {domain} over HTTPS or HTTP."}

    server_headers = response.headers
    # Karşılaştırma için küçük harfli header isimlerini önbelleğe al
    lower_keys = {k.lower(): k for k in server_headers.keys()}

    for header in HEADERS_TO_CHECK:
        matched_key = lower_keys.get(header.lower())
        if matched_key:
            value = server_headers[matched_key]
            results["present"][header] = value
            results["assessments"][header] = HEADER_NOTES[header]
        else:
            results["missing"].append(header)

    return results
