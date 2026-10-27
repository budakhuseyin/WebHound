import requests
import concurrent.futures
import random
import string
from urllib.parse import urlparse, urljoin

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'
}


def check_robots_txt(base_url):
    """robots.txt dosyasını analiz eder. Hem Disallow hem Allow satırlarını toplar."""
    robots_url = f"{base_url}/robots.txt"
    paths = []
    try:
        response = requests.get(robots_url, headers=HEADERS, timeout=3)
        if response.status_code == 200:
            for line in response.text.split('\n'):
                line = line.strip()
                # Disallow VE Allow satırları — ikisi de gerçek path varlığına işaret eder
                if line.lower().startswith('disallow:') or line.lower().startswith('allow:'):
                    path = line.split(':', 1)[1].strip()
                    # '/', boş ve wildcard içerenleri atla
                    if path and path != '/' and '*' not in path:
                        paths.append(path.lstrip('/'))
    except requests.RequestException:
        pass
    return list(set(paths))


def get_baseline(base_url):
    """Var olmayan dosya ve dizin isteklerine sunucunun nasıl yanıt verdiğini ölçer."""
    rnd = ''.join(random.choices(string.ascii_lowercase + string.digits, k=15))

    file_res = {"status_code": 404, "len": 0}
    try:
        r = requests.get(f"{base_url}/{rnd}.html", headers=HEADERS, timeout=4, allow_redirects=False)
        file_res = {"status_code": r.status_code, "len": len(r.content)}
    except requests.RequestException:
        pass

    dir_res = {"status_code": 404, "len": 0}
    try:
        r = requests.get(f"{base_url}/{rnd}/", headers=HEADERS, timeout=4, allow_redirects=False)
        dir_res = {"status_code": r.status_code, "len": len(r.content)}
    except requests.RequestException:
        pass

    return {"file": file_res, "dir": dir_res}


def check_path(url, baseline, homepage):
    """Tek bir path'i test eder ve false positive'leri filtreler."""
    try:
        response = requests.get(url, headers=HEADERS, timeout=3, allow_redirects=False)
        content_length = len(response.content)
        status = response.status_code

        # Redirect kontrolü
        if status in [301, 302, 307, 308]:
            # Hem file hem dir baseline ile karşılaştır
            if (status == baseline['dir']['status_code'] and abs(content_length - baseline['dir']['len']) < 50) or \
               (status == baseline['file']['status_code'] and abs(content_length - baseline['file']['len']) < 50):
                return None

            loc = response.headers.get('Location', '')
            if loc:
                target = urljoin(url, loc) if not loc.startswith('http') else loc

                # Anasayfaya yönlendiriyorsa false positive — atla
                if target.rstrip('/') + '/' == homepage:
                    return None

                try:
                    f_res = requests.get(target, headers=HEADERS, timeout=3, allow_redirects=True)
                    if f_res.status_code in [200, 403]:
                        return {"url": url, "status": status, "size": len(f_res.content), "redirect": target}
                except requests.RequestException:
                    pass
            return None

        # Doğrudan erişim
        if status in [200, 403]:
            if status == baseline['file']['status_code'] and abs(content_length - baseline['file']['len']) < 50:
                return None
            return {"url": url, "status": status, "size": content_length, "redirect": None}

    except requests.RequestException:
        pass
    return None


def scan_directories(domain):
    """Ana dizin tarama giriş noktası."""
    base_url = None
    for proto in ["https://", "http://"]:
        try:
            r = requests.get(f"{proto}{domain}", headers=HEADERS, timeout=3, allow_redirects=True)
            base_url = r.url.rstrip('/')
            break
        except requests.RequestException:
            continue

    if not base_url:
        base_url = f"http://{domain}"

    # homepage bir kez hesaplandı — check_path'e her çağrıda urlparse yapılmıyor
    parsed = urlparse(base_url)
    homepage = f"{parsed.scheme}://{parsed.netloc}/"

    baseline = get_baseline(base_url)
    robots_paths = check_robots_txt(base_url)

    wordlist = [
        # Gizli / Hassas Dosyalar
        '.env', '.env.old', '.env.backup', '.env.production',
        '.git/config', '.git/HEAD', '.git/COMMIT_EDITMSG',
        '.htaccess', '.htpasswd', 'web.config',
        '.ssh/id_rsa', '.ssh/authorized_keys',
        # Konfigürasyon & Kaynak Dosyalar
        'config.php', 'config.yml', 'config.json',
        'wp-config.php', 'wp-config.php.bak',
        'composer.json', 'composer.lock', 'package.json',
        'dockerfile', 'docker-compose.yml',
        # Yedek / Veritabanı Dökümleri
        'backup.zip', 'backup.tar.gz', 'site.zip', 'www.zip',
        'database.sql', 'dump.sql', 'db.sql', 'backup.sql',
        # Sunucu Bilgisi & Durum Sayfaları
        'phpinfo.php', 'info.php', 'test.php',
        'server-status', 'server-info',
        # Admin & Giriş Panelleri
        'admin/', 'administrator/', 'admin/login',
        'cp/', 'cpanel/', 'whm/',
        'login/', 'signin', 'wp-login.php', 'wp-admin/',
        'panel/', 'dashboard/', 'manage/',
        # API & Geliştirme Endpoint'leri
        'api/', 'api/v1/', 'api/v2/',
        'swagger/', 'swagger-ui.html', 'api-docs',
        'graphql', '.well-known/security.txt',
        # Log & Geçici Dosyalar
        'error.log', 'access.log', 'debug.log',
        'tmp/', 'temp/', 'cache/',
    ]

    # robots.txt'ten gelen path'leri wordlist'e ekle (duplicate olmadan)
    wordlist_set = set(wordlist)
    for p in robots_paths:
        if p not in wordlist_set and f"{p}/" not in wordlist_set:
            wordlist.append(p)
            wordlist_set.add(p)

    targets = [f"{base_url}/{w.lstrip('/')}" for w in wordlist]
    found = []

    # Boş thread açmamak için max_workers hedef sayısıyla sınırlandı
    workers = min(40, len(targets))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(check_path, t, baseline, homepage): t for t in targets}
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                found.append(res)

    return {"robots_count": len(robots_paths), "discovered": found}
