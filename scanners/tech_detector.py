import requests
from bs4 import BeautifulSoup

def detect_technologies(url):
    """
    Hedef sistemin web sunucusu, backend dili, framework,
    CMS ve frontend kütüphanelerini tespit eder.
    """
    # Eğer protokolsüz gelirse http ekle
    if not url.startswith('http'):
        url = 'http://' + url

    tech_stack = {
        "web_server": "Not Found",
        "waf": "Not Detected",
        "programming_language": "Not Found",
        "framework": "Not Found",
        "cms": "Not Found",
        "frontend": []
    }

    try:
        # User-Agent ekleyerek waf/bot korumalarından bir nebze kaçınalım
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, headers=headers, timeout=10)
        
        resp_headers = response.headers
        cookies = response.cookies
        html_content = response.text
        
        # PERFORMANS İYİLEŞTİRMESİ: RAM tasarrufu için metni bir kez lower() yapıp değişkende tutalım
        html_content_lower = html_content.lower()
        
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # 1. Web Sunucuları (Web Servers)
        server_header = resp_headers.get('Server', '').lower()
        if 'nginx' in server_header:
            tech_stack['web_server'] = "Nginx" + (" " + resp_headers.get('Server').split('/')[1] if '/' in resp_headers.get('Server') else "")
        elif 'apache' in server_header:
            tech_stack['web_server'] = "Apache" + (" " + resp_headers.get('Server').split('/')[1] if '/' in resp_headers.get('Server') else "")
        elif 'iis' in server_header or 'microsoft' in server_header:
            tech_stack['web_server'] = "Microsoft IIS"
        elif 'cloudflare' in server_header:
            tech_stack['web_server'] = 'Cloudflare'
        elif 'litespeed' in server_header:
            tech_stack['web_server'] = 'LiteSpeed'
        elif server_header:
            tech_stack['web_server'] = resp_headers.get('Server')
            
        # --- WAF (Web Application Firewall) Tespiti ---
        # Genellikle çok spesifik header başlıkları veya çerezlerle kendilerini belli ederler
        waf_headers = str(resp_headers).lower()
        
        if 'cloudflare' in server_header or '__cfduid' in cookie_names_str or 'cf-ray' in waf_headers:
            tech_stack['waf'] = 'Cloudflare'
            tech_stack['web_server'] = 'Cloudflare' # Web sunucusunu da ezmiş olur
        elif 'x-sucuri' in waf_headers or 'sucuri' in server_header:
            tech_stack['waf'] = 'Sucuri'
        elif 'x-hw' in waf_headers or 'highwinds' in server_header:
            tech_stack['waf'] = 'Highwinds / StackPath'
        elif 'imperva' in server_header or 'incap_ses' in cookie_names_str or 'visid_incap' in cookie_names_str:
            tech_stack['waf'] = 'Imperva (Incapsula)'
        elif 'akamai' in server_header or 'x-akamai' in waf_headers:
            tech_stack['waf'] = 'Akamai'
        elif 'awselb' in cookie_names_str or 'awsalb' in cookie_names_str:
            tech_stack['waf'] = 'AWS WAF / ALB'
        elif 'f5' in server_header or 'bigip' in cookie_names_str:
            tech_stack['waf'] = 'F5 BIG-IP'
            
        # 2. Backend Dilleri (Programming Languages)
        powered_by = resp_headers.get('X-Powered-By', '').lower()
        cookie_names = [c.name.lower() for c in cookies]
        
        # LİSTE İÇİ SUBSTRING ÇÖZÜMÜ: cookie'leri text string'e dönüştürüp aratmak en garantisidir
        cookie_names_str = str(cookie_names)
        
        if 'php' in powered_by or 'phpsessid' in cookie_names_str or '.php' in html_content_lower:
            tech_stack['programming_language'] = "PHP"
        elif 'python' in powered_by:
            tech_stack['programming_language'] = "Python"
        elif 'ruby' in powered_by:
            tech_stack['programming_language'] = "Ruby"
        elif 'java' in powered_by or 'jsessionid' in cookie_names_str or '.jsp' in html_content_lower:
            tech_stack['programming_language'] = "Java"
        elif 'asp.net' in powered_by or 'aspsessionid' in cookie_names_str or '.aspx' in html_content_lower:
            tech_stack['programming_language'] = "ASP.NET"
            
        # 3. Web Framework'leri (Çatıları)
        # YANLIŞ ALARM (FALSE POSITIVE) ÇÖZÜMÜ: html_content içinde düz 'django' aramak yerine,
        # sadece o sisteme özgü kesin izlere (çerezler vb.) bakıyoruz.
        if 'csrftoken' in cookie_names_str:
            tech_stack['framework'] = "Django"
            if tech_stack['programming_language'] == "Not Found":
                tech_stack['programming_language'] = "Python"
        elif 'laravel' in cookie_names_str:
            tech_stack['framework'] = "Laravel"
            tech_stack['programming_language'] = "PHP"
        elif 'rack.session' in cookie_names_str:
            tech_stack['framework'] = "Ruby on Rails"
            tech_stack['programming_language'] = "Ruby"
        elif 'express' in powered_by:
            tech_stack['framework'] = "Express.js"
            tech_stack['programming_language'] = "JavaScript (Node.js)"
        elif 'x-aspnetmvc-version' in [k.lower() for k in resp_headers.keys()]:
            tech_stack['framework'] = "ASP.NET MVC"
            tech_stack['programming_language'] = "ASP.NET"
            
        # 4. İçerik Yönetim Sistemleri (CMS)
        generator = soup.find('meta', attrs={'name': 'generator'})
        gen_content = generator.get('content', '').lower() if generator else ''
        
        if 'wordpress' in gen_content or 'wp-content' in html_content_lower or 'wp-includes' in html_content_lower:
            tech_stack['cms'] = "WordPress"
            tech_stack['programming_language'] = "PHP"
        elif 'joomla' in gen_content:
            tech_stack['cms'] = "Joomla"
            tech_stack['programming_language'] = "PHP"
        elif 'drupal' in gen_content:
            tech_stack['cms'] = "Drupal"
            tech_stack['programming_language'] = "PHP"
        elif 'magento' in gen_content or 'mage.cookies' in html_content_lower:
            tech_stack['cms'] = "Magento"
            tech_stack['programming_language'] = "PHP"
        elif 'shopify' in gen_content or 'cdn.shopify.com' in html_content_lower:
            tech_stack['cms'] = "Shopify"

        # 5. Frontend Kütüphaneleri (JavaScript & CSS)
        frontend_libs = set()
        
        # Script ve Link etiketlerinde src/href tarama
        scripts_and_links = [tag.get('src', '') or '' for tag in soup.find_all('script')] + \
                            [tag.get('href', '') or '' for tag in soup.find_all('link')]
        assets_text = ' '.join(scripts_and_links).lower()
        
        # Vue ve React gibi tool'lar için düz metin aramasını çıkardık, spesifik attribute veya dosyaları arıyoruz
        if 'data-reactroot' in html_content_lower or 'react.production' in assets_text:
            frontend_libs.add("React")
        if 'data-v-' in html_content_lower or 'vue.min.js' in assets_text or 'vue@' in assets_text:
            frontend_libs.add("Vue.js")
        if 'ng-app' in html_content_lower or 'angular' in assets_text:
            frontend_libs.add("Angular")
        if 'bootstrap' in assets_text or 'bootstrap' in html_content_lower:
            frontend_libs.add("Bootstrap")
        if 'jquery' in assets_text:
            frontend_libs.add("jQuery")
            
        if frontend_libs:
            tech_stack['frontend'] = list(frontend_libs)
            
    except Exception as e:
        tech_stack["error"] = f"Tarama sırasında hata oluştu: {str(e)}"
        
    return tech_stack
