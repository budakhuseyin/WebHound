import requests
from bs4 import BeautifulSoup


def _extract_server_version(raw_header, label):
    """Server header'ından güvenli şekilde versiyon bilgisi çıkarır."""
    if raw_header and '/' in raw_header:
        parts = raw_header.split('/', 1)
        if len(parts) > 1 and parts[1].strip():
            return f"{label} {parts[1].strip()}"
    return label


def detect_technologies(url):
    """
    Hedef sistemin web sunucusu, backend dili, framework,
    CMS ve frontend kütüphanelerini tespit eder.
    """
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
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)

        resp_headers = response.headers
        cookies = response.cookies
        html_content = response.text
        html_lower = html_content.lower()

        soup = BeautifulSoup(html_content, 'html.parser')

        # Header key'lerini bir kez küçük harfe çevir (tekrarlı list comprehension yerine)
        lower_header_keys = {k.lower() for k in resp_headers.keys()}

        # Cookie isimlerini set olarak tut (string substring çakışması önlendi)
        cookie_names = {c.name.lower() for c in cookies}

        server_raw = resp_headers.get('Server', '')
        server_lower = server_raw.lower()
        powered_by = resp_headers.get('X-Powered-By', '').lower()

        # -- 1. Web Sunucusu --------------------------------------------------
        if 'nginx' in server_lower:
            tech_stack['web_server'] = _extract_server_version(server_raw, 'Nginx')
        elif 'apache' in server_lower:
            tech_stack['web_server'] = _extract_server_version(server_raw, 'Apache')
        elif 'iis' in server_lower or 'microsoft' in server_lower:
            tech_stack['web_server'] = _extract_server_version(server_raw, 'Microsoft IIS')
        elif 'litespeed' in server_lower:
            tech_stack['web_server'] = 'LiteSpeed'
        elif 'cloudflare' in server_lower:
            tech_stack['web_server'] = 'Cloudflare'
        elif 'openresty' in server_lower:
            tech_stack['web_server'] = 'OpenResty (Nginx + Lua)'
        elif 'caddy' in server_lower:
            tech_stack['web_server'] = 'Caddy'
        elif 'gunicorn' in server_lower:
            tech_stack['web_server'] = 'Gunicorn'
        elif 'werkzeug' in server_lower:
            tech_stack['web_server'] = 'Werkzeug (Dev Server)'
        elif server_raw:
            tech_stack['web_server'] = server_raw

        # -- 2. WAF Tespiti ---------------------------------------------------
        # NOT: WAF bulununca web_server alani EZILMIYOR, ayri tutulur
        if 'cloudflare' in server_lower or 'cf-ray' in lower_header_keys or 'cf-cache-status' in lower_header_keys:
            tech_stack['waf'] = 'Cloudflare'
            if tech_stack['web_server'] == 'Not Found':
                tech_stack['web_server'] = 'Cloudflare'
        elif 'x-sucuri-id' in lower_header_keys or 'sucuri' in server_lower:
            tech_stack['waf'] = 'Sucuri'
        elif 'x-hw' in lower_header_keys or 'highwinds' in server_lower:
            tech_stack['waf'] = 'Highwinds / StackPath'
        elif 'imperva' in server_lower or 'incap_ses' in cookie_names or 'visid_incap' in cookie_names:
            tech_stack['waf'] = 'Imperva (Incapsula)'
        elif 'x-akamai-transformed' in lower_header_keys or 'akamai' in server_lower:
            tech_stack['waf'] = 'Akamai'
        elif 'awselb' in cookie_names or 'awsalb' in cookie_names or 'awsalbcors' in cookie_names:
            tech_stack['waf'] = 'AWS WAF / ALB'
        elif 'f5' in server_lower or 'bigipserver' in cookie_names or 'bigip' in cookie_names:
            tech_stack['waf'] = 'F5 BIG-IP'

        # -- 3. Backend Dili --------------------------------------------------
        if 'php' in powered_by or 'phpsessid' in cookie_names or '.php' in html_lower:
            tech_stack['programming_language'] = 'PHP'
        elif 'python' in powered_by:
            tech_stack['programming_language'] = 'Python'
        elif 'ruby' in powered_by:
            tech_stack['programming_language'] = 'Ruby'
        elif 'java' in powered_by or 'jsessionid' in cookie_names or '.jsp' in html_lower:
            tech_stack['programming_language'] = 'Java'
        elif 'asp.net' in powered_by or 'aspsessionid' in cookie_names or '.aspx' in html_lower:
            tech_stack['programming_language'] = 'ASP.NET'
        elif 'go' in powered_by or 'gin' in server_lower or 'fiber' in server_lower:
            tech_stack['programming_language'] = 'Go'
        elif 'node' in powered_by or 'express' in powered_by:
            tech_stack['programming_language'] = 'JavaScript (Node.js)'

        # -- 4. Framework -----------------------------------------------------
        if 'csrftoken' in cookie_names:
            tech_stack['framework'] = 'Django'
            if tech_stack['programming_language'] == 'Not Found':
                tech_stack['programming_language'] = 'Python'
        elif 'laravel_session' in cookie_names or 'xsrf-token' in cookie_names:
            tech_stack['framework'] = 'Laravel'
            tech_stack['programming_language'] = 'PHP'
        elif 'rack.session' in cookie_names:
            tech_stack['framework'] = 'Ruby on Rails'
            tech_stack['programming_language'] = 'Ruby'
        elif 'express' in powered_by:
            tech_stack['framework'] = 'Express.js'
            tech_stack['programming_language'] = 'JavaScript (Node.js)'
        elif 'x-aspnetmvc-version' in lower_header_keys:
            tech_stack['framework'] = 'ASP.NET MVC'
            tech_stack['programming_language'] = 'ASP.NET'
        elif 'id="__next"' in html_lower or '/_next/' in html_lower or 'x-nextjs-cache' in lower_header_keys:
            tech_stack['framework'] = 'Next.js'
            tech_stack['programming_language'] = 'JavaScript (Node.js)'
        elif 'id="__nuxt"' in html_lower or '/_nuxt/' in html_lower:
            tech_stack['framework'] = 'Nuxt.js'
            tech_stack['programming_language'] = 'JavaScript (Node.js)'
        elif '__remixcontext' in html_lower or 'id="__remix"' in html_lower:
            tech_stack['framework'] = 'Remix'
            tech_stack['programming_language'] = 'JavaScript (Node.js)'
        elif '___gatsby' in html_lower or 'gatsby-chunk-' in html_lower:
            tech_stack['framework'] = 'Gatsby'
            tech_stack['programming_language'] = 'JavaScript (Node.js)'
        elif '/_app/immutable/' in html_lower or 'sveltekit' in html_lower:
            tech_stack['framework'] = 'SvelteKit'
            tech_stack['programming_language'] = 'JavaScript (Node.js)'
        elif 'astro-island' in html_lower or 'data-astro-cid' in html_lower:
            tech_stack['framework'] = 'Astro'
            tech_stack['programming_language'] = 'JavaScript (Node.js)'
        elif 'werkzeug' in server_lower:
            tech_stack['framework'] = 'Flask / Werkzeug'
            tech_stack['programming_language'] = 'Python'
        elif 'x-application-context' in lower_header_keys:
            tech_stack['framework'] = 'Spring Boot'
            tech_stack['programming_language'] = 'Java'

        # -- 5. CMS -----------------------------------------------------------
        generator = soup.find('meta', attrs={'name': 'generator'})
        gen_content = generator.get('content', '').lower() if generator else ''

        if 'wordpress' in gen_content or 'wp-content' in html_lower or 'wp-includes' in html_lower:
            tech_stack['cms'] = 'WordPress'
            tech_stack['programming_language'] = 'PHP'
        elif 'joomla' in gen_content:
            tech_stack['cms'] = 'Joomla'
            tech_stack['programming_language'] = 'PHP'
        elif 'drupal' in gen_content or 'drupal.settings' in html_lower:
            tech_stack['cms'] = 'Drupal'
            tech_stack['programming_language'] = 'PHP'
        elif 'magento' in gen_content or 'mage.cookies' in html_lower:
            tech_stack['cms'] = 'Magento'
            tech_stack['programming_language'] = 'PHP'
        elif 'shopify' in gen_content or 'cdn.shopify.com' in html_lower:
            tech_stack['cms'] = 'Shopify'
        elif 'wix.com' in html_lower or 'x-wix-published-version' in lower_header_keys:
            tech_stack['cms'] = 'Wix'
        elif 'squarespace' in html_lower:
            tech_stack['cms'] = 'Squarespace'
        elif 'data-wf-site' in html_lower or 'webflow' in html_lower:
            tech_stack['cms'] = 'Webflow'
        elif 'ghost' in gen_content or '/ghost/' in html_lower:
            tech_stack['cms'] = 'Ghost'
        elif 'contentful' in html_lower:
            tech_stack['cms'] = 'Contentful (Headless)'

        # -- 6. Frontend Kutuphaneleri ----------------------------------------
        frontend_libs = set()

        scripts_and_links = (
            [tag.get('src', '') or '' for tag in soup.find_all('script')] +
            [tag.get('href', '') or '' for tag in soup.find_all('link')]
        )
        assets_text = ' '.join(scripts_and_links).lower()

        if 'data-reactroot' in html_lower or 'react.production' in assets_text or 'react-dom' in assets_text:
            frontend_libs.add('React')
        if 'data-v-' in html_lower or 'vue.min.js' in assets_text or 'vue@' in assets_text or '/vue.' in assets_text:
            frontend_libs.add('Vue.js')
        if 'ng-app' in html_lower or 'angular' in assets_text or 'angularjs' in assets_text:
            frontend_libs.add('Angular')
        if 'svelte' in assets_text and '/_app/' in html_lower:
            frontend_libs.add('Svelte')
        if 'bootstrap' in assets_text or 'bootstrap.min.css' in html_lower:
            frontend_libs.add('Bootstrap')
        if 'jquery' in assets_text or 'jquery.min.js' in html_lower:
            frontend_libs.add('jQuery')
        if 'tailwindcss' in assets_text or 'cdn.tailwindcss.com' in html_lower:
            frontend_libs.add('Tailwind CSS')
        if 'alpinejs' in assets_text or ' x-data=' in html_lower:
            frontend_libs.add('Alpine.js')
        if 'htmx' in assets_text or ' hx-get=' in html_lower or ' hx-post=' in html_lower:
            frontend_libs.add('htmx')
        if 'gsap' in assets_text or 'greensock' in assets_text:
            frontend_libs.add('GSAP')

        if frontend_libs:
            tech_stack['frontend'] = sorted(frontend_libs)

    except Exception as e:
        tech_stack["error"] = f"Tech detection failed: {str(e)}"

    return tech_stack
