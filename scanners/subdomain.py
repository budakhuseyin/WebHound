import requests


def find_subdomains(domain):
    try:
        crt_url = f"https://crt.sh/?q=%.{domain}&output=json"
        # User-Agent ekleyerek crt.sh'in bizi bot olarak engellemesini önle
        headers = {"User-Agent": "Mozilla/5.0 (compatible; WebHound/1.0)"}
        response = requests.get(crt_url, headers=headers, timeout=25)

        if response.status_code != 200:
            return [f"API Error: crt.sh returned HTTP {response.status_code}."]

        # crt.sh bazen yoğunlukta JSON yerine HTML sayfası döner
        content_type = response.headers.get("Content-Type", "")
        if "json" not in content_type:
            return ["API Error: crt.sh returned non-JSON response (likely overloaded). Try again later."]

        data = response.json()
        unique_subdomains = set()

        for entry in data:
            name_value = entry.get("name_value", "")
            for sub in name_value.split("\n"):
                sub = sub.strip()
                # Wildcard ve boş stringleri atla, ana domainin kendisini de atla
                if sub and "*" not in sub and sub != domain:
                    unique_subdomains.add(sub)

        return sorted(unique_subdomains)

    except requests.exceptions.Timeout:
        return ["Connection Error: crt.sh timed out (large domain?). Try again."]
    except requests.exceptions.JSONDecodeError:
        return ["API Error: crt.sh returned invalid JSON. Try again later."]
    except Exception as e:
        return [f"Connection Error: {str(e)}"]
