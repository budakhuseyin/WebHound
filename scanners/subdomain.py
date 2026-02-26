import requests


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
