import whois
from datetime import datetime

def format_date(date_obj):
    if isinstance(date_obj, list):
        date_obj = date_obj[0]
        
    if isinstance(date_obj, datetime):
        return date_obj.strftime("%Y-%m-%d %H:%M:%S")
    elif isinstance(date_obj, str):
        return date_obj
    return "Not Found"

def format_list(item_obj):
    if item_obj is None:
        return []
    if isinstance(item_obj, list):
        return list(set(str(item).lower().strip() for item in item_obj if item))
    return [str(item_obj).lower().strip()]

def get_whois_info(domain):
    whois_data = {
        "registrar": "Not Found",
        "creation_date": "Not Found",
        "expiration_date": "Not Found",
        "updated_date": "Not Found",
        "name_servers": [],
        "country": "Not Found",
        "emails": []
    }

    try:
        domain_info = whois.whois(domain)

        if domain_info.registrar:
            whois_data["registrar"] = domain_info.registrar

        if domain_info.creation_date:
            whois_data["creation_date"] = format_date(domain_info.creation_date)

        if domain_info.expiration_date:
            whois_data["expiration_date"] = format_date(domain_info.expiration_date)

        if domain_info.updated_date:
            whois_data["updated_date"] = format_date(domain_info.updated_date)

        if domain_info.name_servers:
            whois_data["name_servers"] = format_list(domain_info.name_servers)

        if domain_info.country:
            whois_data["country"] = str(domain_info.country).upper()

        if domain_info.emails:
            whois_data["emails"] = format_list(domain_info.emails)

    except Exception as e:
        whois_data["error"] = f"WHOIS error: {str(e)}"

    return whois_data
