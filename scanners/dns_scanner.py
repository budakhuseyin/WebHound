import dns.resolver

def scan_dns_records(domain):
    records = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "TXT": [],
        "NS": []
    }
    
    record_types = ["A", "AAAA", "MX", "TXT", "NS"]
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            for rdata in answers:
                if record_type == "MX":
                    records[record_type].append(f"{rdata.preference} {rdata.exchange.to_text().strip('.')}")
                elif record_type == "TXT":
                    records[record_type].append(rdata.to_text().strip('"'))
                else:
                    records[record_type].append(rdata.to_text().strip('.'))
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NoNameservers:
            continue
        except dns.resolver.NXDOMAIN:
            records["error"] = "Domain does not exist"
            return records
        except dns.resolver.Timeout:
            continue
        except Exception:
            continue
            
    return records
