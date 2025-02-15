import dns.resolver
import whois
import requests
from datetime import datetime

# Common DKIM selectors used by email providers
DKIM_SELECTORS = ["default", "google", "selector1", "selector2"]

# Free Blacklist DNS servers
BLACKLIST_SERVERS = [
    "zen.spamhaus.org",
    "b.barracudacentral.org",
    "bl.spamcop.net"
]

def check_dns_records(domain):
    """Check SPF, DKIM, and DMARC records for a given domain."""
    results = {}

    # Check SPF
    try:
        spf_records = dns.resolver.resolve(domain, "TXT")
        spf_record = next((record.to_text() for record in spf_records if "v=spf1" in record.to_text()), None)
        results["SPF"] = bool(spf_record)
        results["spf_details"] = spf_record.strip('"') if spf_record else "No SPF record found"
    except Exception as e:
        results["SPF"] = False
        results["spf_details"] = f"Error retrieving SPF record: {str(e)}"

    # Check DKIM
    dkim_found = False
    dkim_details = []
    for selector in DKIM_SELECTORS:
        try:
            dkim_records = dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
            dkim_record = dkim_records[0].to_text()
            dkim_found = True
            dkim_details.append(f"Selector '{selector}': {dkim_record.strip('\"')}")
        except:
            continue

    results["DKIM"] = dkim_found
    results["dkim_details"] = "\n".join(dkim_details) if dkim_details else "No DKIM records found"

    # Check DMARC
    try:
        dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc_record = next((record.to_text() for record in dmarc_records if "v=DMARC1" in record.to_text()), None)
        results["DMARC"] = bool(dmarc_record)
        results["dmarc_details"] = dmarc_record.strip('"') if dmarc_record else "No DMARC record found"
    except Exception as e:
        results["DMARC"] = False
        results["dmarc_details"] = f"Error retrieving DMARC record: {str(e)}"

    return results


def check_blacklist_status(domain):
    """Check if a domain is blacklisted by querying common DNSBL servers."""
    results = {}

    for bl_server in BLACKLIST_SERVERS:
        try:
            query = f"{domain}.{bl_server}"
            dns.resolver.resolve(query, "A")  # If we get a response, it's blacklisted
            results[bl_server] = "Blacklisted"
        except:
            results[bl_server] = "Not Listed"

    return results


def get_whois_info(domain):
    """Retrieve WHOIS information for a given domain with fallback options."""
    nameservers = get_nameservers_direct(domain)  # Get nameservers first
    
    # Try primary python-whois first
    whois_info = try_python_whois(domain)
    if whois_info.get("registrar") != "Lookup Failed":
        whois_info['nameservers'] = nameservers or whois_info.get('nameservers', [])
        return whois_info
    
    # If primary fails, try WHOIS API fallback
    api_info = try_whois_api(domain)
    if api_info:
        api_info['nameservers'] = nameservers or api_info.get('nameservers', [])
        return api_info
        
    # If both fail, return with direct nameservers
    return {
        "registrar": "Lookup Failed",
        "creation_date": "Unknown",
        "expiration_date": "Unknown",
        "nameservers": nameservers
    }

def try_python_whois(domain):
    """Try to get WHOIS info using python-whois library."""
    try:
        w = whois.whois(domain)
        if w and hasattr(w, 'registrar'):
            return {
                "registrar": w.registrar if w.registrar else "Unknown",
                "creation_date": str(w.creation_date) if w.creation_date else "Unknown",
                "expiration_date": str(w.expiration_date) if w.expiration_date else "Unknown",
                "nameservers": []  # We'll add nameservers from direct lookup
            }
    except Exception as e:
        print(f"Python WHOIS lookup failed for {domain}: {str(e)}")
    
    return {"registrar": "Lookup Failed"}

def try_whois_api(domain):
    """Try to get WHOIS info using WHOIS API."""
    try:
        response = requests.get(f"https://rdap.org/domain/{domain}")
        if response.status_code == 200:
            data = response.json()
            return {
                "registrar": data.get('entities', [{}])[0].get('vcardArray', [[]])[1][3] if data.get('entities') else 'Unknown',
                "creation_date": format_date(data.get('events', [{}])[0].get('eventDate')),
                "expiration_date": "Not Available via RDAP",
                "nameservers": []  # We'll add nameservers from direct lookup
            }
    except Exception as e:
        print(f"RDAP lookup failed for {domain}: {str(e)}")
    
    return None

def format_date(date_str):
    """Format date string to consistent format."""
    if not date_str:
        return "Unknown"
    try:
        if isinstance(date_str, (list, tuple)):
            date_str = date_str[0]
        if isinstance(date_str, str):
            # Try different date formats
            for fmt in ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d", "%d-%b-%Y"]:
                try:
                    return datetime.strptime(date_str, fmt).strftime("%Y-%m-%d")
                except:
                    continue
        return str(date_str)
    except:
        return "Unknown"


def get_registrar_info(registrar):
    """Provide additional information about known registrars."""
    known_registrars = {
        "Key-Systems GmbH": "A domain registrar based in Germany, often used by resellers.",
        "GoDaddy": "One of the largest domain registrars worldwide.",
        "Namecheap": "Popular for affordable domains and privacy protection.",
        "Google Domains": "Google's domain registration service.",
        "Cloudflare": "DNS provider and security service offering domain registration.",
        "Squarespace Domains II LLC": "Squarespace's domain registration service."
    }
    return known_registrars.get(registrar, "No additional info available")


def get_nameserver_info(nameserver):
    """Provide context for common nameservers."""
    lower_ns = nameserver.lower()
    
    if "cloudflare.com" in lower_ns:
        return "Cloudflare (Security & DNS Provider)"
    elif "googledomains.com" in lower_ns:
        return "Google Domains (Registrar & DNS Provider)"
    elif "awsdns" in lower_ns:
        return "Amazon AWS Route 53 (Cloud Hosting)"
    elif "namecheap.com" in lower_ns:
        return "Namecheap (Domain Registrar & Hosting)"
    elif "godaddy.com" in lower_ns:
        return "GoDaddy (Domain Registrar & Hosting)"
    elif "squarespace" in lower_ns:
        return "Squarespace (Website Builder & DNS Provider)"
    else:
        return "Unknown Provider"

def get_nameservers_direct(domain):
    """Get nameservers directly through DNS query."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        answers = resolver.resolve(domain, 'NS')
        nameservers = [str(rdata.target).rstrip('.') for rdata in answers]
        print(f"Found nameservers for {domain}: {nameservers}")  # Debug print
        return nameservers
    except Exception as e:
        print(f"Direct NS lookup failed for {domain}: {str(e)}")
        return []
