import dns.resolver
import whois

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
        results["SPF"] = any("v=spf1" in record.to_text() for record in spf_records)
    except:
        results["SPF"] = "Record Not Found"

    # Check DKIM
    dkim_found = False
    for selector in DKIM_SELECTORS:
        try:
            dkim_records = dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
            dkim_found = True
            break  # Stop checking if we find a DKIM record
        except:
            continue

    results["DKIM"] = dkim_found if dkim_found else "Record Not Found"

    # Check DMARC
    try:
        dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        results["DMARC"] = any("v=DMARC1" in record.to_text() for record in dmarc_records)
    except:
        results["DMARC"] = "Record Not Found"

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
    """Retrieve WHOIS information for a given domain."""
    try:
        w = whois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "nameservers": w.name_servers
        }
    except:
        return {"error": "WHOIS lookup failed"}


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
