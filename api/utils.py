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

def analyze_spf_record(spf_record):
    """Analyze SPF record and provide detailed interpretation."""
    if not spf_record:
        return {
            "status": "Not Found",
            "analysis": "No SPF record found. This may allow email spoofing.",
            "recommendations": ["Add an SPF record to prevent email spoofing"]
        }
    
    mechanisms = spf_record.split()
    analysis = []
    recommendations = []
    
    # Check version
    if mechanisms[0] != "v=spf1":
        return {
            "status": "Invalid",
            "analysis": "Invalid SPF record format",
            "recommendations": ["SPF record must start with v=spf1"]
        }
    
    # Analyze each mechanism
    for mech in mechanisms[1:]:
        if mech.startswith("include:"):
            domain = mech.split(":")[1]
            analysis.append(f"Includes mail servers from {domain}")
        elif mech.startswith("ip4:") or mech.startswith("ip6:"):
            ip = mech.split(":")[1]
            analysis.append(f"Allows sending from IP {ip}")
        elif mech == "mx":
            analysis.append("Allows sending from domain's MX records")
        elif mech == "a":
            analysis.append("Allows sending from domain's A records")
        elif mech == "-all":
            analysis.append("Strict policy - rejects all other senders")
        elif mech == "~all":
            analysis.append("Soft fail policy - marks other senders as suspicious")
            recommendations.append("Consider using -all for stricter security")
        elif mech == "?all":
            analysis.append("Neutral policy - no opinion on other senders")
            recommendations.append("Use -all or ~all instead of ?all for better security")
    
    return {
        "status": "Valid",
        "analysis": analysis,
        "recommendations": recommendations,
        "raw_record": spf_record
    }

def analyze_dkim_record(dkim_records):
    """Analyze DKIM records and provide detailed interpretation."""
    if not dkim_records:
        return {
            "status": "Not Found",
            "analysis": ["No DKIM records found"],
            "recommendations": ["Configure DKIM to improve email authentication"],
            "raw_record": "No DKIM record found"
        }
    
    analysis = []
    recommendations = []
    
    for record in dkim_records:
        selector = record.get('selector', '')
        if 'v=DKIM1' in record.get('record', ''):
            analysis.append(f"Includes DKIM key for selector {selector}")
        if 'k=rsa' in record.get('record', ''):
            analysis.append(f"Uses RSA encryption for {selector}")
    
    return {
        "status": "Valid",
        "analysis": analysis,
        "recommendations": recommendations,
        "raw_record": "\n".join(r.get('record', '') for r in dkim_records)
    }

def analyze_dmarc_record(dmarc_record):
    """Analyze DMARC record and provide detailed interpretation."""
    if not dmarc_record:
        return {
            "status": "Not Found",
            "analysis": ["No DMARC record found"],
            "recommendations": ["Configure DMARC to enforce email authentication policies"],
            "raw_record": "No DMARC record found"
        }
    
    analysis = []
    recommendations = []
    
    if 'p=none' in dmarc_record:
        analysis.append("Monitor mode - no enforcement actions taken")
        recommendations.append("Consider using p=quarantine or p=reject for better security")
    elif 'p=quarantine' in dmarc_record:
        analysis.append("Quarantine mode - suspicious emails marked as spam")
    elif 'p=reject' in dmarc_record:
        analysis.append("Reject mode - failed messages are blocked")
    
    if 'pct=' in dmarc_record:
        pct = dmarc_record.split('pct=')[1].split()[0].rstrip(';')  # Remove trailing semicolon
        analysis.append(f"Policy applies to {pct}% of emails")
    
    return {
        "status": "Valid",
        "analysis": analysis,
        "recommendations": recommendations,
        "raw_record": dmarc_record
    }

def check_dns_records(domain):
    """Check SPF, DKIM, DMARC, and MX records for a given domain."""
    results = {}

    # SPF Check (existing code)
    try:
        spf_records = dns.resolver.resolve(domain, "TXT")
        spf_record = next((record.to_text().strip('"') for record in spf_records if "v=spf1" in record.to_text()), None)
        results["SPF"] = bool(spf_record)
        results["spf_analysis"] = analyze_spf_record(spf_record)
    except Exception as e:
        results["SPF"] = False
        results["spf_analysis"] = {
            "status": "Error",
            "analysis": [f"Error retrieving SPF record: {str(e)}"],
            "recommendations": ["Check DNS configuration"]
        }

    # DKIM Check
    dkim_records_found = []
    for selector in DKIM_SELECTORS:
        try:
            dkim_records = dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
            for record in dkim_records:
                dkim_records_found.append({
                    'selector': selector,
                    'record': record.to_text().strip('"')
                })
        except:
            continue
    
    results["DKIM"] = bool(dkim_records_found)
    results["dkim_analysis"] = analyze_dkim_record(dkim_records_found)

    # DMARC Check
    try:
        dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc_record = next((record.to_text().strip('"') for record in dmarc_records if "v=DMARC1" in record.to_text()), None)
        results["DMARC"] = bool(dmarc_record)
        results["dmarc_analysis"] = analyze_dmarc_record(dmarc_record)
    except Exception as e:
        results["DMARC"] = False
        results["dmarc_analysis"] = {
            "status": "Error",
            "analysis": [f"Error retrieving DMARC record: {str(e)}"],
            "recommendations": ["Check DNS configuration"]
        }

    # MX Record Check
    try:
        mx_records = dns.resolver.resolve(domain, "MX")
        mx_results = sorted([
            {
                'priority': record.preference,
                'hostname': record.exchange.to_text(omit_final_dot=True)
            } for record in mx_records
        ], key=lambda x: x['priority'])
        
        results["MX"] = bool(mx_records)
        results["mx_analysis"] = {
            "status": "Configured",
            "analysis": [],
            "recommendations": [],
            "raw_record": "\n".join([f"{r['hostname']}" for r in mx_results])
        }
    except Exception as e:
        results["MX"] = False
        results["mx_analysis"] = {
            "status": "Error",
            "analysis": [],
            "recommendations": ["Check DNS configuration"],
            "raw_record": ""
        }

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
        return "Generic DNS Provider"

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
