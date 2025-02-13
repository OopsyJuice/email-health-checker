import dns.resolver
import requests

# Common DKIM selectors used by email providers
DKIM_SELECTORS = ["default", "google", "selector1", "selector2"]

# Free Blacklist DNS servers (replace with API if needed)
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
    except dns.resolver.NoAnswer:
        results["SPF"] = "Record Not Found"
    except dns.resolver.NXDOMAIN:
        results["SPF"] = "Domain does not exist"
    except dns.resolver.LifetimeTimeout:
        results["SPF"] = "DNS timeout"
    except Exception as e:
        results["SPF"] = f"Error: {str(e)}"

    # Check DKIM (Try multiple selectors)
    dkim_found = False
    for selector in DKIM_SELECTORS:
        try:
            dkim_records = dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
            dkim_found = True
            break  # Stop checking if we find a DKIM record
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except dns.resolver.LifetimeTimeout:
            results["DKIM"] = "DNS timeout"
            break
        except Exception as e:
            results["DKIM"] = f"Error: {str(e)}"
            break

    results["DKIM"] = dkim_found if dkim_found else "Record Not Found"

    # Check DMARC
    try:
        dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        results["DMARC"] = any("v=DMARC1" in record.to_text() for record in dmarc_records)
    except dns.resolver.NoAnswer:
        results["DMARC"] = "Record Not Found"
    except dns.resolver.NXDOMAIN:
        results["DMARC"] = "Domain does not exist"
    except dns.resolver.LifetimeTimeout:
        results["DMARC"] = "DNS timeout"
    except Exception as e:
        results["DMARC"] = f"Error: {str(e)}"

    return results


def check_blacklist_status(domain):
    """Check if a domain is blacklisted by querying common DNSBL servers."""
    results = {}

    for bl_server in BLACKLIST_SERVERS:
        try:
            query = f"{domain}.{bl_server}"
            dns.resolver.resolve(query, "A")  # If we get a response, it's blacklisted
            results[bl_server] = "Blacklisted"
        except dns.resolver.NoAnswer:
            results[bl_server] = "Not Listed"
        except dns.resolver.NXDOMAIN:
            results[bl_server] = "Not Listed"
        except dns.resolver.LifetimeTimeout:
            results[bl_server] = "DNS timeout"
        except Exception as e:
            results[bl_server] = f"Error: {str(e)}"

    return results
