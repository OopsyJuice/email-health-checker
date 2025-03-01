"""
Email security provider definitions and detection logic.
"""

EMAIL_SECURITY_PROVIDERS = {
    "proofpoint": {
        "patterns": [
            "ppe-hosted.com"
        ],
        "regions": ["us1", "us2", "eu1", "eu2"],
        "format": "mx{1,2}-{region}.ppe-hosted.com",
        "name": "Proofpoint",
        "type": "Security Gateway"
    },
    "mimecast": {
        "patterns": [
            "mimecast.com",
            "mimecast.co.za",
            "mimecast-offshore.com"
        ],
        "regions": {
            "eu": "Europe",
            "de": "Germany",
            "us": "United States",
            "usb": "United States (B)",
            "ca": "Canada",
            "za": "South Africa",
            "au": "Australia",
            "je": "Offshore"
        },
        "format": "{region}-smtp-inbound-{1,2}.mimecast{tld}",
        "name": "Mimecast",
        "type": "Security Gateway"
    },
    "google": {
        "patterns": [
            "aspmx.l.google.com",
            "alt[1-4].aspmx.l.google.com"
        ],
        "expected_priorities": {
            "aspmx.l.google.com": 1,
            "alt[1-2].aspmx.l.google.com": 5,
            "alt[3-4].aspmx.l.google.com": 10
        },
        "name": "Google Workspace",
        "type": "Mail Provider"
    },
    "microsoft": {
        "patterns": [
            "mail.protection.outlook.com"
        ],
        "name": "Microsoft 365",
        "type": "Mail Provider"
    },
    "barracuda": {
        "patterns": [
            "barracudanetworks.com"
        ],
        "name": "Barracuda",
        "type": "Security Gateway"
    }
}

def detect_mail_provider(mx_records):
    """
    Detect mail security providers from MX records.
    
    Args:
        mx_records (list): List of tuples containing (hostname, priority)
        
    Returns:
        dict: Dictionary containing detected providers and configuration details
    """
    detected = []
    for hostname, priority in mx_records:
        for provider, details in EMAIL_SECURITY_PROVIDERS.items():
            for pattern in details["patterns"]:
                if pattern in hostname.lower():
                    detected.append({
                        "provider": provider,
                        "name": details["name"],
                        "type": details["type"],
                        "hostname": hostname,
                        "priority": priority
                    })
    
    return {
        "providers": detected,
        "multiple_providers": len(set(d["provider"] for d in detected)) > 1,
        "security_risk": _check_security_risk(detected)
    }

def _check_security_risk(detected_providers):
    """
    Check for security risks in mail provider configuration.
    
    Args:
        detected_providers (list): List of detected provider details
        
    Returns:
        dict: Security risk details if found
    """
    providers = set(d["provider"] for d in detected_providers)
    
    # Check for mixed security gateway and direct mail provider
    gateways = set(d["provider"] for d in detected_providers if d["type"] == "Security Gateway")
    providers = set(d["provider"] for d in detected_providers if d["type"] == "Mail Provider")
    
    if gateways and providers:
        return {
            "risk_level": "HIGH",
            "description": "Mixed mail security gateway and direct mail provider detected",
            "impact": "Potential security bypass of gateway filtering",
            "recommendation": "Remove direct mail provider MX records to ensure all mail flows through security gateway"
        }
    
    return None 