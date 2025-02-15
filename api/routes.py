from flask import Blueprint, request, jsonify, render_template
from api.utils import check_dns_records, check_blacklist_status, get_whois_info, get_registrar_info, get_nameserver_info
import socket
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial

api_bp = Blueprint('api', __name__)

# Route to serve the frontend
@api_bp.route('/')
def home():
    return render_template('index.html')

# Route to check email health (SPF, DKIM, DMARC, Blacklist, WHOIS)
@api_bp.route('/check-email-health', methods=['GET', 'POST'])
def check_email_health():
    if request.method == 'POST':
        domain_mode = request.form.get('domain-mode', 'single')
        
        if domain_mode == 'single':
            domain = request.form.get('domain')
            domains = [domain] if domain else []
        else:
            domains_str = request.form.get('domains', '')
            domains = [d.strip() for d in domains_str.split(',') if d.strip()]
    else:
        domain = request.args.get('domain')
        domains = [domain] if domain else []

    if not domains:
        return render_template("index.html", error="Domain parameter is required")

    if len(domains) > 5:  # Enforce 5 domain limit
        return render_template("index.html", error="Maximum 5 domains allowed")

    results = []
    for domain in domains:
        domain_result = {
            'domain': domain,
            'dns_results': check_dns_records(domain),
            'blacklist_results': check_blacklist_status(domain),
            'whois_info': get_whois_info(domain)
        }
        results.append(domain_result)

    return render_template("index.html", 
                         domain_mode=domain_mode,
                         results=results,
                         get_registrar_info=get_registrar_info,
                         get_nameserver_info=get_nameserver_info)

@api_bp.route('/email-config')
def email_config():
    return render_template('email_config.html')

@api_bp.route('/headers')
def headers():
    return render_template('headers.html')

@api_bp.route('/security')
def security():
    return render_template('security.html')

def test_port_with_banner(host, port, timeout=2):
    """Test if a port is open and collect banner if available."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            try:
                # Try to get banner
                banner = sock.recv(1024).decode().strip()
                return True, banner
            except:
                return True, None
    except:
        return False, None

@api_bp.route('/run-mail-tests', methods=['POST'])
def run_mail_tests():
    domain = request.form.get('domain')
    if not domain:
        return render_template('email_config.html', error="Domain is required")
    
    results = {
        'domain': domain,
        'port_25': {'open': False, 'banner': None},
        'port_465': {'open': False, 'banner': None},
        'port_587': {'open': False, 'banner': None},
        'mx_records': [],
        'ptr_record': False,
        'server_details': []
    }
    
    try:
        # Test MX records
        mx_records = dns.resolver.resolve(domain, 'MX')
        results['mx_records'] = [str(mx.exchange) for mx in mx_records]
        
        # Use a set to prevent duplicate server details
        seen_details = set()
        for mx in results['mx_records']:
            mx_host = str(mx).rstrip('.')
            
            # Test all ports
            for port in [25, 465, 587]:
                is_open, banner = test_port_with_banner(mx_host, port)
                port_key = f'port_{port}'
                
                if is_open:
                    results[port_key]['open'] = True
                    if banner:
                        results[port_key]['banner'] = banner
                        detail = f"Port {port}: {banner}"
                        if detail not in seen_details:  # Only add if not seen before
                            seen_details.add(detail)
                            results['server_details'].append(detail)
            
            # Check PTR record
            try:
                ptr = dns.resolver.resolve(dns.reversename.from_address(socket.gethostbyname(mx_host)), 'PTR')
                results['ptr_record'] = True
            except:
                pass

    except Exception as e:
        results['error'] = str(e)
    
    # Check if it's an AJAX request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return render_template('email_config_results.html', results=results)
    
    return render_template('email_config.html', results=results)

def get_smtp_info(host):
    """Get SMTP server information."""
    info = []
    try:
        with socket.create_connection((host, 25), timeout=2) as sock:
            banner = sock.recv(1024).decode()
            info.append(f"Server: {banner.strip()}")
            
            # Try EHLO
            sock.send(b'EHLO nixie.test\r\n')
            response = sock.recv(1024).decode()
            for line in response.split('\n'):
                if line.strip() and not line.startswith('2'):  # Only show capability lines
                    info.append(line.strip())
    except socket.timeout:
        info.append("Server not responding on port 25")
    except ConnectionRefused:
        info.append("Connection refused by server")
    except Exception as e:
        info.append("Unable to connect to mail server")
    
    # Only return server details if we got meaningful information
    return [detail for detail in info if "error" not in detail.lower()]

def check_ptr_record(host):
    """Check PTR record with timeout."""
    try:
        ptr = dns.resolver.resolve(dns.reversename.from_address(socket.gethostbyname(host)), 'PTR', lifetime=2)
        return True
    except:
        return False

def generate_recommendations(results):
    """Generate actionable recommendations based on test results."""
    recommendations = []
    
    if not results['mx_records']:
        recommendations.append({
            'severity': 'high',
            'message': 'No MX records found. Configure MX records to receive email.',
            'details': 'MX records are required for receiving email. Contact your DNS provider to set them up.'
        })
    
    if not any([results['port_25']['open'], results['port_465']['open'], results['port_587']['open']]):
        recommendations.append({
            'severity': 'high',
            'message': 'No SMTP ports are open. Configure at least one SMTP port.',
            'details': 'At minimum, port 25 (SMTP) or 587 (SMTP with TLS) should be open for email delivery.'
        })
    
    if not results['ptr_record']:
        recommendations.append({
            'severity': 'medium',
            'message': 'Missing PTR record. Configure reverse DNS.',
            'details': 'PTR records help prevent your emails from being marked as spam.'
        })
    
    return recommendations
