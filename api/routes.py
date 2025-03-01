from flask import Blueprint, request, jsonify, render_template
from api.utils import check_dns_records, check_blacklist_status, get_whois_info, get_registrar_info, get_nameserver_info
import socket
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial
from api.security.headers import EmailHeaderAnalyzer

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

@api_bp.route('/headers', methods=['GET', 'POST'])
def headers():
    if request.method == 'POST':
        raw_headers = request.form.get('headers')
        if not raw_headers:
            return jsonify({'status': 'error', 'message': 'Email headers are required'})
        
        analyzer = EmailHeaderAnalyzer(raw_headers)
        results = analyzer.analyze()
        
        return render_template('headers.html', results=results)
    
    return render_template('headers.html')

@api_bp.route('/security')
def security():
    return render_template('security.html')

def test_port_with_banner(host, port, timeout=2):
    """Tests SMTP server connectivity and retrieves capability information"""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            try:
                # Set socket timeout for banner reading
                sock.settimeout(2)
                banner = sock.recv(1024).decode().strip()
                return True, banner
            except socket.timeout:
                return True, None
    except (socket.timeout, socket.error):
        return False, None

@api_bp.route('/run-mail-tests', methods=['POST'])
def run_mail_tests():
    domain = request.form.get('domain')
    if not domain:
        return render_template('email_config.html', error="Domain is required")
    
    # Set a shorter timeout for DNS resolver
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 4
    
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
    
    # Generate recommendations before returning
    recommendations = generate_recommendations(results)
    
    # Check if it's an AJAX request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return render_template('email_config_results.html', results=results, recommendations=recommendations)
    
    return render_template('email_config.html', results=results, recommendations=recommendations)

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
    """Analyzes test results and returns prioritized configuration fixes"""
    recommendations = []
    
    # MX Record Recommendations
    if not results['mx_records']:
        recommendations.append({
            'severity': 'critical',
            'issue': 'Missing MX Records',
            'impact': 'Emails cannot be delivered to your domain',
            'fix': 'Configure MX records with your email provider\'s mail servers'
        })

    # Port Configuration Recommendations
    port_recommendations = []
    if not results['port_25']['open'] and not results['port_587']['open']:
        port_recommendations.append({
            'severity': 'high',
            'issue': 'No SMTP ports available',
            'impact': 'Unable to send or receive emails',
            'fix': 'Open port 587 (recommended) or port 25 for SMTP traffic'
        })
    elif results['port_25']['open'] and not results['port_587']['open']:
        port_recommendations.append({
            'severity': 'medium',
            'issue': 'Using legacy SMTP port',
            'impact': 'Reduced email security',
            'fix': 'Configure and use port 587 with TLS instead of port 25'
        })

    # PTR Record Recommendations
    if not results['ptr_record']:
        recommendations.append({
            'severity': 'medium',
            'issue': 'Missing PTR Record',
            'impact': 'Emails may be marked as spam',
            'fix': 'Configure reverse DNS (PTR) records with your hosting provider'
        })

    recommendations.extend(port_recommendations)
    return recommendations
