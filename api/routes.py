from flask import Blueprint, request, jsonify, render_template
from api.utils import check_dns_records, check_blacklist_status, get_whois_info, get_registrar_info, get_nameserver_info

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
