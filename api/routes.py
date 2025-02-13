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
        domain = request.form.get('domain')
    else:
        domain = request.args.get('domain')

    if not domain:
        return render_template("index.html", error="Domain parameter is required")

    dns_results = check_dns_records(domain)
    blacklist_results = check_blacklist_status(domain)
    whois_info = get_whois_info(domain)

    return render_template("index.html", 
                           domain=domain, 
                           dns_results=dns_results, 
                           blacklist_results=blacklist_results, 
                           whois_info=whois_info,
                           get_registrar_info=get_registrar_info,
                           get_nameserver_info=get_nameserver_info)
