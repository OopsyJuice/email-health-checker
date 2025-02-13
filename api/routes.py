from flask import Blueprint, request, jsonify, render_template
from api.utils import check_dns_records, check_blacklist_status

api_bp = Blueprint('api', __name__)

@api_bp.route('/')
def home():
    return render_template('index.html')

@api_bp.route('/check-email-health', methods=['GET', 'POST'])
def check_email_health():
    if request.method == 'POST':
        domain = request.form.get('domain')
        if not domain:
            return render_template('index.html', error="Please enter a domain")

        dns_results = check_dns_records(domain)
        blacklist_results = check_blacklist_status(domain)

        return render_template('index.html', domain=domain, dns_results=dns_results, blacklist_results=blacklist_results)

    return jsonify({"error": "Use POST request to check domain health"}), 400
