from flask import Flask, render_template, request
import whois
import socket
import dns.resolver
import requests

app = Flask(__name__)

# VirusTotal API Key
API_KEY = '7c7063a8507b02c5a285b6142e1e4e0ca56ee373607251c40e31a10be8bf18d2'
# IPInfo API Key
IPINFO_API_KEY = 'c0ec2816fd3065'

def get_domain_info(domain_name):
    domain_info = whois.whois(domain_name)
    try:
        ip_address = socket.gethostbyname(domain_name)
        domain_info['ip_address'] = ip_address
    except socket.gaierror:
        domain_info['ip_address'] = None

    try:
        dns_records = dns.resolver.resolve(domain_name, 'A')
        domain_info['dns_records'] = [record.address for record in dns_records]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        domain_info['dns_records'] = None

    return domain_info

def get_location_and_virustotal_info(domain):
    result = {}
    try:
        ip_address = socket.gethostbyname(domain)
        ipinfo_url = f"http://ipinfo.io/{ip_address}/json?token={IPINFO_API_KEY}"
        response_ipinfo = requests.get(ipinfo_url)
        data_ipinfo = response_ipinfo.json()

        vt_url = f'https://www.virustotal.com/api/v3/domains/{domain}'
        headers = {'x-apikey': API_KEY}
        response_vt = requests.get(vt_url, headers=headers)
        data_vt = response_vt.json()

        if "error" in data_ipinfo:
            result['error'] = data_ipinfo['error']['message']
        else:
            result['domain_info'] = get_domain_info(domain)
            result['location_info'] = data_ipinfo
            result['virustotal_info'] = data_vt

    except (socket.gaierror, requests.exceptions.RequestException) as e:
        result['error'] = str(e)

    return result

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        domain = request.form['domain']
        data = get_location_and_virustotal_info(domain)
        return render_template('index.html', data=data, domain=domain)
    return render_template('index.html', data={}, domain=None)

if __name__ == '__main__':
    app.run(debug=True)
