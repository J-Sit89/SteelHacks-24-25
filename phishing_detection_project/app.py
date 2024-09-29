from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
from urllib.parse import urlparse
import re
pipeline = joblib.load('phishing_detection_pipeline.pkl')






# Initialize Flask app
app = Flask(__name__)
CORS(app)  
# Function to extract features from URL
def extract_url_features(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path
    query = parsed_url.query
    file_name = path.split('/')[-1] if path else ''
    
    # Helper function to check if a domain is an IP address
    def is_ip(domain):
        return bool(re.match(r"(\d{1,3}\.){3}\d{1,3}", domain))
    
    features = {
        'qty_dot_url': url.count('.'),
        'qty_hyphen_url': url.count('-'),
        'qty_underline_url': url.count('_'),
        'qty_slash_url': url.count('/'),
        'qty_questionmark_url': url.count('?'),
        'qty_equal_url': url.count('='),
        'qty_at_url': url.count('@'),
        'qty_and_url': url.count('&'),
        'qty_exclamation_url': url.count('!'),
        'qty_space_url': url.count(' '),
        'qty_tilde_url': url.count('~'),
        'qty_comma_url': url.count(','),
        'qty_plus_url': url.count('+'),
        'qty_asterisk_url': url.count('*'),
        'qty_hashtag_url': url.count('#'),
        'qty_dollar_url': url.count('$'),
        'qty_percent_url': url.count('%'),
        'qty_tld_url': sum([url.lower().count(tld) for tld in ['.com', '.net', '.org', '.edu']]),
        'length_url': len(url),
        'qty_dot_domain': domain.count('.'),
        'qty_hyphen_domain': domain.count('-'),
        'qty_underline_domain': domain.count('_'),
        'qty_slash_domain': domain.count('/'),
        'qty_questionmark_domain': domain.count('?'),
        'qty_equal_domain': domain.count('='),
        'qty_at_domain': domain.count('@'),
        'qty_and_domain': domain.count('&'),
        'qty_exclamation_domain': domain.count('!'),
        'qty_space_domain': domain.count(' '),
        'qty_tilde_domain': domain.count('~'),
        'qty_comma_domain': domain.count(','),
        'qty_plus_domain': domain.count('+'),
        'qty_asterisk_domain': domain.count('*'),
        'qty_hashtag_domain': domain.count('#'),
        'qty_dollar_domain': domain.count('$'),
        'qty_percent_domain': domain.count('%'),
        'qty_vowels_domain': sum(1 for char in domain if char in 'aeiou'),
        'domain_length': len(domain),
        'domain_in_ip': 1 if is_ip(domain) else 0,
        'server_client_domain': 0,  # Example placeholder, adjust logic if needed
        'qty_dot_directory': path.count('.'),
        'qty_hyphen_directory': path.count('-'),
        'qty_underline_directory': path.count('_'),
        'qty_slash_directory': path.count('/'),
        'qty_questionmark_directory': path.count('?'),
        'qty_equal_directory': path.count('='),
        'qty_at_directory': path.count('@'),
        'qty_and_directory': path.count('&'),
        'qty_exclamation_directory': path.count('!'),
        'qty_space_directory': path.count(' '),
        'qty_tilde_directory': path.count('~'),
        'qty_comma_directory': path.count(','),
        'qty_plus_directory': path.count('+'),
        'qty_asterisk_directory': path.count('*'),
        'qty_hashtag_directory': path.count('#'),
        'qty_dollar_directory': path.count('$'),
        'qty_percent_directory': path.count('%'),
        'directory_length': len(path),
        'qty_dot_file': file_name.count('.'),
        'qty_hyphen_file': file_name.count('-'),
        'qty_underline_file': file_name.count('_'),
        'qty_slash_file': file_name.count('/'),
        'qty_questionmark_file': file_name.count('?'),
        'qty_equal_file': file_name.count('='),
        'qty_at_file': file_name.count('@'),
        'qty_and_file': file_name.count('&'),
        'qty_exclamation_file': file_name.count('!'),
        'qty_space_file': file_name.count(' '),
        'qty_tilde_file': file_name.count('~'),
        'qty_comma_file': file_name.count(','),
        'qty_plus_file': file_name.count('+'),
        'qty_asterisk_file': file_name.count('*'),
        'qty_hashtag_file': file_name.count('#'),
        'qty_dollar_file': file_name.count('$'),
        'qty_percent_file': file_name.count('%'),
        'file_length': len(file_name),
        'qty_dot_params': query.count('.'),
        'qty_hyphen_params': query.count('-'),
        'qty_underline_params': query.count('_'),
        'qty_slash_params': query.count('/'),
        'qty_questionmark_params': query.count('?'),
        'qty_equal_params': query.count('='),
        'qty_at_params': query.count('@'),
        'qty_and_params': query.count('&'),
        'qty_exclamation_params': query.count('!'),
        'qty_space_params': query.count(' '),
        'qty_tilde_params': query.count('~'),
        'qty_comma_params': query.count(','),
        'qty_plus_params': query.count('+'),
        'qty_asterisk_params': query.count('*'),
        'qty_hashtag_params': query.count('#'),
        'qty_dollar_params': query.count('$'),
        'qty_percent_params': query.count('%'),
        'params_length': len(query),
        'tld_present_params': 1 if any(tld in url.lower() for tld in ['.com', '.net', '.org', '.edu']) else 0,
        'qty_params': query.count('='),
        'email_in_url': 1 if '@' in url else 0,
        'time_response': 0,  # Placeholder for real-time feature
        'domain_spf': 0,  # Placeholder for SPF feature
        'asn_ip': 0,  # Placeholder for ASN feature
        'time_domain_activation': 0,  # Placeholder for domain activation
        'time_domain_expiration': 0,  # Placeholder for domain expiration
        'qty_ip_resolved': 0,  # Placeholder for IP resolution count
        'qty_nameservers': 0,  # Placeholder for nameservers count
        'qty_mx_servers': 0,  # Placeholder for MX server count
        'ttl_hostname': 0,  # Placeholder for TTL hostname
        'tls_ssl_certificate': 0,  # Placeholder for TLS/SSL certificate
        'qty_redirects': 0,  # Placeholder for redirects count
        'url_google_index': 0,  # Placeholder for Google indexing
        'domain_google_index': 0,  # Placeholder for domain Google indexing
        'url_shortened': 1 if any(shortener in url for shortener in ['bit.ly', 'goo.gl', 'tinyurl']) else 0
    }
    
    return features
# Load whitelisted domains and URLs from files
def load_whitelist_domains():
    with open('whitelist_domains.txt', 'r') as file:
        domains = [line.strip() for line in file if line.strip()]
    return domains

def load_whitelist_urls():
    with open('whitelist_urls.txt', 'r') as file:
        urls = set(line.strip() for line in file if line.strip())
    return urls

# Load the whitelists
WHITELISTED_DOMAINS = load_whitelist_domains()
WHITELISTED_URLS = load_whitelist_urls()


def is_domain_whitelisted(domain):
    domain = domain.lower()
    for pattern in WHITELISTED_DOMAINS:
        # Handle wildcard patterns
        if pattern.startswith('*.'):
            # Remove '*.' from pattern to get the base domain
            base_domain = pattern[2:].lower()
            # Regex to match subdomains of the base domain
            regex_pattern = r'^([a-z0-9-]+\.)*' + re.escape(base_domain) + r'$'
        else:
            # Exact domain match
            base_domain = pattern.lower()
            regex_pattern = r'^' + re.escape(base_domain) + r'$'
        
        if re.match(regex_pattern, domain):
            return True
    return False

def is_url_whitelisted(url):
    return url in WHITELISTED_URLS

# Define the /analyze_link route for analyzing phishing links
@app.route('/analyze_link', methods=['POST'])
def analyze_link():
    data = request.json
    url = data.get('url')
    
    # Extract features from the URL
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    # Check if domain is whitelisted
    if is_domain_whitelisted(domain):
        # Return '0' indicating the link is safe
        return jsonify({'phishing': 0})
    
    # Proceed with feature extraction and prediction
    features = extract_url_features(url)
    features_df = pd.DataFrame([features])
    prediction = pipeline.predict(features_df)
    return jsonify({'phishing': int(prediction[0])})

if __name__ == '__main__':
    app.run()