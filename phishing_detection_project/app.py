import google.generativeai as genai
import os
from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
from urllib.parse import urlparse
import re

# Initialize Flask app
app = Flask(__name__)
CORS(app)
# Rate limiter cache to store checked domains
cache = {}

# Load the phishing detection pipeline model
pipeline = joblib.load('phishing_detection_pipeline.pkl')

# Configure the Gemini API with the provided API key
genai.configure(api_key="AIzaSyC_0Gs_kC9DepUQ7bPrRVbRL4Y_auh2bJ0")

# Initialize Gemini model
gemini_model = genai.GenerativeModel(model_name="gemini-1.5-flash")
model = genai.GenerativeModel(model_name="gemini-1.5-flash")
# Generate content
try:
    response = model.generate_content("What is the meaning of life?")
    print(response.text)
except Exception as e:
    print(f"Error calling Gemini API: {e}")

# Function to extract features from the URL
def extract_url_features(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    path = parsed_url.path
    query = parsed_url.query
    file_name = path.split('/')[-1] if path else ''
    
    # Helper function to check if a domain is an IP address
    def is_ip(domain):
        return bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", domain))
    


# Load whitelisted domains and URLs from files
def load_whitelist_domains():
    with open('whitelist_domains.txt', 'r') as file:
        domains = []
        for line in file:
            line = line.strip()
            if line and not line.startswith('#'):
                domains.append(line)
    return domains

def load_whitelist_urls():
    with open('whitelist_urls.txt', 'r') as file:
        urls = set(line.strip() for line in file if line.strip())
    return urls

# Load the whitelists
WHITELISTED_DOMAINS = load_whitelist_domains()
print(f"Loaded whitelisted domains: {WHITELISTED_DOMAINS}")
WHITELISTED_URLS = load_whitelist_urls()
print(f"Loaded whitelisted URLs: {WHITELISTED_URLS}")

def is_domain_whitelisted(domain):
    domain = domain.lower()
    print(f"Checking if domain '{domain}' is whitelisted.")
    for pattern in WHITELISTED_DOMAINS:
        # Normalize the base domain by removing any leading '*.' and converting to lowercase
        base_domain = pattern.lstrip('*.').lower()
        # Check for exact match or subdomain match
        if domain == base_domain or domain.endswith('.' + base_domain):
            print(f"Domain '{domain}' matched with whitelist pattern '{pattern}'")
            return True
    print(f"Domain '{domain}' is NOT whitelisted.")
    return False

def is_url_whitelisted(url):
    return url in WHITELISTED_URLS

# Function to extract features from URL
def extract_url_features(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    path = parsed_url.path
    query = parsed_url.query
    file_name = path.split('/')[-1] if path else ''
    
    # Helper function to check if a domain is an IP address
    def is_ip(domain):
        return bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", domain))
    
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

# Function to limit API calls for known safe URLs
def check_cache(url):
    domain = urlparse(url).netloc.lower()
    if domain in cache:
        return cache[domain]
    return None

# Function to add a URL/domain to cache
def add_to_cache(url, gemini_analysis):
    domain = urlparse(url).netloc.lower()
    cache[domain] = gemini_analysis

@app.route('/analyze_link', methods=['POST'])
def analyze_link():
    data = request.json
    url = data.get('url')

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    # Check the cache first to avoid redundant Gemini API calls
    cached_result = check_cache(url)
    if cached_result:
        print(f"Returning cached result for domain: {url}")
        return jsonify({
            'phishing': 1,
            'gemini_analysis': cached_result
        })

    # Parse the URL to get the domain
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()

    # Initialize default values for the results
    phishing_prediction = 1
    gemini_analysis = "No analysis provided by Gemini."

    try:
        # Log for debugging
        print(f"Received URL: {url}")
        
        # Extract features for the phishing model
        features = extract_url_features(url)
        features_df = pd.DataFrame([features])
        phishing_prediction = pipeline.predict(features_df)
        phishing_prediction = int(phishing_prediction[0])

        # Log the phishing prediction result
        print(f"Phishing model prediction: {phishing_prediction}")

        # If the model predicts phishing, use Gemini to provide further analysis
        if phishing_prediction == 1:
            print(f"Calling Gemini API for further analysis of URL: {url}")
            prompt = (f"Here is a list of trusted domains: {', '.join(WHITELISTED_DOMAINS)}. "
                      f"Determine if the following URL is a phishing link: {url}.")
            response = model.generate_content(prompt)
            gemini_analysis = response.text
            print(f"Gemini analysis: {gemini_analysis}")

            # Cache the result
            add_to_cache(url, gemini_analysis)
        else:
            gemini_analysis = "The URL seems safe based on the model prediction."
            print(f"URL is considered safe based on model prediction.")
            
    except Exception as e:
        print(f"Error during processing: {e}")
        gemini_analysis = "Error in generating Gemini analysis."

    # Return both phishing prediction and Gemini analysis
    return jsonify({
        'phishing': phishing_prediction,
        'gemini_analysis': gemini_analysis
    })

# Define the /check_link route for the web interface
@app.route('/check_link', methods=['POST'])
def check_link():
    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    # Proceed with feature extraction and phishing model prediction
    features = extract_url_features(url)
    features_df = pd.DataFrame([features])
    prediction = pipeline.predict(features_df)
    phishing_prediction = int(prediction[0])

    # If the model predicts phishing (1), use Gemini to provide further analysis
    if phishing_prediction == 1:
        response = gemini_model.generate_content(f"Provide a detailed analysis on why this URL might be a phishing link: {url}")
        gemini_analysis = response.text
    else:
        gemini_analysis = "The URL seems safe based on the model prediction."

    # Return the phishing prediction and Gemini analysis as JSON
    return jsonify({
        'phishing': phishing_prediction,
        'gemini_analysis': gemini_analysis
    })


if __name__ == '__main__':
    app.run()
