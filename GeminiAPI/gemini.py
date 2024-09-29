import google.generativeai as genai
import os
import pandas as pd

# Configure the generative AI model with the API key
genai.configure(api_key=os.environ["AIzaSyC_0Gs_kC9DepUQ7bPrRVbRL4Y_auh2bJ0"])

# Load the whitelist and blacklist
def load_domains():
    good_domains = set()
    bad_domains = set()

    # Load good domains from whitelist_domains.txt
    with open("whitelist_domains.txt", "r") as f:
        for line in f:
            good_domains.add(line.strip())

    # Load bad domains from verified_online.csv
    bad_data = pd.read_csv("verified_online.csv")
    for domain in bad_data['domain']:  # Assume the CSV has a 'domain' column
        bad_domains.add(domain.strip())

    return good_domains, bad_domains

# Classify the URL based on the loaded domains
def classify_url(url, good_domains, bad_domains):
    if url in good_domains:
        return "Good"
    elif url in bad_domains:
        return "Bad"
    else:
        # Optionally use the generative model for further analysis
        model = genai.GenerativeModel(model_name="gemini-1.5-flash")
        response = model.generate_content(f"Classify the following URL: {url}")
        return response.text.strip()  # Assuming the response contains the classification

# Main execution
def main():
    good_domains, bad_domains = load_domains()
    
    # Example URL to classify
    url_to_classify = "example.com"  # Replace with the actual URL you want to classify
    classification = classify_url(url_to_classify, good_domains, bad_domains)
    print(f"The classification for {url_to_classify} is: {classification}")

if __name__ == "__main__":
    main()
