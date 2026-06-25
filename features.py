import re

def extract_features(url):
    features = []
    
    # Feature 1: Length of URL (Phishing URLs are often long)
    features.append(len(url))
    
    # Feature 2: Count of dots (Phishing often uses subdomains like bank.login.secure.com)
    features.append(url.count('.'))
    
    # Feature 3: Presence of "@" symbol
    features.append(1 if "@" in url else 0)
    
    # Feature 4: Use of IP address instead of domain name
    ip_pattern = r'(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}'
    features.append(1 if re.search(ip_pattern, url) else 0)
    
    # Feature 5: Number of hyphens (Common in fake domains)
    features.append(url.count('-'))
    
    return features