import math
import re
from urllib.parse import urlparse
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", 
    "banking", "confirm", "signin", "paypal", "support"
]

def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy to detect randomly generated domains."""
    if not text:
        return 0.0
    probabilities = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in probabilities)

def extract_features(url: str) -> dict:
    """Extracts numerical lexical and structural features from a URL."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    hostname = parsed.netloc
    path = parsed.path

    # Check if hostname is an IPv4 address
    has_ip = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0

    return {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "at_symbol_count": url.count("@"),
        "question_count": url.count("?"),
        "equal_count": url.count("="),
        "digit_count": sum(c.isdigit() for c in url),
        "is_https": 1 if parsed.scheme == "https" else 0,
        "has_ip": has_ip,
        "hostname_entropy": calculate_entropy(hostname),
        "suspicious_word_count": sum(word in url.lower() for word in SUSPICIOUS_KEYWORDS),
    }

def main():
    # Sample dataset (0 = Benign, 1 = Phishing)
    # Replace with a full dataset (e.g., PhishTank + Tranco top domains) for production
    data = [
        ("https://www.google.com", 0),
        ("https://github.com/Techmo29/Cyber-Tools", 0),
        ("https://docs.python.org/3/library/urllib.parse.html", 0),
        ("https://www.wikipedia.org/wiki/Machine_learning", 0),
        ("https://stackoverflow.com/questions/tagged/python", 0),
        ("http://192.168.1.45/login/verify-account.php", 1),
        ("http://secure-paypal-update.com.verify-user.xyz/signin", 1),
        ("http://account-security-alert.tk/confirm?user=89412", 1),
        ("https://login-microsoft-online-auth.top/update", 1),
        ("http://banking-verify-id@evil-domain.com/login", 1),
    ]

    df = pd.DataFrame(data, columns=["url", "label"])
    
    # Convert URLs into a feature matrix
    features_df = pd.DataFrame([extract_features(u) for u in df["url"]])
    X = features_df
    y = df["label"]

    # Split and train Random Forest model
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42
    )
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # Evaluate
    predictions = model.predict(X_test)
    print("--- Model Evaluation ---")
    print(classification_report(y_test, predictions, zero_division=0))

    # Test on unseen URLs
    test_urls = [
        "https://www.amazon.com/gp/css/homepage.html",
        "http://paypal-secure-login-verify-9921.xyz/auth"
    ]
    print("--- Live Predictions ---")
    for test_url in test_urls:
        feat = pd.DataFrame([extract_features(test_url)])
        pred = model.predict(feat)[0]
        prob = model.predict_proba(feat)[0][1]
        status = "PHISHING" if pred == 1 else "SAFE"
        print(f"[{status} | Risk: {prob:.2%}] -> {test_url}")

if __name__ == "__main__":
    main()
