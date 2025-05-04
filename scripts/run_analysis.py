import pandas as pd
import os
import sys
import re
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from rules.rule_engine import PhishingRuleEngine
from collections import Counter
from urllib.parse import urlparse

# Engine variables
ALLOWLIST = {
    'usa', 'pythondev', 'contenttype', 'textplain', 'zvlllneumpythonorg',
    'smsbmopythonorg', 'url', 'messageid', 'guido', 'etc', 'pgp', 'cnn', 'cnncom', 'edt',
    'dont', 'ive', 'doesnt', 'thats', 'youre', 'theres', 'didnt', 'havent', 'isnt', 'html',
    'smtp', 'pdf', 'youll', 'wasnt', 'api', 'barista', 'los', 'angeles', 'arent', 'youve',
    'todays', 'wouldnt', 'theyre', 'shouldnt', 'weve', 'couldnt', 'youd', 'gnulinux'
}
FREE_DOMAINS = [
    'gmail.com', 'yahoo.com', 'hotmail.com', 'aol.com', 'outlook.com'
]

KEYWORDS = [
    'urgent', 'verify', 'account', 'password', 'login', 'click', 'reset', 'invoice',
     'top', 'daily', 'alert', 'alerts'
]

# Load cleaned dataset
data = pd.read_csv("data/CEAS_08_cleaned.csv")

# Run Rule Engine
engine = PhishingRuleEngine(ALLOWLIST, FREE_DOMAINS, KEYWORDS)
data_analyzed = engine.apply_rules(data)

# Save CSV output
data_analyzed.to_csv("reports/ceas_header_analysis.csv", index=False)

# Summary Reports
score_summary = data_analyzed.groupby(['label', 'phishing_score']).size().unstack(fill_value=0)
flag_summary = data_analyzed.groupby('label')[
    ['sender_receiver_mismatch', 'suspicious_subject', 'has_url', 'free_email_provider',
      'too_many_symbols', 'body_misspellings', 'short_body']
].sum()

misspell_phish = data_analyzed[data_analyzed['label'] == 1]['misspelled_words'].explode().dropna()
misspell_normal = data_analyzed[data_analyzed['label'] == 0]['misspelled_words'].explode().dropna()
top_phish_misspellings = Counter(misspell_phish).most_common(10)
top_normal_misspellings = Counter(misspell_normal).most_common(10)

def extract_url_domains(df: pd.DataFrame, label_value: int = 1) -> list[tuple[str, int]]:
    phishing_bodies = df[df['label'] == label_value]['body'].dropna().astype(str)
    url_pattern = re.compile(r'http[s]?://\S+')

    domains = []
    for body in phishing_bodies:
        urls = url_pattern.findall(body)
        for url in urls:
            try:
                domain = urlparse(url).netloc
                domains.append(domain)
            except Exception:
                continue  # Skip malformed ones

    return Counter(domains).most_common(20)

common_url_domains = extract_url_domains(data)

# Write to summary
with open('reports/phishing_rule_summary.txt', 'w') as f:
    f.write("Phishing Score Distribution by Label\n")
    f.write(score_summary.to_string())
    f.write("\n\nRule Hit Counts by Label\n")
    f.write(flag_summary.to_string())
    f.write("\n\nTop Phishing Misspellings:\n")
    for word, count in top_phish_misspellings:
        f.write(f"{word:10} {count}\n")
    f.write("\nTop Normal Misspellings:\n")
    for word, count in top_normal_misspellings:
        f.write(f"{word:10} {count}\n")
    f.write("\nTop URL Domains in Phishing Emails\n")
    for domain, count in common_url_domains:
        f.write(f"{domain:25} {count}\n")

print("Run complete. Outputs written to 'reports/'")