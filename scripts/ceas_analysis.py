import pandas as pd
import re
from spellchecker import SpellChecker
from collections import Counter

# Load CEAS dataset
data = pd.read_csv('data/CEAS_08_cleaned.csv')

spell = SpellChecker()

# Spellchecker allow list
CUSTOM_ALLOWLIST = {
    'usa', 'pythondev', 'contenttype', 'textplain',
    'zvlllneumpythonorg', 'smsbmopythonorg', 'url', 'messageid',
    'guido', 'etc', 'pgp', 'cnn', 'cnncom', 'edt', 'dont', 'ive',
    'doesnt', 'thats', 'youre', 'theres', 'didnt', 'havent', 'isnt', 'html',
    'smtp', 'pdf', 'youll', 'wasnt', 'api', 'barista', 'los', 'angeles', 'arent', 'youve',
    'todays', 'wouldnt', 'theyre', 'shouldnt', 'weve', 'couldnt', 'youd', 'gnulinux'
}

# List of free email domains
free_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'aol.com', 'outlook.com']
# shortners for urls
SHORTENERS = ['bit.ly', 'tinyurl.com', 'ow.ly', 't.co', 'goo.gl']

# Flag if sender and recipient domains mismatch
def domain_mismatch(sender, receiver):
    try:
        sender_domain = sender
        receiver_domain = receiver
        return sender_domain != receiver_domain
    except:
        return True

# Flag suspicious subject lines
def is_subject_suspicious(subject):
    keywords = ['urgent', 'verify', 'account', 'password', 'login', 'click', 'reset', 'invoice', 'top', 'daily', 'alert', 'alerts']
    return any(kw in subject.lower() for kw in keywords)

# Flag if Contains URL
def has_url_flag(val):
    return int(val) == 1 if pd.notna(val) else False

# Check Free Email Provider
def from_free_email(sender):
    try:
        domain = sender.split('@')[-1].lower()
        return domain in free_domains
    except:
        return False

# Check for shortened url
def body_has_shortened_url(body):
    if pd.isna(body): return False, []
    body = body.lower()
    urls = re.findall(r'http[s]?://\S+', body)
    shortened = [url for url in urls if any(short in url for short in SHORTENERS)]
    return len(shortened) > 0, shortened

# Check for unusual use of symbols
def too_many_symbols(body):
    if pd.isna(body): return False
    return sum(1 for c in body if c in '!@#$%^&*()+=') > 30

# Clean data for spelll check
def clean_text_for_spellcheck(text):
    text = str(text).lower()
    text = re.sub(r"http\S+", "", text)  # Remove URLs
    text = re.sub(r"[^\w\s]", "", text)  # Remove punctuation
    text = re.sub(r"\d+", "", text)      # Remove numbers
    words = text.split()
    # Filter out single letters or very short tokens
    return [word for word in words if len(word) > 2 and word.isalpha()]

# Check for misspelling in the body
def has_misspellings(body):
    if pd.isna(body): return False, []
    words = clean_text_for_spellcheck(body)
    filtered = [word for word in words if word not in CUSTOM_ALLOWLIST]
    misspelled = list(spell.unknown(filtered))
    return len(misspelled) >= 10, misspelled  # Threshold: 3 or more misspelled words

# Check if body is short
def short_body(body):
    if pd.isna(body): return False
    return len(str(body).strip()) < 30


# Apply flags
data['sender_receiver_mismatch'] = data.apply(lambda row: domain_mismatch(row['sender_name'], row['receiver_name']), axis=1)
data['suspicious_subject'] = data['subject'].fillna('').apply(is_subject_suspicious)
data['has_url'] = data['urls'].apply(has_url_flag)
data['free_email_provider'] = data['sender'].apply(from_free_email)
data[['body_has_shortened_url', 'shortened_urls']] = data['body'].apply(lambda x: pd.Series(body_has_shortened_url(x)))
data['too_many_symbols'] = data['body'].apply(too_many_symbols)
data[['body_misspellings', 'misspelled_words']] = data['body'].apply(lambda x: pd.Series(has_misspellings(x)))
data['short_body'] = data['body'].apply(short_body)

# Simple rule-based phishing score (0-4)
data['phishing_score'] = data[['sender_receiver_mismatch', 'suspicious_subject', 'has_url', 'free_email_provider', 'body_has_shortened_url', 'too_many_symbols', 'body_misspellings', 'short_body']].sum(axis=1)

# Count score distribution by label
score_summary = data.groupby(['label', 'phishing_score']).size().unstack(fill_value=0)

# Count rule hits by label
flag_summary = data.groupby('label')[['sender_receiver_mismatch', 'suspicious_subject', 'has_url', 'free_email_provider', 'body_has_shortened_url', 'too_many_symbols', 'body_misspellings', 'short_body']].sum()


# Combine all misspellings
misspell_phishing = data[data['label'] == 1]['misspelled_words'].explode().dropna()
misspell_normal = data[data['label'] == 0]['misspelled_words'].explode().dropna()

# Count misspelled word occurence
top_phish_misspellings = Counter(misspell_phishing).most_common(10)
top_normal_misspellings = Counter(misspell_normal).most_common(10)

# Extract shortened urls and count them
phishing_short_urls = data[data['label'] == 1]['shortened_urls'].explode().dropna()
short_url_counts = Counter(phishing_short_urls).most_common(15)

# Write results to report
with open('reports/phishing_rule_summary.txt', 'w') as f:
    f.write("Phishing Score Distribution by Label\n")
    f.write("======================================\n")
    f.write(score_summary.to_string())
    f.write("\n\nRule Hit Counts by Label (1 = matched)\n")
    f.write("========================================\n")
    f.write(flag_summary.to_string())
    f.write("\n Top Phishing Misspellings: \n")
    f.write("==========================================\n")
    for word, count in top_phish_misspellings:
        f.write(f"{word:10} {count}\n")
    f.write("\n Top Normal Misspellings: \n")
    f.write("==========================================\n")
    for word, count in top_normal_misspellings:
        f.write(f"{word:10} {count}\n")
    f.write("\n Top Shortened URLs in Phishing Emails\n")
    f.write("=============================================\n")
    for url, count in short_url_counts:
        f.write(f"{url:15} {count}\n")
# Save report
data.to_csv('reports/ceas_header_analysis.csv', index=False)
print("Header analysis report saved.")