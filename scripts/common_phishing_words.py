import pandas as pd
from collections import Counter
import re

# Load cleaned data
data = pd.read_csv('data/CEAS_08_cleaned.csv')

# Filter phishing emails
phish_subjects = data[data['label'] == 1]['subject'].dropna().astype(str).tolist()

# Tokenize and clean words
all_words = []
for subj in phish_subjects:
    subj = re.sub(r'[^a-zA-Z\s]', '', subj)  # remove punctuation
    words = subj.lower().split()
    all_words.extend(words)

# Count
top_words = Counter(all_words).most_common(30)

# Save or print
with open('reports/common_phishing_words.txt', 'w') as f:
    f.write(" Most commonly used phishing subject words\n")
    f.write("======================================\n")
    for word, count in top_words:
        f.write(f"{word:15} {count}\n")
print("\nTop 30 Most Common Words in Phishing Subjects:\n")
for word, count in top_words:
    print(f"{word:15} {count}")