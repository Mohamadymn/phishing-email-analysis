# phishing-email-analysis

This project focuses on identifying phishing emails using two approaches:

**Rule-Based Detection** — Based on email headers, content patterns, and common phishing tactics  

## Project Structure
- data/ # Dataset files (excluded from GitHub, see download link)
- reports/ # Analysis summaries, result logs
- rules/ # Rule engine
- scripts/ # Rule-based detection 
- README.md

---

## Rules Used in Rule-Based Detection

| Rule | Description |
|------|-------------|
| `sender_receiver_mismatch` | Sender and recipient domains don't match |
| `suspicious_subject` | Subject has phishing keywords (e.g. "verify", "account", "click") |
| `has_url` | Email contains one or more URLs |
| `free_email_provider` | Sender uses free domain (e.g., Gmail, Yahoo) |
| `too_many_symbols` | Excessive use of repeated special characters (e.g. `!!!!`, `======`) |
| `body_misspellings` | Contains 10 or more misspelled words (validated by spellchecker) |
| `short_body` | Email body is very short |

Each email is assigned a **phishing score** based on how many of these flags it matches.

---

## Output Files (Reports)

| File | Description |
|------|-------------|
| `phishing_rule_summary.txt` | Flag counts by label and score distribution, top phishing misspellings, and top URLs in phishing emails |
| `common_phishing_words.txt` | Top phishing words used in the header of the email |
| `ceas_phishing_rules_report.csv` | Full dataset with all rule flags and scores (found through link)

---


## Dataset Information

The **CEAS 2008 phishing email dataset** was used, which contains labeled phishing and legitimate emails with sender, recipient, subject, body, and date metadata.

**Download the dataset here**:  
[Google Drive Link to Dataset](https://drive.google.com/drive/u/1/folders/1RyhtDAai02yBxr1T6UAiLTlIcd2ICnAb)

*Note: The dataset is excluded from this repository due to GitHub’s size limitations.*

---

## Tools Used

- Python 3.13
- `pandas` for data analysis
- `re` for email and URL parsing
- `pyspellchecker` for dictionary-based spell checking
- `Counter` for frequency analysis
- 'urlparse' for URL checking

---
