import pandas as pd
import re
from collections import Counter
from spellchecker import SpellChecker
from typing import Tuple, List

class PhishingRuleEngine:
    def __init__(self, allowlist: set, free_domains: list, keywords: list):
        self.spell = SpellChecker()
        self.allowlist = allowlist
        self.free_domains = free_domains
        self.keywords = keywords

    def _domain_mismatch(self, sender: str, receiver: str) -> bool:
        try:
            return sender.split('@')[-1] != receiver.split('@')[-1]
        except:
            return False

    def _is_subject_suspicious(self, subject: str) -> bool:
        return any(kw in subject.lower() for kw in self.keywords)

    def _has_url_flag(self, val) -> bool:
        return int(val) == 1 if pd.notna(val) else False

    def _from_free_email(self, sender: str) -> bool:
        try:
            domain = sender.split('@')[-1].lower()
            return domain in self.free_domains
        except:
            return False

    def _too_many_symbols(self, body: str) -> bool:
        if pd.isna(body): return False
        return bool(re.search(r'[^a-zA-Z0-9\s]{8,}', body))

    def _clean_text(self, text: str) -> List[str]:
        text = re.sub(r"http\S+|[^\w\s]|\d+", "", str(text).lower())
        return [w for w in text.split() if len(w) > 2 and w.isalpha()]

    def _has_misspellings(self, body: str) -> Tuple[bool, List[str]]:
        if pd.isna(body): return False, []
        words = [w for w in self._clean_text(body) if w not in self.allowlist]
        misspelled = list(self.spell.unknown(words))
        return len(misspelled) >= 10, misspelled

    def _short_body(self, body: str) -> bool:
        return pd.notna(body) and len(str(body).strip()) < 30

    def apply_rules(self, df: pd.DataFrame) -> pd.DataFrame:
        df['sender_receiver_mismatch'] = df.apply(lambda r: self._domain_mismatch(r['sender_name'], r['receiver_name']), axis=1)
        df['suspicious_subject'] = df['subject'].fillna('').apply(self._is_subject_suspicious)
        df['has_url'] = df['urls'].apply(self._has_url_flag)
        df['free_email_provider'] = df['sender'].apply(self._from_free_email)
        df['too_many_symbols'] = df['body'].apply(self._too_many_symbols)
        df[['body_misspellings', 'misspelled_words']] = df['body'].apply(lambda x: pd.Series(self._has_misspellings(x)))
        df['short_body'] = df['body'].apply(self._short_body)
        df['phishing_score'] = df[[
            'sender_receiver_mismatch', 'suspicious_subject', 'has_url', 'free_email_provider',
             'too_many_symbols', 'body_misspellings', 'short_body'
        ]].sum(axis=1)
        return df