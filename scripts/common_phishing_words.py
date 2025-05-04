import pandas as pd
from collections import Counter
import re
import argparse

def _extract_common_words(
    df: pd.DataFrame,
    label_column: str = 'label',
    text_column: str = 'subject',
    label_value: int = 1,
    top_n: int = 30
) -> list[tuple[str, int]]:
    subjects = df[df[label_column] == label_value][text_column].dropna().astype(str)
    FILLER_WORDS = {
        'the', 'to', 'in', 'for', 'of', 'a', 'and', 'is', 'at', 'on', 'this', 'that', 
        'with', 'be', 'by', 'it', 'from', 'as', 'an', 'or', 'are', 'your', 'my', 'you', 're'
    }
    words: list[str] = []
    for subj in subjects:
        subj = re.sub(r'[^a-zA-Z\s]', '', subj)
        words.extend([
            word for word in subj.lower().split()
            if word not in FILLER_WORDS and len(word) > 2
        ])
    return Counter(words).most_common(top_n)

def _save_word_report(input_path: str, output_path: str) -> None:
    df = pd.read_csv(input_path)
    top_words = _extract_common_words(df)
    with open(output_path, 'w') as f:
        f.write("Most Common Phishing Subject Words\n")
        f.write("==================================\n")
        for word, count in top_words:
            f.write(f"{word:15} {count}\n")
    print(f"Top phishing subject words written to {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract top common phishing words from email subjects.")
    parser.add_argument("--input", type=str, default="data/CEAS_08_cleaned.csv", help="Input CSV path")
    parser.add_argument("--output", type=str, default="reports/common_phishing_words.txt", help="Output report path")
    args = parser.parse_args()
    _save_word_report(input_path=args.input, output_path=args.output)