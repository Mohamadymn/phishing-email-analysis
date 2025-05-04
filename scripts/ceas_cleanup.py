import pandas as pd
import re
import argparse

def extract_name_email(full_info: str) -> tuple[str, str]:
    if pd.isna(full_info):
        return "John Doe", "unknown@example.com"
    match = re.match(r'(.*)<(.+?)>', full_info)
    if match:
        name = match.group(1).strip().strip('"') or "John Doe"
        email = match.group(2).strip()
    else:
        name = "John Doe"
        email = full_info.strip()
    return name, email

def clean_dataset(input_path: str, output_path: str) -> None:
    df = pd.read_csv(input_path)
    df[['sender_name', 'sender_email']] = df['sender'].apply(lambda x: pd.Series(extract_name_email(x)))
    df[['receiver_name', 'receiver_email']] = df['receiver'].apply(lambda x: pd.Series(extract_name_email(x)))
    df.to_csv(output_path, index=False)
    print(f"Cleaned data saved to {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Clean sender/receiver fields in CEAS data.")
    parser.add_argument("--input", type=str, default="data/CEAS_08.csv", help="Input CSV path")
    parser.add_argument("--output", type=str, default="data/CEAS_08_cleaned.csv", help="Output CSV path")
    args = parser.parse_args()
    clean_dataset(args.input, args.output)