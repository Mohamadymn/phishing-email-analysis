import pandas as pd
import re

# Load dataset
data = pd.read_csv('data/CEAS_08.csv')

# Parse function
def extract_name_email(full_info):
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

# Apply to sender
data[['sender_name', 'sender_email']] = data['sender'].apply(
    lambda x: pd.Series(extract_name_email(x)))

# Apply to recipient
data[['receiver_name', 'receiver_email']] = data['receiver'].apply(
    lambda x: pd.Series(extract_name_email(x)))

# Save cleaned file
data.to_csv('data/CEAS_08_cleaned.csv', index=False)
print("Cleaned sender/recipient info saved to data/CEAS_08_cleaned.csv")