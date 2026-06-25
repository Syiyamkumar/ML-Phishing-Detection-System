import pandas as pd
import pickle

# 1. Load the model and feature names
try:
    with open('phish_model.pkl', 'rb') as f:
        data = pickle.load(f)
        model = data['classifier']
        feature_names = data['features']
except FileNotFoundError:
    print("Error: Run train.py first!")
    exit()

# 2. Load the CSV to grab a test sample
df = pd.read_csv("C:\Phishing_Detection_System\dataset_phishing.csv")

# 3. Pick the first row (the crestonwood URL)
# We convert it to a DataFrame with proper column names to fix the Warning
sample_row_data = df.drop(['url', 'status'], axis=1).iloc[[0]] 
sample_url = df.iloc[0]['url']

# 4. Predict
prediction = model.predict(sample_row_data)

print(f"\nTesting URL: {sample_url}")
print("-" * 30)

if prediction[0] == 1:
    print("Result: ⚠️  PHISHING")
else:
    print("Result: ✅  LEGITIMATE")
print("-" * 30)