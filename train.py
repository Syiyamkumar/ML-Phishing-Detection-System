import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# 1. Load your dataset
df = pd.read_csv("C:\Phishing_Detection_System\dataset_phishing.csv")
# 2. Data Cleaning - Explicitly map the status
# 0 = Safe, 1 = Phishing
df['target'] = df['status'].map({'legitimate': 0, 'phishing': 1})

# Define Features (X) and Target (y)
X = df.drop(['url', 'status', 'target'], axis=1)
y = df['target']

# 3. Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 4. Train the Model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# 5. Save the model AND the feature names (to fix the Warning later)
model_data = {
    'classifier': model,
    'features': X.columns.tolist()
}

with open('phish_model.pkl', 'wb') as f:
    pickle.dump(model_data, f)

print(f"Model trained! Accuracy: {model.score(X_test, y_test)*100:.2f}%")