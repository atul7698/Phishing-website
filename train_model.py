import pandas as pd
import joblib
import os

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score
)


# ==========================================
# 1. LOAD DATASET
# ==========================================

DATASET_PATH = "Dataset/PhiUSIIL_Phishing_URL_Dataset.csv"

print("Loading dataset...")

df = pd.read_csv(DATASET_PATH)

print("Dataset loaded successfully.")
print("Dataset shape:", df.shape)


# ==========================================
# 2. SELECT URL AND LABEL
# ==========================================

df = df[["URL", "label"]].dropna()

df["URL"] = df["URL"].astype(str)

X = df["URL"]
y = df["label"]


print("\nClass distribution:")
print(y.value_counts())

print("\nLabel meaning:")
print("0 = Phishing")
print("1 = Legitimate")


# ==========================================
# 3. TRAIN / TEST SPLIT
# ==========================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))


# ==========================================
# 4. CONVERT URL INTO ML FEATURES
# ==========================================

print("\nCreating URL features...")

vectorizer = TfidfVectorizer(
    analyzer="char",
    ngram_range=(3, 5),
    max_features=50000,
    min_df=2,
    sublinear_tf=True
)

X_train_vectorized = vectorizer.fit_transform(X_train)

X_test_vectorized = vectorizer.transform(X_test)


print("URL feature extraction completed.")


# ==========================================
# 5. TRAIN MODEL
# ==========================================

print("\nTraining Logistic Regression...")

model = LogisticRegression(
    max_iter=1000,
    solver="liblinear"
)

model.fit(
    X_train_vectorized,
    y_train
)


# ==========================================
# 6. PREDICTION
# ==========================================

print("\nTesting model...")

y_pred = model.predict(
    X_test_vectorized
)


# ==========================================
# 7. PERFORMANCE
# ==========================================

accuracy = accuracy_score(
    y_test,
    y_pred
)

precision = precision_score(
    y_test,
    y_pred,
    zero_division=0
)

recall = recall_score(
    y_test,
    y_pred,
    zero_division=0
)

f1 = f1_score(
    y_test,
    y_pred,
    zero_division=0
)


print("\n===================================")
print("MODEL PERFORMANCE")
print("===================================")

print(
    "Accuracy :",
    round(accuracy * 100, 2),
    "%"
)

print(
    "Precision:",
    round(precision * 100, 2),
    "%"
)

print(
    "Recall   :",
    round(recall * 100, 2),
    "%"
)

print(
    "F1-Score :",
    round(f1 * 100, 2),
    "%"
)


# ==========================================
# 8. SAVE MODEL + VECTORIZER
# ==========================================

os.makedirs(
    "model",
    exist_ok=True
)

model_path = "model/phishing_model.pkl"

joblib.dump(
    {
        "model": model,
        "vectorizer": vectorizer
    },
    model_path
)


print("\n===================================")
print("MODEL SAVED SUCCESSFULLY")
print("===================================")

print(
    "Location:",
    model_path
)