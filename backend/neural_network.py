import os
import sys

import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report
)

from feature_extractor import get_feature_vector
from ml_model import train_model


# ============================================================
# CONFIGURATION
# ============================================================

DATASET_PATH = "../data/phishing_urls.csv"


# ============================================================
# LOAD DATASET
# ============================================================

def load_dataset():
    print("\nLoading phishing URL dataset...")

    if not os.path.exists(DATASET_PATH):
        print(f"\nERROR: Dataset not found:")
        print(DATASET_PATH)
        print("\nPlace your CSV file inside the data folder.")
        sys.exit(1)

    df = pd.read_csv(DATASET_PATH)

    print(f"Dataset loaded successfully.")
    print(f"Total rows: {len(df)}")

    return df


# ============================================================
# PREPARE DATA
# ============================================================

def prepare_data(df):

    # --------------------------------------------------------
    # Check required columns
    # --------------------------------------------------------

    required_columns = ["url", "label"]

    missing_columns = [
        column
        for column in required_columns
        if column not in df.columns
    ]

    if missing_columns:
        print("\nERROR: Required columns are missing:")
        print(missing_columns)

        print("\nAvailable columns:")
        print(list(df.columns))

        sys.exit(1)

    # --------------------------------------------------------
    # Remove missing values
    # --------------------------------------------------------

    df = df[["url", "label"]].dropna()

    # --------------------------------------------------------
    # Convert labels
    # --------------------------------------------------------

    df["label"] = pd.to_numeric(
        df["label"],
        errors="coerce"
    )

    df = df.dropna(subset=["label"])

    # Keep only binary labels
    df = df[df["label"].isin([0, 1])]

    print(f"\nUsable rows: {len(df)}")

    print("\nClass distribution:")
    print(df["label"].value_counts())

    # --------------------------------------------------------
    # Feature extraction
    # --------------------------------------------------------

    print("\nExtracting URL features...")

    X = []
    y = []

    for index, row in df.iterrows():

        try:
            features = get_feature_vector(
                str(row["url"])
            )

            X.append(features)
            y.append(int(row["label"]))

        except Exception as error:

            print(
                f"Skipping row {index}: {error}"
            )

    X = np.array(X)
    y = np.array(y)

    print("\nFeature extraction completed.")

    print("Feature matrix shape:", X.shape)
    print("Label vector shape:", y.shape)

    return X, y


# ============================================================
# TRAINING
# ============================================================

def main():

    print("=" * 60)
    print("CYBERSENTINEL - NEURAL NETWORK TRAINING")
    print("=" * 60)

    # Load dataset
    df = load_dataset()

    # Prepare features
    X, y = prepare_data(df)

    # --------------------------------------------------------
    # Train/Test Split
    # --------------------------------------------------------

    print("\nSplitting dataset...")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    print(f"Training samples: {len(X_train)}")
    print(f"Testing samples:  {len(X_test)}")

    # --------------------------------------------------------
    # Train Neural Network
    # --------------------------------------------------------

    print("\nTraining neural network...")

    model = train_model(
        X_train,
        y_train
    )

    # --------------------------------------------------------
    # Evaluate
    # --------------------------------------------------------

    print("\nEvaluating model...")

    predictions = model.predict(X_test)

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    precision = precision_score(
        y_test,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0
    )

    print("\n" + "=" * 60)
    print("MODEL PERFORMANCE")
    print("=" * 60)

    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1 Score : {f1:.4f}")

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            predictions,
            target_names=[
                "Legitimate",
                "Phishing"
            ],
            zero_division=0
        )
    )

    print("=" * 60)
    print("TRAINING COMPLETE")
    print("=" * 60)


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    main()