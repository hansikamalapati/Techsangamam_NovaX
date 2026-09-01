import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


# ============================================================
# CYBERSENTINEL - MESSAGE NEURAL NETWORK
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATASET_PATH = os.path.join(
    BASE_DIR,
    "data",
    "message_dataset.csv"
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "models"
)

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "message_phishing_model.pkl"
)


# ============================================================
# CREATE NEURAL NETWORK
# ============================================================

def create_model():
    """
    Creates the message phishing detection pipeline.

    Architecture:

    Message
       ↓
    TF-IDF
       ↓
    128 neurons
       ↓
    64 neurons
       ↓
    32 neurons
       ↓
    Phishing / Legitimate
    """

    model = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                lowercase=True,
                ngram_range=(1, 2),
                max_features=5000,
                sublinear_tf=True
            )
        ),

        (
            "neural_network",
            MLPClassifier(
                hidden_layer_sizes=(128, 64, 32),
                activation="relu",
                solver="adam",
                max_iter=300,
                early_stopping=True,
                validation_fraction=0.2,
                random_state=42
            )
        )
    ])

    return model


# ============================================================
# LOAD DATASET
# ============================================================

def load_dataset():

    print("\n" + "=" * 60)
    print("CYBERSENTINEL - MESSAGE DATASET")
    print("=" * 60)

    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(
            f"\nMessage dataset not found:\n"
            f"{DATASET_PATH}\n\n"
            f"Expected location:\n"
            f"CyberSentinel/data/message_dataset.csv"
        )

    df = pd.read_csv(DATASET_PATH)

    print(f"\nDataset location: {DATASET_PATH}")
    print(f"Total messages : {len(df)}")
    print(f"Columns        : {list(df.columns)}")

    # Check required columns
    if "message" not in df.columns:
        raise ValueError(
            "Dataset must contain a 'message' column."
        )

    if "label" not in df.columns:
        raise ValueError(
            "Dataset must contain a 'label' column."
        )

    # Remove empty rows
    df = df.dropna(subset=["message", "label"])

    # Convert message to string
    df["message"] = df["message"].astype(str)

    # Convert labels to integer
    df["label"] = df["label"].astype(int)

    # Keep only valid labels
    df = df[df["label"].isin([0, 1])]

    print("\nLabel information:")

    legitimate = int((df["label"] == 0).sum())
    phishing = int((df["label"] == 1).sum())

    print(f"Legitimate messages : {legitimate}")
    print(f"Phishing messages   : {phishing}")
    print(f"Total valid samples : {len(df)}")

    return df


# ============================================================
# TRAIN MODEL
# ============================================================

def train_model():

    df = load_dataset()

    X = df["message"]
    y = df["label"]

    print("\n" + "=" * 60)
    print("SPLITTING DATASET")
    print("=" * 60)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    print(f"\nTraining messages: {len(X_train)}")
    print(f"Testing messages : {len(X_test)}")

    print("\n" + "=" * 60)
    print("CREATING MESSAGE NEURAL NETWORK")
    print("=" * 60)

    print("""
Architecture:

Message
   ↓
TF-IDF
   ↓
128 neurons
   ↓
64 neurons
   ↓
32 neurons
   ↓
Phishing / Legitimate
""")

    model = create_model()

    print("Training message neural network...")
    print("Please wait...")

    model.fit(X_train, y_train)

    print("\nTraining completed successfully.")

    # ========================================================
    # EVALUATION
    # ========================================================

    print("\n" + "=" * 60)
    print("MODEL EVALUATION")
    print("=" * 60)

    predictions = model.predict(X_test)

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    print(f"\nAccuracy: {accuracy * 100:.2f}%")

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

    print("Confusion Matrix:")

    print(
        confusion_matrix(
            y_test,
            predictions
        )
    )

    # ========================================================
    # SAVE MODEL
    # ========================================================

    os.makedirs(
        MODEL_DIR,
        exist_ok=True
    )

    joblib.dump(
        model,
        MODEL_PATH
    )

    print("\n" + "=" * 60)
    print("MODEL SAVING")
    print("=" * 60)

    print(f"\nMessage model saved to:")
    print(MODEL_PATH)

    return model


# ============================================================
# LOAD TRAINED MODEL
# ============================================================

def load_model():

    if not os.path.exists(MODEL_PATH):

        raise FileNotFoundError(
            "Message neural-network model not found.\n"
            "Please run:\n"
            "python message_model.py"
        )

    return joblib.load(MODEL_PATH)


# ============================================================
# PREDICT MESSAGE
# ============================================================

def predict_message(message: str):

    """
    Predicts whether a message is phishing or legitimate.

    Returns:

        prediction
        phishing_probability
        legitimate_probability
    """

    if not message or not message.strip():

        raise ValueError(
            "Message cannot be empty."
        )

    model = load_model()

    message = message.strip()

    # Prediction
    prediction = model.predict(
        [message]
    )[0]

    # Probability
    probabilities = model.predict_proba(
        [message]
    )[0]

    legitimate_probability = float(
        probabilities[0]
    )

    phishing_probability = float(
        probabilities[1]
    )

    return {

        "prediction": int(prediction),

        "phishing_probability":
            phishing_probability,

        "legitimate_probability":
            legitimate_probability
    }


# ============================================================
# TEST PREDICTIONS
# ============================================================

def test_predictions():

    print("\n" + "=" * 60)
    print("TESTING MESSAGE DETECTOR")
    print("=" * 60)

    test_messages = [

        "URGENT! Your bank account will be blocked. Verify your OTP immediately.",

        "Congratulations! You won a prize. Claim your reward now.",

        "Your appointment is confirmed for Monday.",

        "Please attend the project meeting at 10 AM."

    ]

    for message in test_messages:

        result = predict_message(message)

        if result["prediction"] == 1:
            verdict = "PHISHING"
        else:
            verdict = "LEGITIMATE"

        print("\nMessage:")
        print(message)

        print(f"Verdict: {verdict}")

        print(
            f"Phishing probability: "
            f"{result['phishing_probability'] * 100:.2f}%"
        )

        print(
            f"Legitimate probability: "
            f"{result['legitimate_probability'] * 100:.2f}%"
        )


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    print("\n")
    print("=" * 60)
    print("       CYBERSENTINEL MESSAGE AI")
    print("=" * 60)

    train_model()

    test_predictions()

    print("\n" + "=" * 60)
    print("       MESSAGE MODEL READY")
    print("=" * 60)

    print(
        "\nNext step:"
        "\nConnect predict_message() to FastAPI."
    )