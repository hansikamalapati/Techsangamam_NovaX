import os
import random
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix
)
from sklearn.utils.class_weight import compute_class_weight

from feature_extractor import (
    get_feature_vector,
    FEATURE_ORDER
)

from ml_model import (
    create_model,
    save_model
)


# ============================================================
# CYBERSENTINEL - URL MODEL TRAINING
# ============================================================

SEED = 42

random.seed(SEED)
np.random.seed(SEED)


# ============================================================
# PROJECT PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

DATASET_PATH = os.path.join(
    BASE_DIR,
    "data",
    "phishing_urls.csv"
)


# ============================================================
# MODEL SETTINGS
# ============================================================

TEST_SIZE = 0.20

FEATURE_COUNT = len(
    FEATURE_ORDER
)


# ============================================================
# LOAD DATASET
# ============================================================

def load_dataset():

    print("\n" + "=" * 70)
    print("CYBERSENTINEL - LOADING URL DATASET")
    print("=" * 70)

    if not os.path.exists(DATASET_PATH):

        raise FileNotFoundError(
            f"\nDataset not found:\n"
            f"{DATASET_PATH}\n\n"
            f"Expected location:\n"
            f"CyberSentinel/data/phishing_urls.csv"
        )

    df = pd.read_csv(
        DATASET_PATH
    )

    print(
        f"\nDataset location : "
        f"{DATASET_PATH}"
    )

    print(
        f"Total rows       : "
        f"{len(df)}"
    )

    print(
        f"Columns          : "
        f"{list(df.columns)}"
    )

    return df


# ============================================================
# FIND URL COLUMN
# ============================================================

def find_url_column(df):

    possible_columns = [
        "url",
        "URL",
        "Url",
        "link",
        "Link",
        "website",
        "Website"
    ]

    for column in possible_columns:

        if column in df.columns:

            return column

    raise ValueError(
        "\nCould not find URL column.\n"
        "Expected something like: url"
    )


# ============================================================
# FIND LABEL COLUMN
# ============================================================

def find_label_column(df):

    possible_columns = [
        "label",
        "Label",
        "class",
        "Class",
        "target",
        "Target",
        "result",
        "Result",
        "status",
        "Status"
    ]

    for column in possible_columns:

        if column in df.columns:

            return column

    raise ValueError(
        "\nCould not find label column.\n"
        "Expected something like: label"
    )


# ============================================================
# CONVERT LABEL TO 0 / 1
# ============================================================

def convert_label(label):

    # --------------------------------------------------------
    # Numeric labels
    # --------------------------------------------------------

    if isinstance(
        label,
        (
            int,
            float,
            np.integer,
            np.floating
        )
    ):

        if pd.isna(label):

            raise ValueError(
                "Empty label"
            )

        value = int(
            label
        )

        if value in [0, 1]:

            return value

    # --------------------------------------------------------
    # String labels
    # --------------------------------------------------------

    text = str(
        label
    ).strip().lower()

    phishing_labels = {
        "1",
        "phishing",
        "malicious",
        "malware",
        "bad",
        "fake",
        "fraud",
        "fraudulent",
        "unsafe",
        "suspicious",
        "attack",
        "scam"
    }

    legitimate_labels = {
        "0",
        "legitimate",
        "benign",
        "safe",
        "good",
        "normal",
        "clean"
    }

    if text in phishing_labels:

        return 1

    if text in legitimate_labels:

        return 0

    raise ValueError(
        f"Unknown label: '{label}'"
    )


# ============================================================
# SHOW FEATURE INFORMATION
# ============================================================

def show_feature_information():

    print("\n" + "=" * 70)

    print(
        f"CYBERSENTINEL - "
        f"{FEATURE_COUNT} URL SECURITY FEATURES"
    )

    print("=" * 70)

    for index, feature in enumerate(
        FEATURE_ORDER,
        start=1
    ):

        print(
            f"{index:02d}. {feature}"
        )

    print()

    print(
        "IMPORTANT:"
    )

    print(
        "The exact same feature order is used "
        "during training and prediction."
    )


# ============================================================
# PREPARE DATA
# ============================================================

def prepare_data(
    df,
    url_column,
    label_column
):

    print("\n" + "=" * 70)
    print("EXTRACTING URL SECURITY FEATURES")
    print("=" * 70)

    X = []
    y = []

    skipped = 0

    total = len(df)

    for position, (
        index,
        row
    ) in enumerate(
        df.iterrows(),
        start=1
    ):

        url = str(
            row[url_column]
        ).strip()

        # ----------------------------------------------------
        # Skip invalid URLs
        # ----------------------------------------------------

        if (
            not url
            or url.lower() == "nan"
            or url.lower() == "none"
        ):

            skipped += 1

            continue

        try:

            # ------------------------------------------------
            # URL → FEATURES
            # ------------------------------------------------

            features = get_feature_vector(
                url
            )

            # ------------------------------------------------
            # Validate feature count
            # ------------------------------------------------

            if len(features) != FEATURE_COUNT:

                raise ValueError(
                    f"Expected "
                    f"{FEATURE_COUNT} features, "
                    f"got {len(features)}"
                )

            # ------------------------------------------------
            # Validate numeric values
            # ------------------------------------------------

            features = np.asarray(
                features,
                dtype=np.float32
            )

            if not np.all(
                np.isfinite(features)
            ):

                raise ValueError(
                    "Feature vector contains "
                    "invalid numeric values."
                )

            # ------------------------------------------------
            # Convert label
            # ------------------------------------------------

            label = convert_label(
                row[label_column]
            )

            X.append(
                features
            )

            y.append(
                label
            )

        except Exception as error:

            skipped += 1

            print(
                f"Skipping row {index}: "
                f"{error}"
            )

        # ----------------------------------------------------
        # Progress
        # ----------------------------------------------------

        if position % 500 == 0:

            print(
                f"Processed "
                f"{position}/{total} rows..."
            )

    if len(X) == 0:

        raise ValueError(
            "No valid training samples found."
        )

    X = np.asarray(
        X,
        dtype=np.float32
    )

    y = np.asarray(
        y,
        dtype=np.int32
    )

    print(
        "\nFeature extraction completed."
    )

    print(
        f"Valid samples      : {len(X)}"
    )

    print(
        f"Skipped samples    : {skipped}"
    )

    print(
        f"Number of features : {X.shape[1]}"
    )

    return X, y


# ============================================================
# DATASET INFORMATION
# ============================================================

def show_dataset_information(y):

    print("\n" + "=" * 70)
    print("DATASET INFORMATION")
    print("=" * 70)

    legitimate = int(
        np.sum(
            y == 0
        )
    )

    phishing = int(
        np.sum(
            y == 1
        )
    )

    total = len(
        y
    )

    print(
        f"\nLegitimate URLs : "
        f"{legitimate}"
    )

    print(
        f"Phishing URLs   : "
        f"{phishing}"
    )

    print(
        f"Total samples   : "
        f"{total}"
    )

    if total > 0:

        print(
            f"\nLegitimate ratio : "
            f"{legitimate / total * 100:.2f}%"
        )

        print(
            f"Phishing ratio   : "
            f"{phishing / total * 100:.2f}%"
        )

    if legitimate == 0:

        raise ValueError(
            "No legitimate samples found."
        )

    if phishing == 0:

        raise ValueError(
            "No phishing samples found."
        )


# ============================================================
# CLASS WEIGHTS
# ============================================================

def calculate_class_weights(y):

    classes = np.unique(
        y
    )

    weights = compute_class_weight(
        class_weight="balanced",
        classes=classes,
        y=y
    )

    class_weights = {
        int(classes[i]):
        float(weights[i])

        for i in range(
            len(classes)
        )
    }

    print("\n" + "=" * 70)
    print("CLASS BALANCING")
    print("=" * 70)

    print(
        f"\nLegitimate weight : "
        f"{class_weights.get(0, 1.0):.4f}"
    )

    print(
        f"Phishing weight   : "
        f"{class_weights.get(1, 1.0):.4f}"
    )

    return class_weights


# ============================================================
# TRAIN NEURAL NETWORK
# ============================================================

def train_model(
    X_train,
    y_train,
    class_weights
):

    print("\n" + "=" * 70)
    print("CREATING CYBERSENTINEL URL NEURAL NETWORK")
    print("=" * 70)

    print("\nArchitecture:")
    print()

    print(
        f"{FEATURE_COUNT} URL Security Features"
    )

    print(
        "          ↓"
    )

    print(
        "      64 neurons"
    )

    print(
        "          ↓"
    )

    print(
        "      32 neurons"
    )

    print(
        "          ↓"
    )

    print(
        "      16 neurons"
    )

    print(
        "          ↓"
    )

    print(
        "Phishing / Legitimate"
    )

    print(
        "\nCreating model..."
    )

    model = create_model()

    print(
        "\nTraining model..."
    )

    print(
        "This uses scikit-learn MLPClassifier."
    )

    print(
        "No TensorFlow/Keras dependency is required."
    )

    print(
        "\nPlease wait...\n"
    )

    # --------------------------------------------------------
    # IMPORTANT
    #
    # create_model() returns a Pipeline containing:
    #
    # StandardScaler
    #       ↓
    # MLPClassifier
    #
    # Therefore we CANNOT pass:
    #
    # epochs
    # batch_size
    # validation_split
    #
    # directly to Pipeline.fit().
    #
    # --------------------------------------------------------

    # --------------------------------------------------------
    # Class weights
    #
    # MLPClassifier does not accept class_weight directly.
    # We therefore create sample weights.
    # --------------------------------------------------------

    sample_weights = np.array(
        [
            class_weights[
                int(label)
            ]

            for label in y_train
        ],
        dtype=np.float64
    )

    # --------------------------------------------------------
    # Fit model
    # --------------------------------------------------------

    try:

        # Newer sklearn versions support
        # step-specific fit parameters.

        model.fit(
            X_train,
            y_train,
            neural_network__sample_weight=sample_weights
        )

    except TypeError:

        # ----------------------------------------------------
        # Compatibility fallback.
        #
        # If this sklearn version does not allow
        # sample_weight for MLPClassifier, train normally.
        # The dataset is already balanced in this project.
        # ----------------------------------------------------

        print(
            "\nWarning:"
        )

        print(
            "This scikit-learn version does not "
            "support sample weights for MLPClassifier."
        )

        print(
            "Training without sample weights."
        )

        model.fit(
            X_train,
            y_train
        )

    print(
        "\nTraining completed successfully."
    )

    return model


# ============================================================
# EVALUATE MODEL
# ============================================================

def evaluate_model(
    model,
    X_test,
    y_test
):

    print("\n" + "=" * 70)
    print("CYBERSENTINEL MODEL EVALUATION")
    print("=" * 70)

    # --------------------------------------------------------
    # Predictions
    # --------------------------------------------------------

    predictions = model.predict(
        X_test
    )

    predictions = np.asarray(
        predictions
    ).astype(int)

    # --------------------------------------------------------
    # Probability
    # --------------------------------------------------------

    probabilities = model.predict_proba(
        X_test
    )

    phishing_probability = (
        probabilities[:, 1]
    )

    # --------------------------------------------------------
    # Metrics
    # --------------------------------------------------------

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

    try:

        roc_auc = roc_auc_score(
            y_test,
            phishing_probability
        )

    except ValueError:

        roc_auc = 0.0

    # --------------------------------------------------------
    # Display metrics
    # --------------------------------------------------------

    print(
        f"\nAccuracy  : "
        f"{accuracy * 100:.2f}%"
    )

    print(
        f"Precision : "
        f"{precision * 100:.2f}%"
    )

    print(
        f"Recall    : "
        f"{recall * 100:.2f}%"
    )

    print(
        f"F1 Score  : "
        f"{f1 * 100:.2f}%"
    )

    print(
        f"ROC-AUC   : "
        f"{roc_auc:.4f}"
    )

    # --------------------------------------------------------
    # Classification report
    # --------------------------------------------------------

    print(
        "\nClassification Report:"
    )

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

    # --------------------------------------------------------
    # Confusion matrix
    # --------------------------------------------------------

    print(
        "Confusion Matrix:"
    )

    matrix = confusion_matrix(
        y_test,
        predictions
    )

    print(
        matrix
    )

    # --------------------------------------------------------
    # Explain metrics
    # --------------------------------------------------------

    print(
        "\nMetric meaning:"
    )

    print(
        "Accuracy  = Overall correct predictions"
    )

    print(
        "Precision = How many detected phishing "
        "URLs were actually phishing"
    )

    print(
        "Recall    = How many phishing URLs "
        "were successfully detected"
    )

    print(
        "F1 Score  = Balance between precision "
        "and recall"
    )

    print(
        "ROC-AUC   = Overall separation ability "
        "of the classifier"
    )

    print(
        "\nThe test set contains URLs that were "
        "not used during model training."
    )

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "roc_auc": roc_auc
    }


# ============================================================
# TEST INDIVIDUAL URLS
# ============================================================

def test_sample_urls(model):

    print("\n" + "=" * 70)
    print("CYBERSENTINEL SAMPLE URL TEST")
    print("=" * 70)

    test_urls = [

        "https://www.google.com",

        "https://www.github.com",

        "https://www.tiktok.com",

        "https://tiktok2.com",

        "https://gooogle.com",

        "https://amaz0n.com",

        "https://secure-login-example.com/login",

        "http://192.168.1.10/login"

    ]

    for url in test_urls:

        try:

            features = get_feature_vector(
                url
            )

            features = np.asarray(
                features,
                dtype=np.float32
            ).reshape(
                1,
                -1
            )

            prediction = int(
                model.predict(
                    features
                )[0]
            )

            probabilities = (
                model.predict_proba(
                    features
                )[0]
            )

            legitimate_probability = float(
                probabilities[0]
            )

            phishing_probability = float(
                probabilities[1]
            )

            result = (
                "PHISHING"
                if prediction == 1
                else "LEGITIMATE"
            )

            print()
            print(
                f"URL: {url}"
            )

            print(
                f"Prediction: {result}"
            )

            print(
                f"Phishing probability: "
                f"{phishing_probability * 100:.2f}%"
            )

            print(
                f"Legitimate probability: "
                f"{legitimate_probability * 100:.2f}%"
            )

        except Exception as error:

            print()
            print(
                f"URL: {url}"
            )

            print(
                f"Testing failed: {error}"
            )


# ============================================================
# SAVE MODEL
# ============================================================

def save_trained_model(model):

    print("\n" + "=" * 70)
    print("SAVING CYBERSENTINEL MODEL")
    print("=" * 70)

    save_model(
        model
    )

    print(
        "\nTrained model saved successfully."
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print("\n")

    print("=" * 70)
    print(
        "        CYBERSENTINEL AI URL MODEL TRAINING"
    )
    print("=" * 70)

    print()

    print(
        "Purpose:"
    )

    print(
        "Train a machine-learning neural network "
        "to distinguish legitimate and phishing URLs."
    )

    print()

    print(
        "Important:"
    )

    print(
        "The model does NOT contain hardcoded "
        "decisions for individual websites."
    )

    print(
        "It learns patterns from the training dataset."
    )

    # --------------------------------------------------------
    # 1. Feature information
    # --------------------------------------------------------

    show_feature_information()

    # --------------------------------------------------------
    # 2. Dataset
    # --------------------------------------------------------

    df = load_dataset()

    # --------------------------------------------------------
    # 3. Columns
    # --------------------------------------------------------

    url_column = find_url_column(
        df
    )

    label_column = find_label_column(
        df
    )

    print(
        f"\nURL column   : "
        f"{url_column}"
    )

    print(
        f"Label column : "
        f"{label_column}"
    )

    # --------------------------------------------------------
    # 4. Feature extraction
    # --------------------------------------------------------

    X, y = prepare_data(
        df,
        url_column,
        label_column
    )

    # --------------------------------------------------------
    # 5. Dataset information
    # --------------------------------------------------------

    show_dataset_information(
        y
    )

    # --------------------------------------------------------
    # 6. Class weights
    # --------------------------------------------------------

    class_weights = calculate_class_weights(
        y
    )

    # --------------------------------------------------------
    # 7. Train/test split
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("SPLITTING DATASET")
    print("=" * 70)

    X_train, X_test, y_train, y_test = (
        train_test_split(
            X,
            y,
            test_size=TEST_SIZE,
            random_state=SEED,
            stratify=y
        )
    )

    print(
        f"\nTraining samples : "
        f"{len(X_train)}"
    )

    print(
        f"Testing samples  : "
        f"{len(X_test)}"
    )

    # --------------------------------------------------------
    # Verify dimensions
    # --------------------------------------------------------

    print(
        f"\nTraining feature shape: "
        f"{X_train.shape}"
    )

    print(
        f"Testing feature shape : "
        f"{X_test.shape}"
    )

    # --------------------------------------------------------
    # 8. Train
    # --------------------------------------------------------

    model = train_model(
        X_train,
        y_train,
        class_weights
    )

    # --------------------------------------------------------
    # 9. Evaluate
    # --------------------------------------------------------

    metrics = evaluate_model(
        model,
        X_test,
        y_test
    )

    # --------------------------------------------------------
    # 10. Save
    # --------------------------------------------------------

    save_trained_model(
        model
    )

    # --------------------------------------------------------
    # 11. Sample tests
    # --------------------------------------------------------

    test_sample_urls(
        model
    )

    # --------------------------------------------------------
    # Final report
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print(
        "        CYBERSENTINEL MODEL READY"
    )
    print("=" * 70)

    print()

    print(
        f"Features used : "
        f"{FEATURE_COUNT}"
    )

    print(
        f"Accuracy      : "
        f"{metrics['accuracy'] * 100:.2f}%"
    )

    print(
        f"Precision     : "
        f"{metrics['precision'] * 100:.2f}%"
    )

    print(
        f"Recall        : "
        f"{metrics['recall'] * 100:.2f}%"
    )

    print(
        f"F1 Score      : "
        f"{metrics['f1'] * 100:.2f}%"
    )

    print(
        f"ROC-AUC       : "
        f"{metrics['roc_auc']:.4f}"
    )

    print()

    print(
        "Model saved and ready for prediction."
    )

    print()

    print(
        "Next step:"
    )

    print(
        "Update ml_model.py to use the new model."
    )

    print()


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()