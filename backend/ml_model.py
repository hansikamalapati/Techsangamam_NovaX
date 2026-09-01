import os
import joblib
import numpy as np

from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

from feature_extractor import (
    get_feature_vector,
    FEATURE_ORDER
)


# ============================================================
# CYBERSENTINEL URL MODEL
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "models"
)

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "url_phishing_model.pkl"
)


# ============================================================
# MODEL CONFIGURATION
# ============================================================

# Automatically use the feature count from feature_extractor.py.
# This prevents training/prediction mismatch.

FEATURE_COUNT = len(
    FEATURE_ORDER
)

PHISHING_CLASS = 1
LEGITIMATE_CLASS = 0


# ============================================================
# CREATE NEURAL NETWORK
# ============================================================

def create_model():

    """
    Creates the CyberSentinel URL phishing
    detection neural network.

    Architecture:

        51 input features
              ↓
          64 neurons
              ↓
          32 neurons
              ↓
          16 neurons
              ↓
       Legitimate / Phishing
    """

    model = Pipeline([

        (
            "scaler",
            StandardScaler()
        ),

        (
            "neural_network",

            MLPClassifier(

                hidden_layer_sizes=(
                    64,
                    32,
                    16
                ),

                activation="relu",

                solver="adam",

                max_iter=500,

                random_state=42,

                early_stopping=True,

                validation_fraction=0.20,

                n_iter_no_change=10,

                learning_rate="adaptive",

                verbose=False
            )
        )
    ])

    return model


# ============================================================
# VALIDATE FEATURE VECTOR
# ============================================================

def validate_features(features):

    """
    Makes sure the URL feature vector contains
    exactly the same number of features used by
    the current feature extractor.
    """

    if len(features) != FEATURE_COUNT:

        raise ValueError(

            f"CyberSentinel expected "
            f"{FEATURE_COUNT} URL features, "

            f"but received "
            f"{len(features)}."
        )

    return features


# ============================================================
# TRAIN MODEL
# ============================================================

def train_model(X, y):

    """
    Trains the CyberSentinel URL neural network.

    X:
        URL feature matrix

    y:
        0 = legitimate
        1 = phishing
    """

    print(
        "\nCyberSentinel URL Neural Network"
    )

    print(
        f"Architecture: "
        f"{FEATURE_COUNT} → 64 → 32 → 16 → 2"
    )

    print(
        f"Training samples: {len(X)}"
    )

    # --------------------------------------------------------
    # Validate training matrix
    # --------------------------------------------------------

    X = np.asarray(
        X,
        dtype=np.float32
    )

    y = np.asarray(
        y,
        dtype=np.int32
    )

    if X.ndim != 2:

        raise ValueError(
            "Training feature matrix must "
            "be two-dimensional."
        )

    if X.shape[1] != FEATURE_COUNT:

        raise ValueError(

            f"Training data contains "
            f"{X.shape[1]} features, "

            f"but CyberSentinel expects "
            f"{FEATURE_COUNT}."
        )

    # --------------------------------------------------------
    # Create model
    # --------------------------------------------------------

    model = create_model()

    print(
        "\nTraining CyberSentinel "
        "neural network..."
    )

    # --------------------------------------------------------
    # Train
    # --------------------------------------------------------

    model.fit(
        X,
        y
    )

    print(
        "Training completed successfully."
    )

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    save_model(
        model
    )

    return model


# ============================================================
# SAVE MODEL
# ============================================================

def save_model(model):

    """
    Saves the trained model to:

        CyberSentinel/models/
        url_phishing_model.pkl
    """

    os.makedirs(
        MODEL_DIR,
        exist_ok=True
    )

    joblib.dump(
        model,
        MODEL_PATH
    )

    print(
        f"\nModel saved to:\n"
        f"{MODEL_PATH}"
    )


# ============================================================
# LOAD MODEL
# ============================================================

def load_model():

    """
    Loads the trained URL model.
    """

    if not os.path.exists(
        MODEL_PATH
    ):

        raise FileNotFoundError(

            "\nCyberSentinel URL model "
            "was not found.\n\n"

            f"Expected location:\n"
            f"{MODEL_PATH}\n\n"

            "Please train the model first using:\n"

            "python train_model.py"
        )

    try:

        model = joblib.load(
            MODEL_PATH
        )

    except Exception as error:

        raise RuntimeError(

            "The CyberSentinel URL model "
            "could not be loaded.\n"

            f"Reason: {error}"
        )

    return model


# ============================================================
# VALIDATE LOADED MODEL
# ============================================================

def validate_loaded_model(model):

    """
    Makes sure the saved model was trained
    using the current feature count.
    """

    try:

        expected_features = (
            model.named_steps[
                "neural_network"
            ].n_features_in_
        )

    except Exception:

        expected_features = None

    if (
        expected_features is not None
        and
        expected_features != FEATURE_COUNT
    ):

        raise RuntimeError(

            "Model/feature mismatch detected.\n"

            f"Current feature extractor: "
            f"{FEATURE_COUNT}\n"

            f"Saved model expects: "
            f"{expected_features}\n\n"

            "Retrain the model using:\n"
            "python train_model.py"
        )


# ============================================================
# GET MODEL INFORMATION
# ============================================================

def get_model_information():

    """
    Returns information about the trained model.
    """

    return {

        "model":
            "CyberSentinel URL Neural Network",

        "architecture":
            f"{FEATURE_COUNT}-64-32-16-2",

        "input_features":
            FEATURE_COUNT,

        "feature_names":
            FEATURE_ORDER,

        "classes": {

            "0":
                "Legitimate",

            "1":
                "Phishing"
        },

        "model_file":
            MODEL_PATH
    }


# ============================================================
# PREDICT URL
# ============================================================

def predict_url(url):

    """
    Predicts whether a URL is legitimate
    or phishing.

    Returns:

        prediction
        prediction_label
        phishing_probability
        legitimate_probability
        confidence
        model information
        extracted features
    """

    # --------------------------------------------------------
    # Validate URL input
    # --------------------------------------------------------

    if not isinstance(
        url,
        str
    ):

        raise ValueError(
            "URL must be a string."
        )

    url = url.strip()

    if not url:

        raise ValueError(
            "URL cannot be empty."
        )

    # --------------------------------------------------------
    # Load model
    # --------------------------------------------------------

    model = load_model()

    # --------------------------------------------------------
    # Validate model
    # --------------------------------------------------------

    validate_loaded_model(
        model
    )

    # --------------------------------------------------------
    # Extract current features
    # --------------------------------------------------------

    features = get_feature_vector(
        url
    )

    features = validate_features(
        features
    )

    # --------------------------------------------------------
    # Convert to NumPy array
    # --------------------------------------------------------

    feature_array = np.asarray(
        features,
        dtype=np.float32
    ).reshape(
        1,
        -1
    )

    # --------------------------------------------------------
    # Validate feature values
    # --------------------------------------------------------

    if not np.all(
        np.isfinite(
            feature_array
        )
    ):

        raise ValueError(
            "URL feature vector contains "
            "invalid numeric values."
        )

    # --------------------------------------------------------
    # Prediction
    # --------------------------------------------------------

    prediction = model.predict(
        feature_array
    )[0]

    prediction = int(
        prediction
    )

    # --------------------------------------------------------
    # Probability
    # --------------------------------------------------------

    if not hasattr(
        model,
        "predict_proba"
    ):

        raise RuntimeError(
            "The trained model does not support "
            "probability prediction."
        )

    probabilities = model.predict_proba(
        feature_array
    )[0]

    # --------------------------------------------------------
    # Get model classes
    # --------------------------------------------------------

    if not hasattr(
        model,
        "classes_"
    ):

        raise RuntimeError(
            "The trained model does not expose "
            "its class information."
        )

    classes = list(
        model.classes_
    )

    # --------------------------------------------------------
    # Legitimate probability
    # --------------------------------------------------------

    if LEGITIMATE_CLASS in classes:

        legitimate_index = classes.index(
            LEGITIMATE_CLASS
        )

        legitimate_probability = float(
            probabilities[
                legitimate_index
            ]
        )

    else:

        legitimate_probability = 0.0

    # --------------------------------------------------------
    # Phishing probability
    # --------------------------------------------------------

    if PHISHING_CLASS in classes:

        phishing_index = classes.index(
            PHISHING_CLASS
        )

        phishing_probability = float(
            probabilities[
                phishing_index
            ]
        )

    else:

        phishing_probability = 0.0

    # --------------------------------------------------------
    # Confidence
    # --------------------------------------------------------

    confidence = max(
        phishing_probability,
        legitimate_probability
    )

    # --------------------------------------------------------
    # Human-readable prediction
    # --------------------------------------------------------

    if prediction == PHISHING_CLASS:

        prediction_label = "PHISHING"

    else:

        prediction_label = "LEGITIMATE"

    # --------------------------------------------------------
    # Risk level based ONLY on model probability
    #
    # This is NOT the final CyberSentinel risk engine.
    # risk_engine.py will later combine:
    # AI + domain + reputation + threat intelligence.
    # --------------------------------------------------------

    if phishing_probability >= 0.80:

        model_risk_level = "HIGH"

    elif phishing_probability >= 0.50:

        model_risk_level = "MEDIUM"

    else:

        model_risk_level = "LOW"

    # --------------------------------------------------------
    # Feature dictionary
    # --------------------------------------------------------

    feature_dictionary = {

        FEATURE_ORDER[index]:
            float(
                features[index]
            )

        for index in range(
            len(FEATURE_ORDER)
        )
    }

    # --------------------------------------------------------
    # Return complete result
    # --------------------------------------------------------

    return {

        "prediction":
            prediction,

        "prediction_label":
            prediction_label,

        "phishing_probability":
            phishing_probability,

        "legitimate_probability":
            legitimate_probability,

        "confidence":
            confidence,

        "model_risk_level":
            model_risk_level,

        "model":
            "CyberSentinel URL Neural Network",

        "architecture":
            f"{FEATURE_COUNT}-64-32-16-2",

        "features_used":
            FEATURE_COUNT,

        "feature_names":
            FEATURE_ORDER,

        "features":
            feature_dictionary
    }


# ============================================================
# SIMPLE TEST
# ============================================================

def test_prediction(url):

    print(
        "\n" + "=" * 70
    )

    print(
        "CYBERSENTINEL URL TEST"
    )

    print(
        "=" * 70
    )

    print(
        f"\nURL:\n{url}"
    )

    result = predict_url(
        url
    )

    print(
        "\nPrediction:"
    )

    print(
        result[
            "prediction_label"
        ]
    )

    print(
        f"\nPhishing probability: "
        f"{result['phishing_probability'] * 100:.2f}%"
    )

    print(
        f"Legitimate probability: "
        f"{result['legitimate_probability'] * 100:.2f}%"
    )

    print(
        f"Confidence: "
        f"{result['confidence'] * 100:.2f}%"
    )

    print(
        f"Model risk level: "
        f"{result['model_risk_level']}"
    )

    print(
        f"\nFeatures used: "
        f"{result['features_used']}"
    )

    print(
        "\nFeatures:"
    )

    for name, value in result[
        "features"
    ].items():

        print(
            f"{name}: {value}"
        )

    print(
        "=" * 70
    )

    return result


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    print(
        "\nCyberSentinel ML Model Module"
    )

    print(
        f"Model path:\n"
        f"{MODEL_PATH}"
    )

    print(
        f"\nCurrent feature count: "
        f"{FEATURE_COUNT}"
    )

    if os.path.exists(
        MODEL_PATH
    ):

        print(
            "\n✓ Trained model found."
        )

        try:

            model = load_model()

            validate_loaded_model(
                model
            )

            model_info = (
                get_model_information()
            )

            print(
                f"Architecture: "
                f"{model_info['architecture']}"
            )

            print(
                f"Features: "
                f"{model_info['input_features']}"
            )

            print(
                "\n✓ Model is compatible "
                "with the current feature extractor."
            )

        except Exception as error:

            print(
                "\n✗ Model validation failed."
            )

            print(
                f"\nReason: {error}"
            )

            print(
                "\nRetrain using:"
            )

            print(
                "python train_model.py"
            )

    else:

        print(
            "\n⚠ Trained model not found."
        )

        print(
            "\nTrain the model using:"
        )

        print(
            "python train_model.py"
        )