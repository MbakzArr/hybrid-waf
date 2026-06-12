"""
Pipeline 2: Random Forest Classifier (scikit-learn reference pipeline)
Hybrid WAF – IT28X87 Honours Project
Mbadaliga, AB (219044112)

Uses scikit-learn's RandomForestClassifier as the existing reference
pipeline. This is Pipeline 2 – the existing library-based comparison
point against Pipeline 1 (custom Logistic Regression).

Design rationale: scikit-learn's RF provides a well-optimised, well-tested
baseline. Comparing it against the custom LR implementation answers
whether the custom implementation achieves competitive accuracy, and
whether the additional complexity of an ensemble model is justified
given the latency constraints.
"""
import pickle
from typing import Optional

try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class RandomForestModel:
    """
    Wrapper around scikit-learn RandomForestClassifier.
    Trained on the same 6-feature vector as Pipeline 1.

    Parameters
    ----------
    n_estimators : int
        Number of trees. Default 100.
    max_depth : int
        Maximum tree depth. Default 10.
    random_state : int
        Seed for reproducibility.
    """

    def __init__(self, n_estimators: int = 100,
                 max_depth: int = 10,
                 random_state: int = 42):
        if not SKLEARN_AVAILABLE:
            raise ImportError(
                "scikit-learn is required for Pipeline 2. "
                "Run: pip install scikit-learn"
            )
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=random_state,
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        self.trained: bool = False

    def fit(self, X, y) -> None:
        """Scales features and trains the Random Forest."""
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled, y)
        self.trained = True
        print(f"[RF] Training complete. "
              f"Trees: {self.model.n_estimators}")

    def predict_proba(self, x) -> float:
        """
        Returns P(malicious) for a single feature vector.
        Feature scaling is applied before prediction.
        """
        if not self.trained:
            raise RuntimeError(
                "Model not trained. Call fit() or load() first."
            )
        import numpy as np
        x_scaled = self.scaler.transform(x.reshape(1, -1))
        return float(self.model.predict_proba(x_scaled)[0][1])

    def save(self, path: str) -> None:
        with open(path, 'wb') as f:
            pickle.dump({'model': self.model,
                         'scaler': self.scaler,
                         'trained': self.trained}, f)
        print(f"[RF] Model saved to {path}")

    def load(self, path: str) -> None:
        with open(path, 'rb') as f:
            data = pickle.load(f)
        self.model = data['model']
        self.scaler = data['scaler']
        self.trained = data['trained']
        print(f"[RF] Model loaded from {path}")
