"""
Pipeline 1: Custom Logistic Regression Classifier
Hybrid WAF – IT28X87 Honours Project
Mbadaliga, AB (219044112)

Custom implementation of binary logistic regression using gradient descent.
Only numpy is used for matrix operations – no scikit-learn or ML frameworks.

This is a deliberate design choice (not reinventing the wheel for its own sake):
the custom implementation gives full control over the forward pass, loss
function, and weight update step, which is required for the interpretability
NFR and for demonstrating algorithmic understanding in the research paper.

Algorithm:
    Forward pass:  y_hat = sigmoid(X @ w + b)
    Loss:          L = -(1/N) * sum(y*log(y_hat) + (1-y)*log(1-y_hat))
    Weight update: w = w - lr * dL/dw
                   b = b - lr * dL/db
"""
import math
import pickle
from typing import List, Optional

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False


class LogisticRegressionModel:
    """
    Binary logistic regression trained with batch gradient descent.

    Parameters
    ----------
    learning_rate : float
        Step size for gradient updates. Default 0.01.
    n_epochs : int
        Number of full passes through training data. Default 1000.
    """

    def __init__(self, learning_rate: float = 0.01,
                 n_epochs: int = 1000):
        if not NUMPY_AVAILABLE:
            raise ImportError(
                "numpy is required for Pipeline 1. "
                "Run: pip install numpy"
            )
        self.learning_rate = learning_rate
        self.n_epochs = n_epochs
        self.weights: Optional[np.ndarray] = None
        self.bias: float = 0.0
        self.trained: bool = False
        self.loss_history: List[float] = []

    # ── Core algorithm ──────────────────────────────────────────

    @staticmethod
    def _sigmoid(z: np.ndarray) -> np.ndarray:
        """Numerically stable sigmoid: clips z to avoid overflow."""
        z_clipped = np.clip(z, -500, 500)
        return 1.0 / (1.0 + np.exp(-z_clipped))

    def _forward(self, X: np.ndarray) -> np.ndarray:
        """Forward pass: returns predicted probabilities for each sample."""
        return self._sigmoid(X @ self.weights + self.bias)

    def _loss(self, y: np.ndarray,
              y_hat: np.ndarray) -> float:
        """
        Binary cross-entropy loss.
        Clips y_hat to [1e-15, 1-1e-15] to avoid log(0).
        """
        eps = 1e-15
        y_hat = np.clip(y_hat, eps, 1 - eps)
        N = len(y)
        return -float(np.mean(
            y * np.log(y_hat) + (1 - y) * np.log(1 - y_hat)
        ))

    def _gradient_step(self, X: np.ndarray,
                       y: np.ndarray,
                       y_hat: np.ndarray) -> None:
        """Updates weights and bias using batch gradient descent."""
        N = len(y)
        error = y_hat - y                     # (N,)
        dw = (X.T @ error) / N               # (n_features,)
        db = float(np.mean(error))
        self.weights -= self.learning_rate * dw
        self.bias    -= self.learning_rate * db

    # ── Public interface ─────────────────────────────────────────

    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        """
        Trains the model on feature matrix X and label vector y.

        Parameters
        ----------
        X : ndarray of shape (N, 6)
            Feature matrix. Each row is one FeatureVector.to_list().
        y : ndarray of shape (N,)
            Binary labels. 0 = benign, 1 = malicious.
        """
        n_samples, n_features = X.shape
        self.weights = np.zeros(n_features)
        self.bias = 0.0
        self.loss_history = []

        for epoch in range(self.n_epochs):
            y_hat = self._forward(X)
            loss = self._loss(y, y_hat)
            self.loss_history.append(loss)
            self._gradient_step(X, y, y_hat)

            if epoch % 100 == 0:
                print(f"[LR] Epoch {epoch:>5} | Loss: {loss:.6f}")

        self.trained = True
        print(f"[LR] Training complete. "
              f"Final loss: {self.loss_history[-1]:.6f}")

    def predict_proba(self, x: np.ndarray) -> float:
        """
        Returns P(malicious) for a single feature vector.

        Parameters
        ----------
        x : ndarray of shape (6,)
            One FeatureVector.to_list() converted to ndarray.

        Returns
        -------
        float in [0, 1]
        """
        if not self.trained:
            raise RuntimeError(
                "Model not trained. Call fit() or load() first."
            )
        return float(self._forward(x.reshape(1, -1))[0])

    def save(self, path: str) -> None:
        """Serialises model weights and bias to disk."""
        with open(path, 'wb') as f:
            pickle.dump({
                'weights': self.weights,
                'bias': self.bias,
                'learning_rate': self.learning_rate,
                'n_epochs': self.n_epochs,
                'trained': self.trained,
            }, f)
        print(f"[LR] Model saved to {path}")

    def load(self, path: str) -> None:
        """Loads model weights and bias from disk."""
        with open(path, 'rb') as f:
            data = pickle.load(f)
        self.weights = data['weights']
        self.bias = data['bias']
        self.learning_rate = data['learning_rate']
        self.n_epochs = data['n_epochs']
        self.trained = data['trained']
        print(f"[LR] Model loaded from {path}")
