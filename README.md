Here’s the updated **README** without mentioning the **GMM**:

````markdown
# HETEROGENEOUS-KEY HOMOMORPHIC ENCRYPTION IN PRIVACY-PRESERVING FEDERATED LEARNING FOR ROBUST IOT SYSTEMS

This project implements a **Privacy-Preserving Federated Learning (PPFL)** system with a focus on **Heterogeneous-Key Homomorphic Encryption (HE)** in the context of **Robust IoT Systems**. The goal of this project is to enable secure and efficient federated learning for IoT applications, where multiple devices collaborate in training machine learning models while preserving the privacy of their data.

## Overview

In Federated Learning, clients train local models on their own data and share encrypted updates with a central server. The server aggregates these updates into a global model, and the process is repeated for multiple rounds. **Homomorphic Encryption** (HE) ensures that the server can aggregate model updates without accessing the raw data, providing privacy for the clients.

In this implementation, **Heterogeneous-Key Homomorphic Encryption** is used, which allows the use of different encryption keys across clients, making the system more robust in real-world scenarios where different devices might have different capabilities and security requirements.

## Key Features

- **Heterogeneous-Key Homomorphic Encryption (HE)**: The system supports different encryption keys across clients, providing greater flexibility and security.
- **Federated Learning**: Clients train models locally and share encrypted updates with a central server.
- **Shamir Secret Sharing**: Used for securing sensitive data during the federated learning process.
- **Secure Aggregation**: The server aggregates model updates without accessing raw data, ensuring privacy.
- **Dimensionality Reduction**: **PCA (Principal Component Analysis)** is used to reduce the dimensionality of the data before training the model.

## Architecture

### Server:
- Aggregates encrypted model updates from clients using **Heterogeneous-Key Homomorphic Encryption**.
- Uses **Shamir Secret Sharing** to securely share the aggregated updates with the clients.
- Shares the global model with clients for the next round of training.

### Client:
- Trains a local model on its own dataset.
- Encrypts the model updates using **Homomorphic Encryption**.
- Shares the encrypted updates with the server for aggregation.

## Setup

### Prerequisites:
- Python 3.8 or higher.
- The following Python libraries must be installed:
  ```bash
  pip install numpy pandas phe tensorflow scikit-learn
````

### File Structure

```
federated-learning-client-server/
│
├── client.py            # The client-side code.
├── server.py            # The server-side code.
├── ShamirSecret.py      # Custom implementation for Shamir Secret Sharing.
├── DLClient.py          # Custom implementation for Deep Learning client model training.
├── auth.py              # Helper functions for authentication (hashing, signature).
├── cert.pem             # SSL certificate.
├── key.pem              # SSL private key.
├── s<client_id>_processed.csv  # Client-specific dataset.
├── requirements.txt     # List of required Python packages.
└── README.md            # This file.
```

## Feature Engineering

The client performs feature engineering on the data to extract relevant features before training the model. This includes:

1. **Removing irrelevant features**.
2. **Computing time-domain features** like RMS, mean, and standard deviation.
3. **Computing frequency-domain features** using FFT (Fast Fourier Transform).
4. **Dimensionality reduction** using PCA (Principal Component Analysis).

### Example Feature Engineering Code:

```python
def featureEngineering(df):
    # Feature extraction
    ...
    return df_pca
```

## Model Training

The model is a **deep learning** model built using **TensorFlow** and trained using the client's data. The model is trained to predict a target variable (e.g., ECG signal) and the model weights are aggregated securely.

### Example Training Code:

```python
def modelTraining(data, agg_weights=None):
    # Preprocessing and model definition
    ...
    return model.get_weights()
```

## Running the System

### Server Setup:

1. Clone the repository.
2. Run the server script:

   ```bash
   python server.py
   ```

### Client Setup:

1. Clone the repository.
2. Ensure each client has access to its own local dataset.
3. Run the client script with a unique client ID:

   ```bash
   python client.py <client_id>
   ```

### Federated Learning Execution:

* The server will receive encrypted updates from the clients and aggregate them.
* Clients will train their models, encrypt the updates, and send them to the server.
* The system will continue to iterate through multiple rounds of model updates.

## Results

The system evaluates the model performance using **R-squared** and **RMSE (Root Mean Squared Error)**. The goal is to achieve robust and accurate model performance while preserving privacy.

### Performance Evaluation Code:

```python
def evaluate_model(model, X_test, y_test):
    # Evaluate the model performance
    ...
    return rmse, rscore
```

## Conclusion

This project provides a robust framework for federated learning in IoT systems, with enhanced privacy preservation through **Heterogeneous-Key Homomorphic Encryption** and **Shamir Secret Sharing**. It allows multiple devices to collaboratively train machine learning models while keeping their data secure.

