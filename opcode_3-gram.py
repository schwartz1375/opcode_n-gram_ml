#!/usr/bin/env python3
__author__ = 'Matthew Schwartz'

import glob
import os

import numpy as np
import skops.io as sio
import tensorflow as tf
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split


def load_files(ngrams_dir, label):
    ngram_files = glob.glob(os.path.join(ngrams_dir, '*.txt'))
    data, labels = [], []

    for file in ngram_files:
        with open(file, 'r') as f:
            ngrams = f.read()
            data.append(ngrams)
            labels.append(label)

    return data, labels

# Load n-grams and labels for malicious and benign files
malicious_data, malicious_labels = load_files('malicious_3grams', 1)
benign_data, benign_labels = load_files('benign_3grams', 0)

# Combine the data and labels
data = malicious_data + benign_data
labels = malicious_labels + benign_labels

# Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(data, labels, test_size=0.2, random_state=42)

# Convert n-grams into a numerical format using TfidfVectorizer
# vectorizer = TfidfVectorizer()
# See the readme regarding the "Input File & the Vectorizer"
# It is essential to capture the relationships between consecutive opcodes.
vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(2, 3))

X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

# Convert labels to numpy arrays
y_train_np = np.array(y_train)
y_test_np = np.array(y_test)

# Build a neural network classifier using Keras
model = tf.keras.Sequential([
    tf.keras.layers.Dense(64, activation='relu', input_shape=(X_train_vec.shape[1],)),
    tf.keras.layers.Dropout(0.5),
    tf.keras.layers.Dense(32, activation='relu'),
    tf.keras.layers.Dropout(0.5),
    tf.keras.layers.Dense(1, activation='sigmoid')
])

model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# Train the classifier on the training set
model.fit(X_train_vec.toarray(), y_train_np, epochs=10, batch_size=32)

# Evaluate the classifier on the testing set
loss, accuracy = model.evaluate(X_test_vec.toarray(), y_test_np)
print("Accuracy:", accuracy)
y_pred = (model.predict(X_test_vec.toarray()) > 0.5).astype("int32")
print(classification_report(y_test_np, y_pred))

print('Test loss:', loss)
print('Test accuracy:', accuracy)

# Save the trained model
model.save('malware_classification_model-keras.h5')
# Save the vectorizer
sio.dump(vectorizer, 'vectorizer-keras.skops')
