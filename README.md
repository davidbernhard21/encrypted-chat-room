ChaCha20: https://github.com/kirisuna1/ChaChaChatroom

Saber: https://github.com/Przemyslaw11/Saber


The cipher.nonce is a term used in cryptographic algorithms, particularly in the context of the pycryptodome library in Python. 
Let's break down what a nonce is and its function:

What is a Nonce?
Nonce: A "nonce" stands for "number once." It's a random or pseudo-random value that is used only once in a cryptographic 
communication. The main purpose of a nonce is to ensure that the same encryption key produces different ciphertexts 
for the same plaintext when the same key is used multiple times.

Function of cipher.nonce
In the context of the pycryptodome library (and similar cryptographic libraries), 
cipher.nonce is used to hold the nonce value generated by the cipher object. 
This value is typically required to decrypt the data later.

When creating a new cipher object (for instance, using AES in EAX mode), the library automatically generates a nonce 
if you don't provide one explicitly.

The nonce is then stored as an attribute of the cipher object, and you can retrieve it using cipher.nonce.

Importance of Nonce
Uniqueness: Ensures that even if the same plaintext is encrypted multiple times with the same key, 
the resulting ciphertext will be different each time.

Security: Prevents replay attacks and ensures the integrity of the encrypted data.

By using cipher.nonce, you can securely manage and store the nonce value needed for both encryption and decryption processes.



show me sample python code to combine KEM mechanism using Saber with ChaCha20 Symmetric Key thak transfered between two clients