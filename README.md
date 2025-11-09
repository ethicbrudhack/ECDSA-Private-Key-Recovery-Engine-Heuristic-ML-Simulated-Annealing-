# 🔐 ECDSA Private Key Recovery Engine (Heuristic + ML + Simulated Annealing)

This Python script implements an **advanced ECDSA private key recovery engine**, combining:
- Adaptive nonce (`k`) estimation  
- Machine learning prediction  
- Simulated annealing optimization  
- Heuristic filtering and address matching  
- Integrated SegWit (Bech32) Bitcoin address reconstruction  

The script attempts to recover a private key `d` from multiple ECDSA signatures that may have **related or reused nonces** — a known vulnerability in digital signature schemes such as Bitcoin’s **secp256k1**.

---

## 🧩 Overview

ECDSA signatures are defined as:

\[
s = k^{-1} (z + d \cdot r) \pmod{n}
\]

If two or more signatures share related `k` values, or if `k` can be estimated, the private key `d` can be recovered.

This tool applies **statistical feature extraction**, **machine learning regression (SGD)**, and **simulated annealing** to search for possible `k` values that yield a valid private key whose derived address is close (in Hamming distance) to the target address.

---

## ⚙️ Core Features

✅ Adaptive learning — uses `SGDRegressor` to predict next nonce `k`  
✅ Simulated annealing — explores nearby `k` values for optimization  
✅ Automatic avoidance of reused `k` (tracked in `used_k.txt`)  
✅ Dynamic model retraining — updates ML weights after each successful iteration  
✅ Fully offline — no external API or blockchain node required  
✅ Integrated SegWit (Bech32) encoder/decoder for address validation  

---

## 📂 File Structure

| File | Description |
|------|--------------|
| `recovery_engine.py` | The main script |
| `podpisy.txt` | Input file containing extracted ECDSA signature data |
| `used_k.txt` | Tracks previously tested `k` values to avoid repetition |
| `ml_k_model.pkl` | Saved machine learning model for `k` prediction |
| `scaler_k.pkl` | Feature scaler for ML preprocessing |

---

## 🧮 Input Format

The script expects a text file `podpisy.txt` containing multiple signatures, separated by dashed lines:

r1: <hex>
s1: <hex>
z1: <hex>

r2: <hex>
s2: <hex>
z2: <hex>


Each block represents a unique ECDSA signature.

---

## 🚀 How to Run

### 1️⃣ Install dependencies
```bash
pip install ecdsa sympy numpy scikit-learn

2️⃣ Prepare the signature data

Create or export a file podpisy.txt with at least two valid ECDSA signatures.

3️⃣ Run the recovery engine
python3 recovery_engine.py

4️⃣ Monitor the output

You’ll see live logs for:

Predicted and optimized k values

Candidate private keys d

Corresponding Bitcoin addresses

Hamming distance from the target address

Example output:

🎉 ZNALEZIONO: d = 0x4f1a...b9c3 | bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h | Hamming Distance: 0 bits


If a match is found, the recovered private key will be printed in hexadecimal format.

🧠 How It Works (Simplified)

Feature Extraction:
Converts each (r, s, z) into numerical features used to train a regression model for predicting the most probable k.

ML Model:

Trains an incremental model (SGDRegressor) to improve predictions over time.

Saves the model in ml_k_model.pkl.

Simulated Annealing:

Takes the predicted k as a starting point.

Iteratively explores neighboring values with decreasing randomness (temperature cooling).

Selects the best candidate according to cryptographic consistency.

Key Recovery:

𝑑
=
(
𝑠
⋅
𝑘
−
𝑧
)
⋅
𝑟
−
1
(
m
o
d
𝑛
)
d=(s⋅k−z)⋅r
−1
(modn)

Address Check:
Converts d to a compressed public key and then to a SegWit (bc1) address using Bech32 encoding.
The address is compared to the TARGET_ADDRESS via Hamming distance.

🧰 Dependencies
Library	Purpose
ecdsa	secp256k1 key generation and verification
sympy	Modular inverse computation
numpy	Numeric operations and feature extraction
scikit-learn	Machine learning model (SGDRegressor)
base58	For key encoding utilities
⚠️ Security & Ethics Notice

⚠️ This script is provided for educational and research purposes only.
It demonstrates how ECDSA nonce correlation can be exploited mathematically.
Do not use it for unauthorized access, wallet attacks, or data extraction.
Always use test data or controlled cryptographic environments.


BTC donation address: bc1q4nyq7kr4nwq6zw35pg0zl0k9jmdmtmadlfvqhr
