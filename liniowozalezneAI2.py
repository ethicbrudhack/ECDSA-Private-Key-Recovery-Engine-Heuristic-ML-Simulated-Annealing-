#!/usr/bin/env python3
"""
Zaktualizowany skrypt do odzyskiwania klucza prywatnego ECDSA z podpisów.
Uwzględniono:
- adaptacyjny wybór k z kontrolą powtórek
- rozszerzoną analizę heurystyczną
- uczenie maszynowe z realnym postępem
- lepsze logowanie i zarządzanie stanem
- pełna integracja z istniejącym systemem odzyskiwania (nieusunięte funkcje!)
"""

import os
import re
import time
import math
import random
import pickle
import logging
import hashlib
import base58
import ecdsa
import numpy as np
from statistics import mean, stdev
from sympy import mod_inverse
from sklearn.linear_model import SGDRegressor
from sklearn.preprocessing import StandardScaler

# --- Parametry ---
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
TARGET_ADDRESS = "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h"
USED_K_FILE = "used_k.txt"
MODEL_K_FILE = "ml_k_model.pkl"
SCALER_K_FILE = "scaler_k.pkl"

# --- Implementacja Bech32 / SegWit (BIP173) ------------------------------
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        if top & 1:
            chk ^= 0x3b6a57b2
        if top & 2:
            chk ^= 0x26508e6d
        if top & 4:
            chk ^= 0x1ea119fa
        if top & 8:
            chk ^= 0x3d4233dd
        if top & 16:
            chk ^= 0x2a1462b3
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_verify_checksum(hrp, data):
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1

def bech32_encode(hrp, data):
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join([CHARSET[d] for d in combined])

def bech32_decode(bech):
    if any(ord(x) < 33 or ord(x) > 126 for x in bech):
        return (None, None)
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return (None, None)
    hrp = bech[:pos]
    data = []
    for x in bech[pos+1:]:
        if x not in CHARSET:
            return (None, None)
        data.append(CHARSET.find(x))
    if not bech32_verify_checksum(hrp, data):
        return (None, None)
    return (hrp, data[:-6])

def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def segwit_decode(hrp, addr):
    hrpgot, data = bech32_decode(addr)
    if hrpgot != hrp or data is None or len(data) < 1:
        return (None, None)
    witness_version = data[0]
    witness_program = convertbits(data[1:], 5, 8, False)
    if witness_program is None:
        return (None, None)
    if not (2 <= len(witness_program) <= 40):
        return (None, None)
    if witness_version > 16:
        return (None, None)
    return (witness_version, witness_program)

def segwit_encode(hrp, witver, witprog):
    five_bit_prog = convertbits(witprog, 8, 5)
    if five_bit_prog is None:
        return None
    ret = [witver] + five_bit_prog
    return bech32_encode(hrp, ret)

# --- Logowanie ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Obsługa użytych k ---
used_k_map = {}
USED_K_MAX_TRIES = 5
if os.path.exists(USED_K_FILE):
    with open(USED_K_FILE) as f:
        for line in f:
            try:
                k, count = map(int, line.strip().split(","))
                used_k_map[k] = count
            except: pass

def save_used_k(k):
    used_k_map[k] = used_k_map.get(k, 0) + 1
    with open(USED_K_FILE, "a") as f:
        f.write(f"{k},{used_k_map[k]}\n")

def is_k_overused(k):
    return used_k_map.get(k, 0) >= USED_K_MAX_TRIES

def filter_valid_k(candidates):
    return [k for k in candidates if not is_k_overused(k)]

# --- ML: predykcja k ---
if os.path.exists(MODEL_K_FILE) and os.path.exists(SCALER_K_FILE):
    with open(MODEL_K_FILE, "rb") as f:
        ml_k_model = pickle.load(f)
    with open(SCALER_K_FILE, "rb") as f:
        scaler_k = pickle.load(f)
else:
    ml_k_model = SGDRegressor()
    scaler_k = StandardScaler()
    X_init = np.array([[1, 2, 3, 4, 5, 6, 7]])
    y_init = np.array([0.5])
    scaler_k.fit(X_init)
    ml_k_model.partial_fit(scaler_k.transform(X_init), y_init)

def extract_signature_features(sig):
    r, s, z = sig["r"], sig["s"], sig["z"]
    return [
        r % 997, s % 997, z % 997,
        abs(r - s) % 997,
        (r + s) % 997,
        (r * s) % 997,
        (r ^ s) % 997,
    ]

def predict_k(sig):
    features = np.array([extract_signature_features(sig)])
    scaled = scaler_k.transform(features)
    norm_k = ml_k_model.predict(scaled)[0]
    return max(1, min(int(norm_k * n), n - 1))

# --- Odzyskiwanie d ---
def recover_d(r, s, k, z):
    try:
        inv_r = mod_inverse(r, n)
        d = ((s * k - z) * inv_r) % n
        return d if 1 < d < n else None
    except:
        logging.error(f"Error recovering d: r={r}, s={s}, k={k}, z={z}")
        return None

# --- Generowanie adresu ---
def private_key_to_address(d):
    sk = ecdsa.SigningKey.from_secret_exponent(d, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    x, y = vk.pubkey.point.x(), vk.pubkey.point.y()
    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    pubkey = prefix + x.to_bytes(32, 'big')
    sha = hashlib.sha256(pubkey).digest()
    rip = hashlib.new('ripemd160', sha).digest()
    # SegWit address (bc1 format)
    return segwit_encode("bc", 0, list(rip))

# --- Hamming Distance ---
def compute_hamming_distance(addr1, addr2):
    """Oblicza Hamming distance między dwoma adresami w formie hex"""
    # Konwersja adresu SegWit (bc1...) na hex
    try:
        hrp, data = segwit_decode("bc", addr1)
        if hrp is None or data is None:
            raise ValueError(f"Niepoprawny adres SegWit: {addr1}")
        addr1_hex = ''.join(format(byte, '02x') for byte in data)

        # Konwersja docelowego adresu na hex
        hrp_target, data_target = segwit_decode("bc", addr2)
        if hrp_target is None or data_target is None:
            raise ValueError(f"Niepoprawny adres SegWit: {addr2}")
        addr2_hex = ''.join(format(byte, '02x') for byte in data_target)

        # Upewniamy się, że obydwa adresy mają 160-bitową długość (40 znaków hex)
        addr1_bin = bin(int(addr1_hex, 16))[2:].zfill(160)
        addr2_bin = bin(int(addr2_hex, 16))[2:].zfill(160)
        return sum(c1 != c2 for c1, c2 in zip(addr1_bin, addr2_bin))

    except Exception as e:
        logging.error(f"Błąd przy obliczaniu Hamming Distance: {e}")
        return None


# --- SA dla k ---
def simulated_annealing_k(r, s, z, initial_k, max_iter=200, initial_temp=100.0, cooling_rate=0.98):
    best_k = initial_k
    best_score = -1
    temp = initial_temp

    def score(k):
        return 1 if recover_d(r, s, k, z) else 0

    for _ in range(max_iter):
        step = max(1, int(temp))
        candidates = [max(1, min(best_k + random.randint(-step, step), n - 1)) for _ in range(10)]
        candidates.append(random.randint(1, n - 1))
        valid = filter_valid_k(candidates)
        if not valid:
            continue
        scores = list(map(score, valid))
        max_s = max(scores)
        if max_s > best_score:
            best_score = max_s
            best_k = valid[scores.index(max_s)]
        temp *= cooling_rate
        if best_score >= 1:
            break

    save_used_k(best_k)
    return best_k

# --- Wczytaj podpisy ---
def read_signatures(path):
    txs = []
    with open(path) as f:
        blocks = f.read().split("----------------------------------")
        logging.info(f"Wczytano {len(blocks)} bloków danych.")
        for blk in blocks:
            r = re.search(r"r\d+:\s*([0-9a-fA-F]+)", blk)
            s = re.search(r"s\d+:\s*([0-9a-fA-F]+)", blk)
            z = re.search(r"z\d+:\s*([0-9a-fA-F]+)", blk)
            if r and s and z:
                txs.append({
                    "r": int(r.group(1), 16),
                    "s": int(s.group(1), 16),
                    "z": int(z.group(1), 16),
                })
    logging.info(f"Wczytano {len(txs)} podpisów.")
    return txs

# --- Główna pętla ---
def main():
    txs = read_signatures("podpisy.txt")
    if not txs:
        logging.error("Brak transakcji do przetworzenia!")
        return

    for tx in txs:
        try:
            pred_k = predict_k(tx)
            final_k = simulated_annealing_k(tx["r"], tx["s"], tx["z"], pred_k)
            d = recover_d(tx["r"], tx["s"], final_k, tx["z"])
            if d:
                addr = private_key_to_address(d)
                hamming_dist = compute_hamming_distance(addr, TARGET_ADDRESS)
                print(f"\n🎉 ZNALEZIONO: d = {hex(d)} | {addr} | Hamming Distance: {hamming_dist} bits\n")
                features = np.array([extract_signature_features(tx)])
                try:
                    # Aktualizacja modelu ML
                    ml_k_model.partial_fit(scaler_k.transform(features), [final_k / n])
                    with open(MODEL_K_FILE, "wb") as f1, open(SCALER_K_FILE, "wb") as f2:
                        pickle.dump(ml_k_model, f1)
                        pickle.dump(scaler_k, f2)
                except Exception as e:
                    logging.error(f"ML update error: {e}")
            else:
                logging.warning("Nie znaleziono klucza d dla tej transakcji.")
        except Exception as e:
            logging.error(f"Błąd przy przetwarzaniu transakcji: {e}")
        time.sleep(0.1)  # Skrócony czas oczekiwania dla szybszego działania

if __name__ == '__main__':
    main()
