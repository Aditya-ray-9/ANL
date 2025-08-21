# 🔐 ANL5 – Advanced Numeric Lock Encryption

ANL5 (**Advanced Numeric Lock v5**) is a custom **encryption & decryption system** written in Python. It converts text into an ANL numeric code, then into binary, and secures the binary using a generated key. The module is modular and easy to integrate with Flask or other Python apps. its developer is Aditya Ray a python developer

---

## 🚀 Features

* **Key-based encryption** (random per operation)
* **Two-way encode/decode** with the same key
* **Two mixing modes:** `add` (integer addition) and `xor` (bitwise stream XOR)
* **Returns results as a dict** containing encoded string, key, and secured binary
* **Flask-ready**: example `main.py` included for quick web integration

---

## 📂 Project Structure

```
ANL5/
├── ANL.py           # Core encryption/decryption module
├── main.py          # Flask server (example)
├── templates/
│   ├── index.html   # Main encryption page
│   ├── translate.html # Decryption page
│   └── help.html    # Help & documentation
├── static/          # (optional) CSS/JS assets
└── README.md
```

---

## 🛠 Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/ANL5.git
cd ANL5
```

2. Create a virtual environment (recommended):

```bash
python -m venv venv
source venv/bin/activate   # macOS / Linux
venv\Scripts\activate     # Windows
```

3. Install dependencies:

```bash
pip install -r requirements.txt
# or at minimum:
pip install flask
```

4. Run the Flask app locally:

```bash
python main.py
```

Open your browser at `http://127.0.0.1:5000/`.

---

## 🔑 Quick API (module)

Import and use the `ANL` class from `ANL.py`:

```python
from ANL import ANL

# Encode with a generated key
obj = ANL.generate_with_key("Hello World", key_length=9, mode="add")
print(obj["secured_binary"])  # secured binary
print(obj["key_text"])        # the key text (keep secret)

# Decode with key
res = ANL.decrypt_from_object(obj)
print(res["decoded"])        # original text
```

**Main helper functions**:

* `ANL.generate_with_key(text, key_text=None, key_length=9, mode='add', add_multiplier=2)` → returns a `dict` with `original`, `encoded`, `encoded_binary`, `key_text`, `key_binary`, `secured_binary`, and metadata.
* `ANL.decrypt_from_object(obj, mode=None)` → accepts that `dict` (or similar) and returns `{'recovered_encoded', 'decoded'}`.
* `text_to_binary(text)`, `binary_to_text(binary)` utility helpers are in the module.

Modes:

* `add`: converts encoded string to integer, multiplies key integer by `add_multiplier`, then adds.
* `xor`: XORs repeated key-bit stream with encoded-bit stream.

---

## 🌐 Web Integration (Flask)

`main.py` includes endpoints used by the provided frontend templates:

* `GET /` → `index.html` (encode page)
* `POST /process` → accepts text, returns JSON with `secured_binary` and `key_text`
* `GET /translate` → `translate.html` (decode page)
* `POST /decode` → accepts `secured_binary` + `key_text` and returns decoded text

Use the provided `templates/` files as a starting UI.

---

## 🧾 Security Notes

* The module is **educational** and suitable for learning and light-duty privacy. It is **not** a drop-in replacement for vetted cryptographic primitives (AES, RSA).
* Multiplying the key integer by a constant is reversible; for stronger security consider using standard symmetric encryption (AES) or HMAC-based verification.
* Use long, random `key_text` (increase `key_length`) to make brute-force attacks impractical.

---

## 🧪 Tests & Examples

Run the module directly for a demo:

```bash
python ANL.py
```

This prints example encoded, secured, and decoded outputs for both `add` and `xor` modes.

---

## 📄 License

MIT License — see `LICENSE` for details.

---

If you want, I can also:

* add shields/badges at the top (PyPI, License, Build),
* split the module into `alpha.py` + `crypto.py`, or
* produce a `requirements.txt` and a Dockerfile for deployment.
