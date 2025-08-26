# ANL_6.py
import secrets
import string
import base64
import hmac
import hashlib
from typing import Dict, Optional, Any

def text_to_binary(text: str, spaced: bool = True) -> str:
    if not text:
        return ""
    bits = "".join(format(ord(c), "08b") for c in text)
    if spaced:
        return " ".join(bits[i:i+8] for i in range(0, len(bits), 8))
    return bits

def binary_to_text(binary: str) -> str:
    if not binary:
        return ""
    bits = "".join(ch for ch in binary if ch in "01")
    pad = (-len(bits)) % 8
    if pad:
        bits = ("0" * pad) + bits
    return "".join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))

class ANL:
    char_map = {chr(i): str(i - 96) + "." for i in range(97, 123)}
    char_map.update({chr(i): f"U{str(i - 64)}." for i in range(65, 91)})
    special_char_map = {
        "@": "_1_", "!": "_2_", "#": "_3_", "$": "_4_",
        "+": "__1__", "-": "__2__", "*": "__3__", "/": "__4__",
        "%": "__5__", "^": "__6__", "(": "_5_", ")": "_6_",
        "{": "_7_", "}": "_8_", "[": "_9_", "]": "_10_",
        "<": "_11_", ">": "_12_", ":": "_13_", ";": "_14_",
        "'": "_15_", '"': "_16_", "|": "_17_", ",": "_18_",
        "?": "_19_", ".": "_20_", "=": "_21_", "_": "_22_",
        "~": "_23_", "`": "_24_", " ": "__",
    }
    reversed_special_char_map = {v: k for k, v in special_char_map.items()}

    class Component:
        @staticmethod
        def bits_from_text(text: str) -> str:
            return text_to_binary(text, spaced=False)

        @staticmethod
        def bytes_from_bits(bits: str) -> bytes:
            if not bits:
                return b""
            pad = (-len(bits)) % 8
            if pad:
                bits = ("0" * pad) + bits
            n = len(bits) // 8
            return int(bits, 2).to_bytes(n, "big")

        @staticmethod
        def bits_from_bytes(b: bytes) -> str:
            if not b:
                return ""
            return "".join(format(byte, "08b") for byte in b)

        @staticmethod
        def hmac_keystream_bits(key_text: str, length_bits: int) -> str:
            if length_bits <= 0:
                return ""
            key = (key_text or "").encode("utf-8")
            out = bytearray()
            ctr = 0
            while len(out) * 8 < length_bits:
                msg = ctr.to_bytes(4, "big")
                out.extend(hmac.new(key, msg, hashlib.sha256).digest())
                ctr += 1
            bits = ANL.Component.bits_from_bytes(bytes(out))[:length_bits]
            return bits

    @staticmethod
    def generate(text: str) -> str:
        if text is None:
            return ""
        out = []
        for ch in text:
            if ch in ANL.char_map:
                out.append(ANL.char_map[ch])
            elif ch in ANL.special_char_map:
                out.append(ANL.special_char_map[ch])
            elif ch.isdigit():
                out.append(f"${ch}")
            elif ch.isdecimal():
                out.append(f"!{ch}")
            else:
                out.append(ch)
        return "".join(out)

    @staticmethod
    def translate(encoded: str) -> str:
        if not encoded:
            return ""
        i = 0
        out = []
        special_keys = sorted(ANL.reversed_special_char_map.keys(), key=len, reverse=True)
        while i < len(encoded):
            matched = False
            for k in special_keys:
                if encoded.startswith(k, i):
                    out.append(ANL.reversed_special_char_map[k])
                    i += len(k)
                    matched = True
                    break
            if matched:
                continue
            ch = encoded[i]
            if ch in ("$", "!"):
                if i + 1 < len(encoded):
                    out.append(encoded[i + 1])
                    i += 2
                else:
                    i += 1
                continue
            if ch == "U":
                start = i + 1
                dot = encoded.find(".", start)
                if dot == -1:
                    break
                token = encoded[start:dot]
                i = dot + 1
                try:
                    num = int(token)
                    out.append(chr(num + 64))
                except ValueError:
                    pass
                continue
            dot = encoded.find(".", i)
            if dot == -1:
                out.append(encoded[i:])
                break
            token = encoded[i:dot]
            i = dot + 1
            if token == "":
                continue
            try:
                num = int(token)
                out.append(chr(num + 96))
            except ValueError:
                out.append(token)
        return "".join(out)

    @staticmethod
    def _generate_printable_key(length: int = 9) -> str:
        charset = string.ascii_letters + string.digits + "!@#$%&*-_"
        return "".join(secrets.choice(charset) for _ in range(max(1, int(length))))

    @staticmethod
    def generate_with_key(text: str, key_text: Optional[str] = None, key_length: int = 9) -> Dict[str, Any]:
        encoded = ANL.generate(text)
        enc_bits = ANL.Component.bits_from_text(encoded)
        if key_text is None:
            key_text = ANL._generate_printable_key(key_length)

        key_bits = ANL.Component.hmac_keystream_bits(key_text, len(enc_bits))
        secured_bits = "".join("1" if a != b else "0" for a, b in zip(enc_bits, key_bits))

        secured_bytes = ANL.Component.bytes_from_bits(secured_bits)
        key_bytes = ANL.Component.bytes_from_bits(key_bits)

        secured_b64 = base64.b64encode(secured_bytes).decode()
        key_b64 = base64.b64encode(key_bytes).decode()

        return {"secured_b64": secured_b64, "key_b64": key_b64, "key_text": key_text}

    @staticmethod
    def decrypt_from_object(obj: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(obj, dict):
            return {"error": "object must be a dict"}

        sb64 = obj.get("secured_b64") or ""
        kb64 = obj.get("key_b64") or ""
        # If caller provided key_text instead of key_b64, derive key bits from it
        key_text = obj.get("key_text")

        if not sb64:
            return {"error": "secured_b64 required"}
        try:
            secured_bytes = base64.b64decode(sb64)
        except Exception:
            return {"error": "invalid secured_b64"}

        if kb64:
            try:
                key_bytes = base64.b64decode(kb64)
            except Exception:
                return {"error": "invalid key_b64"}
            key_bits = ANL.Component.bits_from_bytes(key_bytes)
        elif key_text:
            secured_bits = ANL.Component.bits_from_bytes(secured_bytes)
            key_bits = ANL.Component.hmac_keystream_bits(key_text, len(secured_bits))
        else:
            return {"error": "key_b64 or key_text required"}

        secured_bits = ANL.Component.bits_from_bytes(secured_bytes)
        if len(secured_bits) != len(key_bits):
            return {"error": "length mismatch between secured and key bits"}

        recovered_bits = "".join("1" if a != b else "0" for a, b in zip(secured_bits, key_bits))
        recovered_spaced = " ".join(recovered_bits[i:i+8] for i in range(0, len(recovered_bits), 8)) if recovered_bits else ""
        recovered_encoded = binary_to_text(recovered_spaced)
        decoded = ANL.translate(recovered_encoded)
        return {"recovered_encoded": recovered_encoded, "decoded": decoded}


if __name__ == "__main__":
    # Example 1: basic encrypt / decrypt using key_b64 (recommended)
    sample = "Aditya Ray @ANL!"
    print("Original:", sample)

    obj = ANL.generate_with_key(sample, key_length=9)  # returns secured_b64, key_b64, key_text
    secured_b64 = obj["secured_b64"]
    key_b64 = obj["key_b64"]
    key_text = obj.get("key_text")

    print("\n--- Example 1 (use returned key_b64) ---")
    print("Secured (base64):", secured_b64)
    print("Key (base64):    ", key_b64)
    print("Optional key_text (seed):", key_text)

    # Decrypt using the key_b64
    dec = ANL.decrypt_from_object({"secured_b64": secured_b64, "key_b64": key_b64})
    print("Recovered encoded:", dec.get("recovered_encoded"))
    print("Decoded:", dec.get("decoded"))

    # Example 2: decrypt using key_text (module will derive keystream)
    print("\n--- Example 2 (derive keystream from key_text) ---")
    obj2 = ANL.generate_with_key("Hello ANL6", key_text=None, key_length=8)
    s_b64 = obj2["secured_b64"]
    k_text = obj2["key_text"]
    print("Secured (base64):", s_b64)
    print("Seed key_text:    ", k_text)

    # Decrypt by sending key_text (no key_b64). Module derives the same keystream.
    dec2 = ANL.decrypt_from_object({"secured_b64": s_b64, "key_text": k_text})
    print("Decoded:", dec2.get("decoded"))

    # Example 3: quick stdin CLI (encrypt)
    try:
        user = input("\nEnter text to encrypt (or press Enter to skip CLI demo): ").strip()
        if user:
            out = ANL.generate_with_key(user, key_length=9)
            print("\nEncrypted (secured_b64):", out["secured_b64"])
            print("Key (key_b64):           ", out["key_b64"])
            print("Keep both secure. Use them to decrypt with ANL.decrypt_from_object({...}).")
    except KeyboardInterrupt:
        print("\nCLI demo aborted by user.")
