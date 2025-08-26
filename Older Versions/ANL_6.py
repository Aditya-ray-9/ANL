# ANL.py  (ANL6) - per-chunk key XOR (raw-char or derived keystream), compact outputs included
import secrets
import string
import json
import base64
import hashlib
import hmac
import math
from typing import Dict, Optional, Tuple, Any


def text_to_binary(text: str, spaced: bool = True) -> str:
    if text is None or text == "":
        return ""
    bits = "".join(format(ord(c), "08b") for c in text)
    if spaced:
        return " ".join(bits[i : i + 8] for i in range(0, len(bits), 8))
    return bits


def binary_to_text(binary: str) -> str:
    if binary is None or binary == "":
        return ""
    bits = "".join(ch for ch in binary if ch in "01")
    if len(bits) % 8 != 0:
        pad = 8 - (len(bits) % 8)
        bits = ("0" * pad) + bits
    return "".join(chr(int(bits[i : i + 8], 2)) for i in range(0, len(bits), 8))


class ANL:
    """
    ANL6: per-chunk XOR mixing using a short human key (key_text).
    - By default uses 'even' chunking: splits encoded-bitstream evenly across key chars.
    - Supports two keystream modes:
        - raw-char mode (default): each key char's 8-bit ASCII repeated/truncated per chunk.
        - derived mode: use HMAC-SHA256 (with key_text as secret) to derive a cryptographically-strong keystream per chunk.
    Public API (keeps previous function names for compatibility):
      - generate(text) -> encoded ANL string
      - translate(encoded) -> decoded plain text
      - generate_with_key(text, key_text=None, key_length=9, chunk_mode='even', derive_keystream=False) -> dict result
      - decrypt_from_object(obj) -> dict result
      - save_object(obj, filename), load_object(filename)
    """

    char_map = {chr(i): str(i - 96) + "." for i in range(97, 123)}
    char_map.update({chr(i): f"U{str(i - 64)}." for i in range(65, 91)})
    special_char_map = {
        "@": "_1_",
        "!": "_2_",
        "#": "_3_",
        "$": "_4_",
        "+": "__1__",
        "-": "__2__",
        "*": "__3__",
        "/": "__4__",
        "%": "__5__",
        "^": "__6__",
        "(": "_5_",
        ")": "_6_",
        "{": "_7_",
        "}": "_8_",
        "[": "_9_",
        "]": "_10_",
        "<": "_11_",
        ">": "_12_",
        ":": "_13_",
        ";": "_14_",
        "'": "_15_",
        '"': "_16_",
        "|": "_17_",
        ",": "_18_",
        "?": "_19_",
        ".": "_20_",
        "=": "_21_",
        "_": "_22_",
        "~": "_23_",
        "`": "_24_",
        " ": "__",
    }
    reversed_special_char_map = {v: k for k, v in special_char_map.items()}

    # ---------- core encode / decode ----------
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
        if encoded is None or encoded == "":
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

    # ---------- helpers ----------
    @staticmethod
    def _bits_normalize(s: str) -> str:
        return "".join(ch for ch in (s or "") if ch in "01")

    @staticmethod
    def _bits_to_spaced(bits: str) -> str:
        if not bits:
            return ""
        pad = (-len(bits)) % 8
        if pad:
            bits = ("0" * pad) + bits
        return " ".join(bits[i : i + 8] for i in range(0, len(bits), 8))

    @staticmethod
    def _bits_to_bytes(bits: str) -> bytes:
        if not bits:
            return b""
        pad = (-len(bits)) % 8
        if pad:
            bits = ("0" * pad) + bits
        nbytes = len(bits) // 8
        val = int(bits, 2)
        return val.to_bytes(nbytes, "big")

    @staticmethod
    def _bytes_to_bits(b: bytes) -> str:
        if not b:
            return ""
        return "".join(format(byte, "08b") for byte in b)

    # derive keystream for chunk using HMAC-SHA256 (expand as needed)
    @staticmethod
    def _derive_keystream_bits(key_text: str, chunk_index: int, length_bits: int) -> str:
        if length_bits <= 0:
            return ""
        key_bytes = (key_text or "").encode("utf-8")
        out_bytes = bytearray()
        counter = 0
        while len(out_bytes) * 8 < length_bits:
            msg = chunk_index.to_bytes(4, "big") + counter.to_bytes(4, "big")
            hm = hmac.new(key_bytes, msg, hashlib.sha256).digest()
            out_bytes.extend(hm)
            counter += 1
        bits = ANL._bytes_to_bits(bytes(out_bytes))[:length_bits]
        return bits

    # build keystream for a chunk from a single key char (raw-char mode)
    @staticmethod
    def _raw_char_keystream_bits(ch: str, length_bits: int) -> str:
        if length_bits <= 0:
            return ""
        base = format(ord(ch), "08b")
        reps = (length_bits + len(base) - 1) // len(base)
        return (base * reps)[:length_bits]

    # ---------- chunking helpers ----------
    @staticmethod
    def _chunk_indices_even(total_bits: int, key_len: int):
        if total_bits <= 0 or key_len <= 0:
            return []
        chunk_size = math.ceil(total_bits / key_len)
        indices = []
        for i in range(key_len):
            start = i * chunk_size
            end = min(start + chunk_size, total_bits)
            if start >= total_bits:
                break
            indices.append((start, end))
        return indices

    # ---------- Key generation ----------
    @staticmethod
    def _generate_printable_key(length: int = 9) -> str:
        charset = string.ascii_letters + string.digits + "!@#$%^&*()-_=+,.?/;:[]{}|"
        return "".join(secrets.choice(charset) for _ in range(max(1, int(length))))

    # ---------- Public secure API (ANL6) ----------
    @staticmethod
    def generate_with_key(
        text: str,
        key_text: Optional[str] = None,
        key_length: int = 9,
        chunk_mode: str = "even",
        derive_keystream: bool = False,
    ) -> Dict[str, Any]:
        """
        Create an encrypted object:
          - text -> ANL encoded -> encoded_binary (contiguous bits)
          - key_text: short printable key (length = key_length) or provided by user
          - chunk_mode: 'even' (default). (future: 'tokens')
          - derive_keystream: if True, keystream for each chunk is derived via HMAC-SHA256(key_text, chunk_index)
                               otherwise each chunk uses raw ASCII bits of corresponding key char.
        Returns a dict including:
          original, encoded, encoded_binary (spaced), key_text (if raw-char mode), key_binary (spaced),
          key_hex, key_b64, secured_binary (spaced), secured_b64, derive_keystream, chunk_mode.
        """
        encoded = ANL.generate(text)
        enc_bits = text_to_binary(encoded, spaced=False)
        L = len(enc_bits)

        if key_text is None:
            key_text = ANL._generate_printable_key(key_length)
        if not key_text:
            return {"error": "key_text generation failed"}

        # choose chunk indices
        if chunk_mode != "even":
            # for now only 'even' is implemented; keep fallback to even
            chunk_mode = "even"
        indices = ANL._chunk_indices_even(L, len(key_text))
        secured_bits_list = []
        key_bits_full = []

        for idx, (start, end) in enumerate(indices):
            chunk = enc_bits[start:end]
            clen = len(chunk)
            if clen == 0:
                continue
            if derive_keystream:
                kbits = ANL._derive_keystream_bits(key_text, idx, clen)
            else:
                # map key char: cycle key_text if fewer chunks than chars (but usually len(key_text) >= chunks)
                key_char = key_text[idx % len(key_text)]
                kbits = ANL._raw_char_keystream_bits(key_char, clen)
            # XOR chunk with kbits
            xor_chunk = "".join("1" if a != b else "0" for a, b in zip(chunk, kbits))
            secured_bits_list.append(xor_chunk)
            key_bits_full.append(kbits)

        secured_bits = "".join(secured_bits_list)
        key_bits = "".join(key_bits_full)

        # prepare outputs: spaced binary for readability, and compact base64 for easy copy
        secured_spaced = ANL._bits_to_spaced(secured_bits)
        key_spaced = ANL._bits_to_spaced(key_bits)
        encoded_spaced = ANL._bits_to_spaced(enc_bits)

        key_bytes = ANL._bits_to_bytes(key_bits) if key_bits else b""
        secured_bytes = ANL._bits_to_bytes(secured_bits) if secured_bits else b""

        key_hex = key_bytes.hex() if key_bytes else ""
        key_b64 = base64.b64encode(key_bytes).decode() if key_bytes else ""
        secured_b64 = base64.b64encode(secured_bytes).decode() if secured_bytes else ""

        result = {
            "original": text,
            "encoded": encoded,
            "encoded_binary": encoded_spaced,
            "key_text": key_text if not derive_keystream else key_text,
            "key_binary": key_spaced,
            "key_hex": key_hex,
            "key_b64": key_b64,
            "secured_binary": secured_spaced,
            "secured_b64": secured_b64,
            "derive_keystream": bool(derive_keystream),
            "chunk_mode": chunk_mode,
            "chunk_count": len(indices),
        }
        return result

    @staticmethod
    def decrypt_from_object(obj: Dict[str, Any]) -> Dict[str, Any]:
        """
        Decrypt object produced by generate_with_key (or similar structure).
        Accepts:
          - obj['secured_binary'] (spaced or contiguous) OR obj['secured_b64'] (base64)
          - obj['key_binary'] (spaced or contiguous) OR obj['key_b64'] (base64)
          - obj['key_text'] and obj['derive_keystream'] and obj['chunk_mode'] as used during generation
        Returns {'recovered_encoded', 'decoded'} or {'error': ...}
        """

        if not isinstance(obj, dict):
            return {"error": "object must be a dict returned from generate_with_key"}

        # prefer base64 inputs if provided
        secured_spaced = ""
        if obj.get("secured_b64"):
            try:
                secured_bytes = base64.b64decode(obj["secured_b64"])
                secured_spaced = ANL._bits_to_spaced(ANL._bytes_to_bits(secured_bytes))
            except Exception:
                return {"error": "invalid secured_b64"}
        else:
            secured_spaced = obj.get("secured_binary", "")

        key_spaced = ""
        if obj.get("key_b64"):
            try:
                key_bytes = base64.b64decode(obj["key_b64"])
                key_spaced = ANL._bits_to_spaced(ANL._bytes_to_bits(key_bytes))
            except Exception:
                return {"error": "invalid key_b64"}
        else:
            key_spaced = obj.get("key_binary", "")

        derive_keystream = bool(obj.get("derive_keystream", False))
        chunk_mode = obj.get("chunk_mode", "even")
        key_text = obj.get("key_text", "")

        secured_bits = ANL._bits_normalize(secured_spaced)
        key_bits_provided = ANL._bits_normalize(key_spaced)

        # If user provided key_binary directly we can use it (fast path)
        if secured_bits == "" or key_bits_provided == "":
            return {"error": "secured_binary and key_binary (or base64 variants) are required"}

        if len(secured_bits) != len(key_bits_provided) and not derive_keystream:
            return {"error": "length mismatch between secured bits and provided key bits"}

        # If derive_keystream is True, we must rebuild per-chunk keystream using key_text and chunking
        if derive_keystream:
            # Need encoded length to compute chunk indices; derive from recovered bits length
            total_bits = len(secured_bits)
            if key_text is None or key_text == "":
                return {"error": "key_text required for derived keystream mode"}
            indices = ANL._chunk_indices_even(total_bits, len(key_text))
            key_bits_rebuilt_parts = []
            for idx, (start, end) in enumerate(indices):
                clen = end - start
                if clen <= 0:
                    continue
                kbits = ANL._derive_keystream_bits(key_text, idx, clen)
                key_bits_rebuilt_parts.append(kbits)
            key_bits_rebuilt = "".join(key_bits_rebuilt_parts)
            if len(key_bits_rebuilt) != len(secured_bits):
                return {"error": "internal error: derived keystream length mismatch"}
            key_bits_used = key_bits_rebuilt
        else:
            key_bits_used = key_bits_provided

        # XOR to recover original encoded bits
        recovered_bits = "".join(
            "1" if a != b else "0" for a, b in zip(secured_bits, key_bits_used)
        )

        recovered_spaced = ANL._bits_to_spaced(recovered_bits)
        recovered_encoded = binary_to_text(recovered_spaced)
        decoded = ANL.translate(recovered_encoded)
        return {"recovered_encoded": recovered_encoded, "decoded": decoded}

    # ---------- I/O helpers ----------
    @staticmethod
    def save_object(obj: Dict[str, Any], filename: str) -> None:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)

    @staticmethod
    def load_object(filename: str) -> Dict[str, Any]:
        with open(filename, "r", encoding="utf-8") as f:
            return json.load(f)


if __name__ == "__main__":
    print("note: it contains things made using an ai model(ChatGPT) ")
    sample = "Aditya Ray @ANL!"
    print("Original:", sample)
    # default: raw-char per-chunk XOR
    obj_raw = ANL.generate_with_key(sample, key_length=6, derive_keystream=False)
    print("\n--- RAW-CHAR CHUNKED MODE ---")
    print("Encoded:", obj_raw["encoded"])
    print("Encoded binary:", obj_raw["encoded_binary"])
    print("Key text:", obj_raw["key_text"])
    print("Key binary:", obj_raw["key_binary"])
    print("Secured binary:", obj_raw["secured_binary"])
    print("Secured (base64):", obj_raw["secured_b64"])
    dec_raw = ANL.decrypt_from_object(obj_raw)
    print("Decoded:", dec_raw.get("decoded"))


    print("[SERVER]: Another Method")
    # derived keystream mode: stronger keystream from short key_text
    obj_derived = ANL.generate_with_key(sample, key_text="mySecret!", key_length=8, derive_keystream=True)
    print("\n--- DERIVED KEYSTREAM MODE (HMAC-SHA256) ---")
    print("Encoded:", obj_derived["encoded"])
    print("Encoded binary:", obj_derived["encoded_binary"])
    print("Key text (seed):", obj_derived["key_text"])
    print("Key binary (derived):", obj_derived["key_binary"])
    print("Secured binary:", obj_derived["secured_binary"])
    print("Secured (base64):", obj_derived["secured_b64"])
    dec_derived = ANL.decrypt_from_object(obj_derived)
    print("Decoded:", dec_derived.get("decoded"))

    #   testing again :
    print("\n \n \n")
# End of ANL.py