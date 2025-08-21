# ANL.py
import secrets
import string
import json
from typing import Dict, Optional, Tuple, Any


def text_to_binary(text: str, spaced: bool = True) -> str:
    """
    Convert text to binary. If spaced=True returns bytes separated by spaces.
    """
    if text is None or text == "":
        return ""
    bits = "".join(format(ord(c), "08b") for c in text)
    if spaced:
        return " ".join(bits[i : i + 8] for i in range(0, len(bits), 8))
    return bits


def binary_to_text(binary: str) -> str:
    """
    Convert binary string (spaced or contiguous) back to text.
    If binary contains non-0/1 chars they are ignored except spaces.
    """
    if binary is None or binary == "":
        return ""
    bits = "".join(ch for ch in binary if ch in "01")
    if len(bits) % 8 != 0:
        pad = 8 - (len(bits) % 8)
        bits = ("0" * pad) + bits
    return "".join(chr(int(bits[i : i + 8], 2)) for i in range(0, len(bits), 8))


class ANL:
    """
    ANL main class (module).
    Public API (static methods):
      - generate(text) -> encoded ANL string
      - translate(encoded) -> decoded plain text
      - generate_random_key_text(length=9) -> random key string
      - generate_with_key(text, key_text=None, key_length=9, mode='add') -> dict result
      - decrypt_from_object(obj, mode='add') -> dict result
      - save_object(obj, filename)
      - load_object(filename)
    Mixing modes supported:
      - 'add' : integer addition of binary integers (encoded_int + key_int)
      - 'xor' : XOR stream of key bits repeated to match length
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

    # ---------- Core encode / decode ----------
    @staticmethod
    def generate(text: str) -> str:
        """
        Encode text into ANL encoded string.
        Lowercase -> number + '.' ; Uppercase -> 'U' + number + '.'
        Special chars mapped by special_char_map
        digits are encoded as $<digit> and !<digit> (kept as-is)
        """
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
                # If unknown char, preserve as-is (safer) or map to underscore token
                out.append(ch)
        return "".join(out)

    @staticmethod
    def translate(encoded: str) -> str:
        """
        Decode an ANL encoded string back to plain text.
        Handles special tokens (longest-first), $ / ! digit markers, U uppercase tokens,
        and simple numeric tokens ending with '.' for lowercase letters.
        """
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
                # no dot found, treat rest as literal
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
                # token wasn't a number: append as literal text (fallback)
                out.append(token)
        return "".join(out)

    # ---------- Internal binary helpers ----------
    @staticmethod
    def _text_bits_to_int_and_bits(text: str) -> Tuple[int, str]:
        """
        Convert a text string into (int_value, contiguous_bits_string).
        If text empty returns (0, "").
        """
        bits = text_to_binary(text, spaced=False)
        if bits == "":
            return 0, ""
        return int(bits, 2), bits

    @staticmethod
    def _int_to_spaced_binary_str(n: int) -> str:
        """
        Convert integer n to spaced 8-bit binary string.
        If n==0 returns "00000000".
        """
        if n == 0:
            return "00000000"
        bits = bin(n)[2:]
        pad = (-len(bits)) % 8
        if pad:
            bits = ("0" * pad) + bits
        return " ".join(bits[i : i + 8] for i in range(0, len(bits), 8))

    @staticmethod
    def _repeat_to_length(s: str, length: int) -> str:
        if not s:
            return "0" * length
        reps = (length + len(s) - 1) // len(s)
        return (s * reps)[:length]

    # ---------- Key generation ----------
    @staticmethod
    def generate_random_key_text(length: int = 9) -> str:
        charset = string.ascii_letters + string.digits + string.punctuation
        return "".join(secrets.choice(charset) for _ in range(max(1, int(length))))

    # ---------- Mixing implementations ----------
    @staticmethod
    def _mix_add_mode(encoded_text: str, key_text: str) -> Dict[str, Any]:
        enc_int, enc_bits = ANL._text_bits_to_int_and_bits(encoded_text)
        key_int, key_bits = ANL._text_bits_to_int_and_bits(key_text)
        secured_int = enc_int + key_int
        return {
            "encoded_int": enc_int,
            "encoded_bits": enc_bits,
            "key_int": key_int,
            "key_bits": key_bits,
            "secured_int": secured_int,
            "secured_binary": ANL._int_to_spaced_binary_str(secured_int),
        }

    @staticmethod
    def _mix_xor_mode(encoded_text: str, key_text: str) -> Dict[str, Any]:
        enc_bits_spaced = text_to_binary(encoded_text, spaced=True)
        enc_bits = enc_bits_spaced.replace(" ", "")
        key_bits_spaced = text_to_binary(key_text, spaced=True)
        key_bits = key_bits_spaced.replace(" ", "")
        if enc_bits == "":
            xor_bits = ""
        else:
            stream = ANL._repeat_to_length(key_bits, len(enc_bits))
            xor_list = [
                str(int(a) ^ int(b)) for a, b in zip(enc_bits, stream)
            ]
            xor_bits = "".join(xor_list)
        secured_binary_spaced = " ".join(xor_bits[i : i + 8] for i in range(0, len(xor_bits), 8)) if xor_bits else ""
        return {
            "encoded_bits": enc_bits,
            "key_bits": key_bits,
            "secured_bits": xor_bits,
            "secured_binary": secured_binary_spaced,
        }

    # ---------- Public secure API ----------
    @staticmethod
    def generate_with_key(
        text: str, key_text: Optional[str] = None, key_length: int = 9, mode: str = "add"
    ) -> Dict[str, Any]:
        """
        Create a secure object from plain text.
        mode: 'add' (integer addition) or 'xor' (stream XOR).
        Returns a dict containing original, encoded, encoded_binary, key_text, key_binary, secured_binary, mode.
        """
        encoded = ANL.generate(text)
        if key_text is None:
            key_text = ANL.generate_random_key_text(key_length)
        result: Dict[str, Any] = {
            "original": text,
            "encoded": encoded,
            "mode": mode,
        }
        if mode == "add":
            mix = ANL._mix_add_mode(encoded, key_text)
            result.update(
                {
                    "encoded_binary": ANL._int_to_spaced_binary_str(mix["encoded_int"]),
                    "key_text": key_text,
                    "key_binary": ANL._int_to_spaced_binary_str(mix["key_int"]),
                    "secured_binary": mix["secured_binary"],
                }
            )
        elif mode == "xor":
            mix = ANL._mix_xor_mode(encoded, key_text)
            result.update(
                {
                    "encoded_binary": " ".join(mix["encoded_bits"][i : i + 8] for i in range(0, len(mix["encoded_bits"]), 8))
                    if mix["encoded_bits"]
                    else "",
                    "key_text": key_text,
                    "key_binary": " ".join(mix["key_bits"][i : i + 8] for i in range(0, len(mix["key_bits"]), 8))
                    if mix["key_bits"]
                    else "",
                    "secured_binary": mix["secured_binary"],
                }
            )
        else:
            raise ValueError("mode must be 'add' or 'xor'")
        return result

    @staticmethod
    def decrypt_from_object(obj: Dict[str, Any], mode: Optional[str] = None) -> Dict[str, Any]:
        """
        Given an object produced by generate_with_key (or equivalent),
        decrypt and return {'recovered_encoded': ..., 'decoded': ...}.
        If mode not provided, uses obj['mode'].
        """
        if not isinstance(obj, dict):
            return {"error": "object must be a dict returned from generate_with_key"}
        if mode is None:
            mode = obj.get("mode", "add")
        key_text = obj.get("key_text")
        secured_binary = obj.get("secured_binary")
        if key_text is None or secured_binary is None:
            return {"error": "object must contain 'key_text' and 'secured_binary'"}
        if mode == "add":
            key_int, _ = ANL._text_bits_to_int_and_bits(key_text)
            bits = "".join(ch for ch in secured_binary if ch in "01")
            if bits == "":
                return {"error": "secured_binary empty or invalid"}
            secured_int = int(bits, 2)
            orig_int = secured_int - key_int
            if orig_int < 0:
                return {"error": "invalid key or corrupted data (negative result)"}
            orig_spaced = ANL._int_to_spaced_binary_str(orig_int)
            recovered_encoded = binary_to_text(orig_spaced)
            decoded = ANL.translate(recovered_encoded)
            return {"recovered_encoded": recovered_encoded, "decoded": decoded}
        elif mode == "xor":
            key_bits = text_to_binary(key_text, spaced=False)
            secured_bits = "".join(ch for ch in secured_binary if ch in "01")
            if secured_bits == "":
                return {"error": "secured_binary empty or invalid"}
            stream = ANL._repeat_to_length(key_bits, len(secured_bits))
            xor_list = [str(int(a) ^ int(b)) for a, b in zip(secured_bits, stream)]
            recovered_bits = "".join(xor_list)
            recovered_spaced = " ".join(recovered_bits[i : i + 8] for i in range(0, len(recovered_bits), 8))
            recovered_encoded = binary_to_text(recovered_spaced)
            decoded = ANL.translate(recovered_encoded)
            return {"recovered_encoded": recovered_encoded, "decoded": decoded}
        else:
            return {"error": "mode must be 'add' or 'xor'"}

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
    # demo CLI usage
    print("ANL module demo")
    sample = "Aditya Ray @ANL!"
    print("Original:", sample)
    obj_add = ANL.generate_with_key(sample, key_length=9, mode="add")
    print("\nMODE = add")
    print("Encoded:", obj_add["encoded"])
    print("Encoded binary:", obj_add["encoded_binary"])
    print("Key text:", obj_add["key_text"])
    print("Key binary:", obj_add["key_binary"])
    print("Secured binary:", obj_add["secured_binary"])
    dec_add = ANL.decrypt_from_object(obj_add)
    print("Recovered encoded:", dec_add.get("recovered_encoded"))
    print("Decoded:", dec_add.get("decoded"))

    obj_xor = ANL.generate_with_key(sample, key_length=12, mode="xor")
    print("\nMODE = xor")
    print("Encoded:", obj_xor["encoded"])
    print("Encoded binary:", obj_xor["encoded_binary"])
    print("Key text:", obj_xor["key_text"])
    print("Key binary:", obj_xor["key_binary"])
    print("Secured binary:", obj_xor["secured_binary"])
    dec_xor = ANL.decrypt_from_object(obj_xor, mode="xor")
    print("Recovered encoded:", dec_xor.get("recovered_encoded"))
    print("Decoded:", dec_xor.get("decoded"))
