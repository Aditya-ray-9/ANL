import random
import string


def text_to_binary(text):
    return ' '.join(format(ord(char), '08b') for char in text)

def binary_to_text(binary):
    bits = binary.replace(" ", "")
    n = 8
    return ''.join(chr(int(bits[i:i + n], 2)) for i in range(0, len(bits), n))

class Alpha:
    char_map = {chr(i): str(i - 96) + '.' for i in range(97, 123)}
    char_map.update({chr(i): f"U{str(i - 64)}." for i in range(65, 91)})
    special_char_map = {
        '@': '_1_', '!': '_2_', '#': '_3_', '$': '_4_',
        '+': '__1__', '-': '__2__', '*': '__3__', '/': '__4__',
        '%': '__5__', '^': '__6__', '(': '_5_', ')': '_6_',
        '{': '_7_', '}': '_8_', '[': '_9_', ']': '_10_',
        '<': '_11_', '>': '_12_', ':': '_13_', ';': '_14_',
        "'": '_15_', '"': '_16_', '|': '_17_', ',': '_18_',
        '?': '_19_', '.': '_20_', '=': '_21_', '_': '_22_',
        '~': '_23_', '`': '_24_', ' ': '__'
    }
    reversed_special_char_map = {v: k for k, v in special_char_map.items()}

    @staticmethod
    def generate(s):
        output = []
        for char in s:
            if char in Alpha.char_map:
                output.append(Alpha.char_map[char])
            elif char in Alpha.special_char_map:
                output.append(Alpha.special_char_map[char])
            elif char.isdigit():
                output.append(f"${char}")
            elif char.isdecimal():
                output.append(f"!{char}")
        return "".join(output)

    @staticmethod
    def translate(s):
        i = 0
        out = []
        special_keys = sorted(Alpha.reversed_special_char_map.keys(), key=len, reverse=True)
        while i < len(s):
            matched = False
            for keytok in special_keys:
                if s.startswith(keytok, i):
                    out.append(Alpha.reversed_special_char_map[keytok])
                    i += len(keytok)
                    matched = True
                    break
            if matched:
                continue
            ch = s[i]
            if ch == '$':
                if i + 1 < len(s):
                    out.append(s[i + 1])
                    i += 2
                else:
                    i += 1
                continue
            if ch == '!':
                if i + 1 < len(s):
                    out.append(s[i + 1])
                    i += 2
                else:
                    i += 1
                continue
            if ch == 'U':
                start = i + 1
                dot_pos = s.find('.', start)
                if dot_pos == -1:
                    break
                token = s[start:dot_pos]
                i = dot_pos + 1
                try:
                    idx = int(token)
                    out.append(chr(idx + 64))
                except ValueError:
                    pass
                continue
            start = i
            dot_pos = s.find('.', start)
            if dot_pos == -1:
                break
            token = s[start:dot_pos]
            i = dot_pos + 1
            if not token:
                continue
            try:
                idx = int(token)
                out.append(chr(idx + 96))
            except ValueError:
                pass
        return "".join(out)

def _shift_num_wrap(n, k):
    return ((n - 1 + k) % 26) + 1

def _unshift_num_wrap(n, k):
    return ((n - 1 - k) % 26) + 1

def apply_key_to_encoded(encoded, key):
    i = 0
    out = []
    special_keys = sorted(Alpha.reversed_special_char_map.keys(), key=len, reverse=True)
    while i < len(encoded):
        matched = False
        for keytok in special_keys:
            if encoded.startswith(keytok, i):
                out.append(keytok)
                i += len(keytok)
                matched = True
                break
        if matched:
            continue
        ch = encoded[i]
        if ch in ('$','!'):
            out.append(ch)
            if i + 1 < len(encoded):
                out.append(encoded[i+1])
                i += 2
            else:
                i += 1
            continue
        if ch == 'U':
            start = i + 1
            dot_pos = encoded.find('.', start)
            if dot_pos == -1:
                out.append('U')
                i += 1
                continue
            num = int(encoded[start:dot_pos])
            shifted = _shift_num_wrap(num, key)
            out.append(f"U{shifted}.")
            i = dot_pos + 1
            continue
        dot_pos = encoded.find('.', i)
        if dot_pos == -1:
            out.append(encoded[i:])
            break
        num = int(encoded[i:dot_pos])
        shifted = _shift_num_wrap(num, key)
        out.append(f"{shifted}.")
        i = dot_pos + 1
    return "".join(out)

def remove_key_from_encoded(encoded_shifted, key):
    i = 0
    out = []
    special_keys = sorted(Alpha.reversed_special_char_map.keys(), key=len, reverse=True)
    while i < len(encoded_shifted):
        matched = False
        for keytok in special_keys:
            if encoded_shifted.startswith(keytok, i):
                out.append(keytok)
                i += len(keytok)
                matched = True
                break
        if matched:
            continue
        ch = encoded_shifted[i]
        if ch in ('$','!'):
            out.append(ch)
            if i + 1 < len(encoded_shifted):
                out.append(encoded_shifted[i+1])
                i += 2
            else:
                i += 1
            continue
        if ch == 'U':
            start = i + 1
            dot_pos = encoded_shifted.find('.', start)
            if dot_pos == -1:
                out.append('U')
                i += 1
                continue
            num = int(encoded_shifted[start:dot_pos])
            unshifted = _unshift_num_wrap(num, key)
            out.append(f"U{unshifted}.")
            i = dot_pos + 1
            continue
        dot_pos = encoded_shifted.find('.', i)
        if dot_pos == -1:
            out.append(encoded_shifted[i:])
            break
        num = int(encoded_shifted[i:dot_pos])
        unshifted = _unshift_num_wrap(num, key)
        out.append(f"{unshifted}.")
        i = dot_pos + 1
    return "".join(out)

def generate_with_key(text, key=None):
    enc = Alpha.generate(text)
    if key is None:
        key = random.randint(9**9, 9**99)
    secured = apply_key_to_encoded(enc, key)
    secured_binary = text_to_binary(secured)
    return {
        "original": text,
        "encoded": enc,
        "key": key,
        "secured": secured,
        "secured_binary": secured_binary
    }

def decrypt_from_object(obj):
    if isinstance(obj, dict):
        key = obj.get("key")
        if key is None:
            return {"error": "missing key"}
        if "secured_binary" in obj and obj["secured_binary"]:
            recovered_str = binary_to_text(obj["secured_binary"])
        else:
            recovered_str = obj.get("secured", "")
    else:
        return {"error": "object must be a dict returned from generate_with_key"}
    recovered_unshifted = remove_key_from_encoded(recovered_str, key)
    decoded = Alpha.translate(recovered_unshifted)
    return {
        "recovered_encoded": recovered_unshifted,
        "decoded": decoded
    }

def random_key() :
    pass
if __name__ == "__main__":
    text = input("Enter text to encode: ")
    result = generate_with_key(text)
    print("Original:", result["original"])
    print("Encoded:", result["encoded"])
    print("Key (keep secret):", result["key"])
    print("Secured Encoded:", result["secured"])
    print("Secured Binary:", result["secured_binary"])
    demo = decrypt_from_object(result)
    print("Recovered Encoded after removing key:", demo["recovered_encoded"])
    print("Decoded text:", demo["decoded"])

