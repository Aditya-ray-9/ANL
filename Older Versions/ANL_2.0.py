# fixed moduled version of ANL by chatgpt
import random

def text_to_binary(text):
    binary_result = ' '.join(format(ord(char), '08b') for char in text)
    return binary_result

def binary_to_text(binary):
    """
    Converts binary representation back to text.
    Accepts space-separated bytes (like text_to_binary output) or continuous bytes.
    """
    # remove spaces if present
    bits = binary.replace(" ", "")
    n = 8
    return ''.join(chr(int(bits[i:i + n], 2)) for i in range(0, len(bits), n))


class Alpha:
    # a-z -> "1." .. "26."
    char_map = {chr(i): str(i - 96) + '.' for i in range(97, 123)}
    # A-Z -> repeated number + '.' (design choice from original)
    char_map.update({chr(i): str(i - 64) + str(i - 64) + '.' for i in range(65, 91)})

    special_char_map = {
        '@': '_1_', '!': '_2_', '#': '_3_', '$': '_4_',
        '+': '__1__', '-': '__2__', '*': '__3__', '/': '__4__',
        '%': '__5__', '^': '__6__', '(': '_5_', ')': '_6_',
        '{': '_7_', '}': '_8_', '[': '_9_', ']': '_10_',
        '<': '_11_', '>': '_12__', ':': '_13_', ';': '_14_',
        "'": '_15_', '"': '_16_', '|': '_17_', ',': '_18_',
        '?': '_19_', '.': '_20_', '=': '_21_', '_': '_22_',
        '~': '_23_', '`': '_24_', ' ': '__'
    }

    reversed_special_char_map = {v: k for k, v in special_char_map.items()}

    def generate(self):
        """
        Takes a string as self (so you can call Alpha.generate("text")).
        Returns the encoded string.
        """
        output = []
        for char in self:
            if char in Alpha.char_map:
                output.append(Alpha.char_map[char])
            elif char in Alpha.special_char_map:
                output.append(Alpha.special_char_map[char])
            elif char.isdigit():         # digits encoded with a leading $
                output.append(f"${char}")
            elif char.isdecimal():       # redundant with isdigit for ASCII digits, but kept per original
                output.append(f"!{char}")
            else:
                # unknown char: leave as-is or skip
                pass
        return "".join(output)

    def translate(self):
        """
        Decode the encoded string back to normal text.
        It parses:
         - letter tokens that end with '.' (numbers for lower, repeated-number for upper),
         - special tokens like '__1__' (from reversed_special_char_map),
         - $n and !n digit markers.
        NOTE: because of the original encoding scheme, some tokens are ambiguous
        (e.g. '11.' could be lowercase 'k' (11) or uppercase 'A' (1 repeated)).
        This decoder prefers the "uppercase if token is exact repetition" rule:
          if token length is even and token == first_half * 2 --> uppercase.
        """
        s = self
        i = 0
        out = []

        # prepare special keys sorted by length desc so longest matches are checked first
        special_keys = sorted(Alpha.reversed_special_char_map.keys(), key=len, reverse=True)

        while i < len(s):
            # check special tokens (start with '_' or '__', etc.)
            matched = False
            for key in special_keys:
                if s.startswith(key, i):
                    out.append(Alpha.reversed_special_char_map[key])
                    i += len(key)
                    matched = True
                    break
            if matched:
                continue

            ch = s[i]
            # digit encodings
            if ch == '$':  # original code used "$<digit>"
                if i + 1 < len(s):
                    out.append(s[i + 1])
                    i += 2
                else:
                    i += 1
                continue
            if ch == '!':  # original code used "!<digit>"
                if i + 1 < len(s):
                    out.append(s[i + 1])
                    i += 2
                else:
                    i += 1
                continue

            # otherwise expect a number token that ends with '.'
            dot_pos = s.find('.', i)
            if dot_pos == -1:
                # nothing meaningful left; break to avoid infinite loop
                break

            token = s[i:dot_pos]  # digits (like '1', '11', '2626', etc.)
            i = dot_pos + 1  # move past the dot

            if not token:
                continue

            # prefer uppercase if token is an even-length repetition of its half
            if len(token) % 2 == 0:
                half = token[:len(token) // 2]
                if half * 2 == token:
                    # uppercase
                    try:
                        idx = int(half)
                        out.append(chr(idx + 64))
                        continue
                    except ValueError:
                        pass

            # otherwise treat as lowercase
            try:
                idx = int(token)
                out.append(chr(idx + 96))
            except ValueError:
                # unexpected token, skip
                pass

        return "".join(out)


# execution test
if __name__ == "__main__":
    temp = input("Enter text to encode: ")
    enc = Alpha.generate(temp)
    print("Encoded:", enc)
    print("As binary:", text_to_binary(enc))

    dec = Alpha.translate(enc)
    print("Decoded:", dec)
