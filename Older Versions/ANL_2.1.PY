import random

def text_to_binary(text):
    binary_result = ' '.join(format(ord(char), '08b') for char in text)
    return binary_result

def binary_to_text(binary):
    bits = binary.replace(" ", "")
    n = 8
    return ''.join(chr(int(bits[i:i + n], 2)) for i in range(0, len(bits), n))

class Alpha:
    char_map = {chr(i): str(i - 96) + '.' for i in range(97, 123)}
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
            else:
                pass
        return "".join(output)

    @staticmethod
    def translate(s):
        i = 0
        out = []
        special_keys = sorted(Alpha.reversed_special_char_map.keys(), key=len, reverse=True)
        while i < len(s):
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
            start = i
            dot_pos = s.find('.', start)
            if dot_pos == -1:
                break
            token = s[start:dot_pos]
            i = dot_pos + 1
            if not token:
                continue
            is_repetition = (len(token) % 2 == 0) and (token[:len(token)//2] * 2 == token)
            at_word_start = (start == 0) or (out and out[-1] == ' ')
            if is_repetition and at_word_start:
                try:
                    half = token[:len(token)//2]
                    idx = int(half)
                    out.append(chr(idx + 64))
                    continue
                except ValueError:
                    pass
            try:
                idx = int(token)
                out.append(chr(idx + 96))
            except ValueError:
                pass
        return "".join(out)

if __name__ == "__main__":
    temp = input("Enter text to encode: ")
    enc = Alpha.generate(temp)
    print("Encoded:", enc)
    print("As binary:", text_to_binary(enc))
    dec = Alpha.translate(enc)
    print("Decoded:", dec)
