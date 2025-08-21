# this is a moduled version of ANL
import random 


def text_to_binary(text):
    binary_result = ' '.join(format(ord(char), '08b') for char in text)
    return binary_result

def binary_to_text(binary):
    """
    Converts binary representation back to text.
    """
    n = 8
    return ''.join(chr(int(binary[i:i + n], 2)) for i in range(0, len(binary), n))
# main alpha logic
class Alpha :
    char_map = {chr(i): str(i-96) + '.' for i in range(97, 123)}  # a-z
    char_map.update({chr(i): str(i-64) + str(i-64) + '.' for i in range(65, 91)})  # A-Z
    special_char_map = {
        '@': '_1_', '!': '_2_', '#': '_3_', '$': '_4_',
        '+': '__1__', '-': '__2__', '*': '__3__', '/': '__4__',
        '%': '__5__', '^': '__6__', '(': '_5_', ')': '_6_',
        '{': '_7_', '}': '_8_', '[': '_9_', ']': '_10_',
        '<': '_11_', '>': '_12__', ':': '_13_', ';': '_14_',
        "'": '_15_', '"': '_16_', '|': '_17_', ',': '_18_',
        '?': '_19_', '.': '_20_', '=': '_21_', '_': '_22_',
        '~': '_23_', '`': '_24_', ' ': '..'
    }

    # modified Alpha generation
    def generate(string_base):
        output = []
        for char in string_base:
            if char in Alpha.char_map:
                output.append(Alpha.char_map[char])
            elif char in Alpha.special_char_map:
                output.append(Alpha.special_char_map[char])
            elif char.isdigit():
                output.append(f"${char}")
            elif char.isdecimal():
                output.append(f"!{char}")
            else :
                pass
        answer = "".join(output)
        return answer

# execution test
if __name__ == "__main__" :
    a = Alpha.generate("ADITYA")
    print(a, text_to_binary(a))
