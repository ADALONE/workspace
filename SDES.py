from flask import Flask, render_template_string, request

app = Flask(__name__)

# Your Python functions
def permute(original, permutation_table):
    return ''.join(original[i - 1] for i in permutation_table)

def left_shift(key, shifts):
    return key[shifts:] + key[:shifts]

def xor(bits1, bits2):
    return ''.join('1' if b1 != b2 else '0' for b1, b2 in zip(bits1, bits2))

def sbox_lookup(input_bits, sbox):
    row = int(input_bits[0] + input_bits[3], 2)
    col = int(input_bits[1] + input_bits[2], 2)
    return format(sbox[row][col], '02b')

def f_k(bits, key):
    EP = [4, 1, 2, 3, 2, 3, 4, 1]
    S0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
    S1 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]
    P4 = [2, 4, 3, 1]
    left_half = bits[:4]
    right_half = bits[4:]
    right_expanded = permute(right_half, EP)
    xor_result = xor(right_expanded, key)
    left_xor = xor_result[:4]
    right_xor = xor_result[4:]
    s0_result = sbox_lookup(left_xor, S0)
    s1_result = sbox_lookup(right_xor, S1)
    combined_sbox = s0_result + s1_result
    p4_result = permute(combined_sbox, P4)
    result = xor(left_half, p4_result)
    return result + right_half

def sdes_key_generation(original_key):
    P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    P8 = [6, 3, 7, 4, 8, 5, 10, 9]
    key_p10 = permute(original_key, P10)
    left_half = key_p10[:5]
    right_half = key_p10[5:]
    left_half_shifted = left_shift(left_half, 1)
    right_half_shifted = left_shift(right_half, 1)
    combined_key1 = left_half_shifted + right_half_shifted
    K1 = permute(combined_key1, P8)
    left_half_shifted_2 = left_shift(left_half_shifted, 2)
    right_half_shifted_2 = left_shift(right_half_shifted, 2)
    combined_key2 = left_half_shifted_2 + right_half_shifted_2
    K2 = permute(combined_key2, P8)
    return K1, K2

def sdes_encrypt(plaintext, original_key):
    IP = [2, 6, 3, 1, 4, 8, 5, 7]
    IP_inv = [4, 1, 3, 5, 7, 2, 8, 6]
    K1, K2 = sdes_key_generation(original_key)
    permuted_text = permute(plaintext, IP)
    first_round = f_k(permuted_text, K1)
    swapped = first_round[4:] + first_round[:4]
    second_round = f_k(swapped, K2)
    ciphertext = permute(second_round, IP_inv)
    return ciphertext

def sdes_decrypt(ciphertext, original_key):
    IP = [2, 6, 3, 1, 4, 8, 5, 7]
    IP_inv = [4, 1, 3, 5, 7, 2, 8, 6]
    K1, K2 = sdes_key_generation(original_key)
    permuted_text = permute(ciphertext, IP)
    first_round = f_k(permuted_text, K2)
    swapped = first_round[4:] + first_round[:4]
    second_round = f_k(swapped, K1)
    plaintext = permute(second_round, IP_inv)
    return plaintext

# Flask routes
@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        original_key = request.form['original_key']
        plaintext = request.form['plaintext']
        ciphertext = sdes_encrypt(plaintext, original_key)
        decrypted_text = sdes_decrypt(ciphertext, original_key)
        result = {
            'ciphertext': ciphertext,
            'decrypted_text': decrypted_text
        }
    
    return render_template_string('''
    <html>
        <body>
            <h2>SDES Encryption and Decryption</h2>
            <form method="POST">
                <label for="original_key">Enter a 10-bit key:</label><br>
                <input type="text" id="original_key" name="original_key" required><br><br>
                
                <label for="plaintext">Enter an 8-bit plaintext:</label><br>
                <input type="text" id="plaintext" name="plaintext" required><br><br>
                
                <input type="submit" value="Encrypt and Decrypt">
            </form>
            {% if result %}
                <h3>Results:</h3>
                <p><strong>Ciphertext:</strong> {{ result.ciphertext }}</p>
                <p><strong>Decrypted Text:</strong> {{ result.decrypted_text }}</p>
            {% endif %}
        </body>
    </html>
    ''', result=result)

if __name__ == '__main__':
    app.run(debug=True)
