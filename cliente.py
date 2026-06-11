import socket
import threading

def rsa_modular_exponentiation(message, exponent, modulus):
    result = 1
    message = message % modulus
    while exponent > 0:
        if exponent & 1:
            result = (result * message) % modulus
        message = (message * message) % modulus
        exponent = exponent // 2
    return result

def modular_inverse(public_exponent, totient):
    m0, y, x = totient, 0, 1
    if totient == 1: return 0
    while public_exponent > 1:
        q = public_exponent // totient
        t = totient
        totient = public_exponent % totient
        public_exponent = t
        t = y
        y = x - q * y
        x = t
    if x < 0: x = x + m0
    return x

def greatest_common_divisor(x, y):
    while y != 0:
        x, y = y, x % y
    return x

def generate_rsa_keys(prime_p, prime_q):
    modulus = prime_p * prime_q
    totient = (prime_p - 1) * (prime_q - 1)
    public_exponent = 0
    for public_exponent in range(2, totient):
        if greatest_common_divisor(public_exponent, totient) == 1:
            break
    private_exponent = modular_inverse(public_exponent, totient)
    return public_exponent, private_exponent, modulus

def encrypt_message(message, public_exponent, modulus):
    if isinstance(message, str):
        message_bytes = message.encode('utf-8')
        message_int = int.from_bytes(message_bytes, byteorder='big')
    else:
        message_int = message

    if message_int >= modulus:
        raise ValueError('Mensagem muito grande para os primos escolhidos! Use primos maiores.')
    return rsa_modular_exponentiation(message_int, public_exponent, modulus)

def decrypt_message(ciphertext, private_exponent, modulus):
    decrypted_int = rsa_modular_exponentiation(ciphertext, private_exponent, modulus)
    try:
        num_bytes = (decrypted_int.bit_length() + 7) // 8
        num_bytes = max(1, num_bytes) 
        decrypted_bytes = decrypted_int.to_bytes(num_bytes, byteorder='big')
        return decrypted_bytes.decode('utf-8')
    except Exception:
        return 'Erro ao decodificar os bytes para string.'

PRIMO_P = 99971
PRIMO_Q = 90067

meu_e, meu_d, meu_n = generate_rsa_keys(PRIMO_P, PRIMO_Q)

HOST = '127.0.0.1'
PORT = 65432

cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
cliente.connect((HOST, PORT))
print("[*] Conectado ao Terminal A!")

dados_chave_servidor = cliente.recv(1024).decode('utf-8')
servidor_e, servidor_n = map(int, dados_chave_servidor.split(','))
cliente.send(f"{meu_e},{meu_n}".encode('utf-8'))

print("[*] Chaves trocadas! Chat criptografado pronto.\n" + "-"*40)

def receber():
    while True:
        try:
            dados = cliente.recv(4096).decode('utf-8')
            if not dados: break
            
            num_cifrado = int(dados)
            texto_decifrado = decrypt_message(num_cifrado, meu_d, meu_n)
            print(f"\n[Terminal A]: {texto_decifrado}")
        except:
            print("\n[*] Conexão encerrada.")
            break

threading.Thread(target=receber, daemon=True).start()

while True:
    try:
        texto = input()
        if texto.lower() == 'sair': break
        if not texto: continue

        num_cifrado = encrypt_message(texto, servidor_e, servidor_n)
        cliente.send(str(num_cifrado).encode('utf-8'))
    except ValueError as e:
        print(f"[ERRO]: {e}")
    except KeyboardInterrupt:
        break

cliente.close()