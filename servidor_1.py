import threading
import time
import requests
from flask import Flask, request, jsonify

def rsa_modular_exponentiation(message, exponent, modulus):
    result = 1
    message = message % modulus
    while exponent > 0:
        if exponent & 1: result = (result * message) % modulus
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
    while y != 0: x, y = y, x % y
    return x

def generate_rsa_keys(prime_p, prime_q):
    modulus = prime_p * prime_q
    totient = (prime_p - 1) * (prime_q - 1)
    public_exponent = 65537
    private_exponent = modular_inverse(public_exponent, totient)
    return public_exponent, private_exponent, modulus

def encrypt_message(message, public_exponent, modulus):
    if isinstance(message, str):
        mensagem_com_padding = f"START:{message}"
        message_bytes = mensagem_com_padding.encode('utf-8')
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
        decrypted_bytes = decrypted_int.to_bytes(num_bytes, byteorder='big')
        
        texto_sujo = decrypted_bytes.decode('utf-8', errors='ignore')
        
        if "START:" in texto_sujo:
            return texto_sujo.split("START:", 1)[1]
        
        return texto_sujo.strip()
    except Exception as e:
        return f'Erro ao decodificar os bytes: {str(e)}'

PRIMO_P = 7917210177204817354392263458471664648979437923128520344717778244309865160194258358194152591075588985530388375991329930985649302403529738345960035153181187
PRIMO_Q = 12328745139396164590855442566730055945087315531204081070264540474149884124380143510452663163641828389261926376580099101648993474483353766504535847004739631

meu_e, meu_d, meu_n = generate_rsa_keys(PRIMO_P, PRIMO_Q)
chave_publica_b = None
modulo_b = None

MINHA_PORTA = 5001
URL_WEBHOOK_DESTINO = "http://127.0.0.1:5002/webhook"

app = Flask(__name__)

@app.route('/webhook', methods=['POST'])
def receber_webhook():
    global chave_publica_b, modulo_b
    payload = request.get_json()
    tipo = payload.get('tipo')

    if tipo == 'troca_chave':
        chave_publica_b = int(payload['e'])
        modulo_b = int(payload['n'])
        return jsonify({"status": "chave_recebida", "e": meu_e, "n": meu_n}), 200

    elif tipo == 'mensagem':
        if 'conteudo' in payload:
            num_cifrado = int(payload['conteudo'])
            texto_decifrado = decrypt_message(num_cifrado, meu_d, meu_n)
            print(f"\n[Terminal B]: {texto_decifrado}")
        return jsonify({"status": "sucesso"}), 200

    return jsonify({"status": "invalido"}), 400

def rodar_servidor_flask():
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    app.run(port=MINHA_PORTA, debug=False, use_reloader=False)

def loop_envio():
    global chave_publica_b, modulo_b
    time.sleep(2)
    
    print("[*] Sincronizando chaves RSA via Webhook...")
    
    while not chave_publica_b:
        try:
            resposta = requests.post(URL_WEBHOOK_DESTINO, json={"tipo": "troca_chave", "e": meu_e, "n": meu_n}, timeout=2)
            if resposta.status_code == 200:
                dados = resposta.json()
                if 'e' in dados and 'n' in dados:
                    chave_publica_b = int(dados['e'])
                    modulo_b = int(dados['n'])
        except requests.exceptions.ConnectionError:
            pass
        
        if not chave_publica_b:
            time.sleep(1)

    print("[*] Conexão estabelecida! Chat criptografado pronto.\n" + "-"*40)

    while True:
        try:
            texto = input()
            if texto.lower() == 'sair': break
            if not texto: continue

            num_cifrado = encrypt_message(texto, chave_publica_b, modulo_b)
            requests.post(URL_WEBHOOK_DESTINO, json={"tipo": "mensagem", "conteudo": str(num_cifrado)})
        except Exception as e:
            print(f"[ERRO]: {e}")

if __name__ == '__main__':
    print(f"[*] Iniciando Terminal A na porta {MINHA_PORTA}...")
    threading.Thread(target=rodar_servidor_flask, daemon=True).start()
    loop_envio()