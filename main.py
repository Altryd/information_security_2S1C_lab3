import json

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os
import pickle


# симметричный алгоритм - chacha20 (256 бит ключ, 192 доп.ключ)
# ассиметричный - RSA

def generate_keys(encrypted_symmetrical_key_path: str, open_asymmetric_key_path: str,
                  private_asymmetric_key_path: str) -> None:
    # генерация ключа симметричного шифрования
    symmetrical_key = ChaCha20Poly1305.generate_key()

    # генерация ключей асимметричного шифрование
    keys = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = keys
    public_key = keys.public_key()

    # сериализация ключей асимметричного шифрования
    pem_private = keys.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(private_asymmetric_key_path, 'wb') as key_file:
        key_file.write(pem_private)

    public_key = keys.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(open_asymmetric_key_path, 'wb') as key_file:
        key_file.write(pem_public)

    # шифрование ключа симметричного алгоритма
    encrypted_symmetrical_key = public_key.encrypt(
        symmetrical_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # сериализация ключа симмеричного алгоритма в файл
    with open(encrypted_symmetrical_key_path, 'wb') as key_file:
        key_file.write(encrypted_symmetrical_key)

    """
    with open(encrypted_symmetrical_key_path, 'rb') as key_file:
        ciphertext = key_file.read()
    расшифровка ключа симметричного алгоритма
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    if plaintext == symmetrical_key:
        print('gotovo')
        
    """


    """
    with open(private_key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
        print(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                                        encryption_algorithm=serialization.NoEncryption()))

    with open(open_key_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
        print(public_key.public_bytes(
              encoding=serialization.Encoding.PEM,
              format=serialization.PublicFormat.SubjectPublicKeyInfo))
    """
    # with open(open_key_path, 'wb') as key_file:
    # key_file.write()


def decrypt_symmetrical_key(encrypted_symmetrical_key_path: str, private_asymmetric_key_path: str) -> bytes:
    with open(encrypted_symmetrical_key_path, 'rb') as key_file:
        encrypted_symmetrical_key = key_file.read()
    with open(private_asymmetric_key_path, 'rb') as key_file:
        private_asymmetric_key = serialization.load_pem_private_key(key_file.read(), password=None)
    # расшифровка ключа симметричного алгоритма
    symmetrical_key = private_asymmetric_key.decrypt(
        encrypted_symmetrical_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return symmetrical_key


def encrypt_text_file(text_file_path: str, private_asymmetric_key_path: str,
                      encrypted_symmetrical_key_path: str, save_to_path: str,
                      ) -> None:

    symmetrical_key = decrypt_symmetrical_key(encrypted_symmetrical_key_path, private_asymmetric_key_path)
    with open(text_file_path, 'r', encoding='utf-8') as key_file:
        text = key_file.read()
    nonce = os.urandom(16)
    algorithm = algorithms.ChaCha20(symmetrical_key, nonce)
    cipher = Cipher(algorithm, mode=None)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(bytes(text, 'UTF-8'))
    result = {'nonce': nonce, 'ciphertext': ciphertext}
    with open(save_to_path, 'wb') as key_file:
        pickle.dump(result, key_file)
    #with open(save_to_path, 'rb') as key_file:
        #ct = key_file.read()
        #decryptor = cipher.decryptor()
        #print(decryptor.update(ct).decode('utf-8'))
    #with open(nonce_file_path, 'wb') as key_file:
    #    key_file.write(nonce)
"""
    cipher = ChaCha20.new(key=key)
    >> > ciphertext = cipher.encrypt(plaintext)
    >> >
    >> > nonce = b64encode(cipher.nonce).decode('utf-8')
    >> > ct = b64encode(ciphertext).decode('utf-8')
    >> > result = json.dumps({'nonce': nonce, 'ciphertext': ct})
    >> > print(result)
"""


"""
    Расшифровка
    with open(save_to_path, 'rb') as key_file:
        cyphertext = key_file.read()


    decryptor = cipher.decryptor()
    dc_text = decryptor.update(cyphertext) + decryptor.finalize()
    print(dc_text.decode('utf-8'))
"""

    # c = encryptor.update(b"a secret message")

    # decryptor = cipher.decryptor()
    # decryptor.update(ct)


def decrypt_text_file(encrypted_text_file_path: str, private_asymmetric_key_path: str,
                      encrypted_symmetrical_key_path: str,
                      save_to_path: str) -> None:

    symmetrical_key = decrypt_symmetrical_key(encrypted_symmetrical_key_path, private_asymmetric_key_path)
    with open(encrypted_text_file_path, 'rb') as key_file:
        cipherdata = pickle.load(key_file)
    nonce = cipherdata['nonce']
    ciphertext = cipherdata['ciphertext']
    algorithm = algorithms.ChaCha20(symmetrical_key, nonce)
    cipher = Cipher(algorithm, mode=None)
    decryptor = cipher.decryptor()
    dc_text = decryptor.update(ciphertext) + decryptor.finalize()
    with open(save_to_path, 'w') as file:
        file.write(dc_text.decode('utf-8'))


if __name__ == '__main__':
   generate_keys(r'C:\Users\Altryd\PycharmProjects\information_security_2S1C_lab3\symmetrical.txt',
                 r'C:\Users\Altryd\PycharmProjects\information_security_2S1C_lab3\open_key.pem',
                 r'C:\Users\Altryd\PycharmProjects\information_security_2S1C_lab3\private_key.pem')
   encrypt_text_file(r"C:\Users\Altryd\PycharmProjects\information_security_2S1C_lab3\tenshi.txt",
                     r'C:\Users\Altryd\PycharmProjects\information_security_2S1C_lab3\private_key.pem',
                     r'C:\Users\Altryd\PycharmProjects\information_security_2S1C_lab3\symmetrical.txt',
                     r"C:\Users\Altryd\PycharmProjects\information_security_2S1C_lab3\tenshi_encrypt.pickle")
   decrypt_text_file(r"C:\Users\Altryd\PycharmProjects\information_security_2S1C_lab3\tenshi_encrypt.pickle",
                     r'C:\Users\Altryd\PycharmProjects\information_security_2S1C_lab3\private_key.pem',
                     r'C:\Users\Altryd\PycharmProjects\information_security_2S1C_lab3\symmetrical.txt',
                     r"C:\Users\Altryd\PycharmProjects\information_security_2S1C_lab3\tenshi_rashifr.txt")