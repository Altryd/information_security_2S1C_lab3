from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from tqdm import tqdm
import os
import pickle
import json
import argparse


# симметричный алгоритм - chacha20 (256 бит ключ, 128 доп.ключ)
# ассиметричный - RSA
def generate_keys(encrypted_symmetrical_key_path: str, open_asymmetric_key_path: str,
                  private_asymmetric_key_path: str) -> None:
    # генерация ключа симметричного шифрования
    symmetrical_key = ChaCha20Poly1305.generate_key()

    # генерация ключей асимметричного шифрование
    keys = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = keys

    # сериализация ключей асимметричного шифрования:
    # закрытый ключ
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(private_asymmetric_key_path, 'wb') as key_file:
        key_file.write(pem_private)

    # открытый ключ
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


def decrypt_text_file(encrypted_text_file_path: str, private_asymmetric_key_path: str,
                      encrypted_symmetrical_key_path: str,
                      save_to_path: str) -> None:

    symmetrical_key = decrypt_symmetrical_key(encrypted_symmetrical_key_path, private_asymmetric_key_path)
    with open(encrypted_text_file_path, 'rb') as key_file:
        cipher_data = pickle.load(key_file)
    nonce = cipher_data['nonce']
    ciphertext = cipher_data['ciphertext']
    algorithm = algorithms.ChaCha20(symmetrical_key, nonce)
    cipher = Cipher(algorithm, mode=None)
    decryptor = cipher.decryptor()
    dc_text = decryptor.update(ciphertext) + decryptor.finalize()
    with open(save_to_path, 'w', encoding='utf-8') as file:
        file.write(dc_text.decode('utf-8'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='main.py')
    parser.add_argument(
        '-i',
        '-inputsettings',
        type=str,
        help='Аргумент, указывающий путь к файлу, в котором содержатся настройки',
        required=True,
        dest='file_input')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-enc', '--encryption', help='Запускает режим шифрования', dest='encryption')
    group.add_argument('-dec', '--decryption', help='Запускает режим дешифрования', dest='decryption')
    args = parser.parse_args()
    read_data_from = os.path.realpath(args.file_input)
    try:
        with open(read_data_from) as fp:
            json_data = json.load(fp)
        json_needed_extension = {
            'initial_file': '.txt',
            "encrypted_file": '.txt',
            "decrypted_file": '.txt',
            "symmetric_key": '.txt',
            "public_key": '.pem',
            "secret_key": '.pem'
        }
        if args.encryption is not None:
            for key, value in json_data.items():
                filename, file_extension = os.path.splitext(value)
                if file_extension != json_needed_extension[key]:
                    print("Settings file is incorrect - invalid extensions in files, try again")
                    raise SystemExit(1)
            with tqdm(range(2), desc='Генерируем ключи системы') as progressbar:
                generate_keys(json_data['symmetric_key'],
                              json_data['public_key'],
                              json_data['secret_key'])
                progressbar.update(1)
                progressbar.set_description('Зашифровываем текстовый файл')
                encrypt_text_file(json_data['initial_file'],
                                  json_data['secret_key'],
                                  json_data['symmetric_key'],
                                  json_data['encrypted_file'])
                progressbar.update(1)
            print('\nФайл был успешно зашифрован')
        else:
            for key, value in json_data.items():
                filename, file_extension = os.path.splitext(value)
                if file_extension != json_needed_extension[key]:
                    print("Settings file is incorrect - invalid extensions in files, try again")
                    raise SystemExit(1)
            with tqdm(range(1), desc='Расшифровываем файл') as progressbar:
                decrypt_text_file(json_data['encrypted_file'],
                                  json_data['secret_key'],
                                  json_data['symmetric_key'],
                                  json_data['decrypted_file'])
                progressbar.update(1)
            print('Файл был успешно расшифрован')
    except:
        print("Произошла критическая ошибка при выполнении программы, проверьте путь к файлу настроек и его содержание")
