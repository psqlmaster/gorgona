import os
import socket
import struct
import base64
import hashlib
import time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class GorgonaSender:
    def __init__(self, node_host, node_port, sync_psk):
        self.host = node_host
        self.port = node_port
        self.psk = sync_psk

    @staticmethod
    def generate_key_pair():
        """
        Генерирует новую пару ключей RSA-2048.
        Возвращает (private_pem, public_pem, key_hash)
        """
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        public_key = private_key.public_key()
        pub_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Хеш публичного ключа (первые 8 байт SHA256 в Base64) — как в Gorgona
        pub_hash = base64.b64encode(hashlib.sha256(pub_der).digest()[:8]).decode('utf-8')
        
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        return priv_pem, pub_pem, pub_hash

    def send_alert(self, private_key_pem, message, unlock_at=0, expire_at=0):
        """
        Шифрует и отправляет сообщение в сеть.
        unlock_at/expire_at: Unix Timestamp (UTC)
        """
        try:
            # 1. Подготовка ключей
            priv_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
            pub_key = priv_key.public_key()
            
            pub_der = pub_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            pub_hash_b64 = base64.b64encode(hashlib.sha256(pub_der).digest()[:8]).decode('utf-8')

            # 2. Шифрование данных (AES-GCM)
            session_key = os.urandom(32)
            iv = os.urandom(12)
            aesgcm = AESGCM(session_key)
            # В Python AESGCM возвращает ciphertext + tag в одном блоке
            ciphertext_with_tag = aesgcm.encrypt(iv, message.encode('utf-8'), None)
            
            tag = ciphertext_with_tag[-16:]
            ciphertext = ciphertext_with_tag[:-16]

            # 3. Шифрование сессионного ключа (RSA-OAEP)
            encrypted_session_key = pub_key.encrypt(
                session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # 4. Формирование пакета
            # SEND|hash|unlock|expire|msg_b64|key_b64|iv_b64|tag_b64
            payload = (
                f"SEND|{pub_hash_b64}|{int(unlock_at)}|{int(expire_at)}|"
                f"{base64.b64encode(ciphertext).decode('utf-8')}|"
                f"{base64.b64encode(encrypted_session_key).decode('utf-8')}|"
                f"{base64.b64encode(iv).decode('utf-8')}|"
                f"{base64.b64encode(tag).decode('utf-8')}\x00"
            ).encode('utf-8')

            # 5. Сетевой обмен (Sync)
            with socket.create_connection((self.host, self.port), timeout=10) as sock:
                # L2 Auth
                auth_cmd = f"AUTH|{self.psk}|0|0|0".encode('utf-8')
                sock.sendall(struct.pack(">I", len(auth_cmd)) + auth_cmd)
                
                # Читаем ответ на AUTH (пропускаем его)
                resp_len_data = sock.recv(4)
                if not resp_len_data: return False
                alen = struct.unpack(">I", resp_len_data)[0]
                sock.recv(alen)

                # Отправляем основной пакет
                sock.sendall(struct.pack(">I", len(payload)) + payload)
                
                # Ждем подтверждения (OK: ...)
                resp_len_data = sock.recv(4)
                if resp_len_data:
                    rlen = struct.unpack(">I", resp_len_data)[0]
                    result = sock.recv(rlen).decode('utf-8')
                    return result
            
            return False

        except Exception as e:
            print(f"Gorgona Send Error: {e}")
            return False
