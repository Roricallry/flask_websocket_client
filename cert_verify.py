from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

def verify_cert_is_signed_by_ca(client_cert_pem: bytes, ca_cert_pem: bytes):
    """
    在客户端本地验证：client_cert 是否由 ca_cert 签发
    """
    # 加载客户端证书
    client_cert = x509.load_pem_x509_certificate(client_cert_pem)

    # 加载 CA（服务器）证书
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_public_key = ca_cert.public_key()

    try:
        # 用 CA 公钥验证客户端证书的签名
        ca_public_key.verify(
            client_cert.signature,
            client_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            client_cert.signature_hash_algorithm
        )
        print("[验证成功] 确实由该 CA 签发")
        return client_cert.public_key()

    except InvalidSignature:
        raise RuntimeError("[验证失败] 该证书不是由指定的 CA 签发")
    except Exception as e:
        raise RuntimeError(f"[验证出错] {e}")

if __name__ == '__main__':
    with open("device_certificate.pem", "rb") as f:
        client_cert_pem = f.read()

    with open("server.crt", "rb") as f:
        ca_cert_pem = f.read()

    # 验证签名并提取客户端公钥
    public_key = verify_cert_is_signed_by_ca(client_cert_pem, ca_cert_pem)

    # 打印公钥
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print("客户端公钥：\n", pem.decode())