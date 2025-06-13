import os
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from socket_client import DEVICE_ID, SERVER_URL

def generate_device_csr(device_uuid=None, key_size=2048):
    if not device_uuid:
        print("No device uuid provided")
        return False

    # 设置默认文件路径
    private_key_path = f"device_{device_uuid}_private.pem"
    csr_path = f"device_{device_uuid}_request.csr"

    # 1. 生成RSA私钥
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

    # 2. 保存私钥（PEM格式）
    with open(private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # 3. 创建简化的CSR（仅包含必要字段）
    # 设备证书通常只需要CN（Common Name）字段
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, device_uuid),
    ])

    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    csr = builder.sign(private_key, hashes.SHA256())

    # 4. 保存CSR
    with open(csr_path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    return {"csr": csr_path}



# 使用示例
def generate_device_certificate():
    if not os.path.exists('device_certificate.pem'):
        generate_device_csr(DEVICE_ID)
        # 提交CSR
        csr_pem = open(f"device_{DEVICE_ID}_request.csr", 'rb').read()
        response = requests.post(
            f"{SERVER_URL}/request_certificate",
            data=csr_pem,
            verify=False  # 在测试中跳过SSL验证，实际应使用CA证书验证
        )
        print(f"{SERVER_URL}/request_certificate")

        if response.status_code == 200:
            with open("device_certificate.pem", "wb") as f:
                f.write(response.content)
            print("[证书签发成功]")
        else:
            print("[错误]", response.json())
    else:
        print("证书已存在")

if __name__ == "__main__":
    print("你目前正在运行单个证书申请功能点的测试")
    generate_device_certificate()