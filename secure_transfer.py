"""
Secure File Transfer using AES-256-GCM encryption.

Usage:
  python secure_transfer.py encrypt  <file> [-o out.enc]
  python secure_transfer.py decrypt  <file.enc> [-o out]
  python secure_transfer.py receive  --port 5001 --outdir received
  python secure_transfer.py send     <file> --host 127.0.0.1 --port 5001

The password (secret key material) is read from the SFT_PASSWORD environment
variable or typed at a hidden prompt. It is never sent over the network.
"""
import argparse
import getpass
import hashlib
import os
import socket
import struct
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"SFT1"          # file-format identifier / version
SALT_LEN = 16            # random salt for key derivation
NONCE_LEN = 12           # 96-bit nonce recommended for GCM
KDF_ITERATIONS = 600_000
MAX_PAYLOAD = 1 << 30    # 1 GiB safety limit for the receiver


# ---------------------------------------------------------------- crypto
def derive_key(password: str, salt: bytes) -> bytes:
    """Turn a human password into a 256-bit AES key (PBKDF2-HMAC-SHA256)."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(data: bytes, password: str) -> bytes:
    """Return MAGIC | salt | nonce | ciphertext+tag."""
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(password, salt)
    ct = AESGCM(key).encrypt(nonce, data, MAGIC + salt)  # header is authenticated
    return MAGIC + salt + nonce + ct


def decrypt_bytes(blob: bytes, password: str) -> bytes:
    """Reverse of encrypt_bytes. Raises ValueError on wrong key / tampering."""
    header = len(MAGIC) + SALT_LEN + NONCE_LEN
    if len(blob) < header + 16 or blob[: len(MAGIC)] != MAGIC:
        raise ValueError("Not a valid encrypted file")
    salt = blob[len(MAGIC): len(MAGIC) + SALT_LEN]
    nonce = blob[len(MAGIC) + SALT_LEN: header]
    ct = blob[header:]
    key = derive_key(password, salt)
    try:
        return AESGCM(key).decrypt(nonce, ct, MAGIC + salt)
    except InvalidTag:
        raise ValueError("Decryption failed: wrong password or file was modified")


def encrypt_file(src: str, dst: str, password: str) -> None:
    with open(src, "rb") as f:
        data = f.read()
    with open(dst, "wb") as f:
        f.write(encrypt_bytes(data, password))


def decrypt_file(src: str, dst: str, password: str) -> None:
    with open(src, "rb") as f:
        blob = f.read()
    with open(dst, "wb") as f:
        f.write(decrypt_bytes(blob, password))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------- network
def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(min(65536, n - len(buf)))
        if not chunk:
            raise ConnectionError("Connection closed early")
        buf.extend(chunk)
    return bytes(buf)


def send_file(path: str, host: str, port: int, password: str) -> None:
    """Encrypt the file in memory, then send: [name_len][name][size][blob]."""
    with open(path, "rb") as f:
        plain = f.read()
    blob = encrypt_bytes(plain, password)
    name = os.path.basename(path).encode("utf-8")
    with socket.create_connection((host, port), timeout=30) as s:
        s.sendall(struct.pack(">H", len(name)) + name)
        s.sendall(struct.pack(">Q", len(blob)))
        s.sendall(blob)
    print(f"Sent {len(blob)} encrypted bytes of '{path}' to {host}:{port}")
    print(f"Original SHA-256: {sha256_hex(plain)}")


def receive_file(port: int, outdir: str, password: str, host: str = "0.0.0.0",
                 ready_event=None, once: bool = True) -> str:
    """Listen, store the encrypted blob, then decrypt it. Returns output path."""
    os.makedirs(outdir, exist_ok=True)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(1)
        print(f"Listening on {host}:{port} ...")
        if ready_event is not None:
            ready_event.set()
        conn, addr = srv.accept()
        with conn:
            (name_len,) = struct.unpack(">H", _recv_exact(conn, 2))
            name = _recv_exact(conn, name_len).decode("utf-8")
            (size,) = struct.unpack(">Q", _recv_exact(conn, 8))
            if size > MAX_PAYLOAD:
                raise ValueError("Payload too large")
            blob = _recv_exact(conn, size)
    safe_name = os.path.basename(name) or "received_file"  # block path tricks
    enc_path = os.path.join(outdir, safe_name + ".enc")
    with open(enc_path, "wb") as f:
        f.write(blob)
    plain = decrypt_bytes(blob, password)
    out_path = os.path.join(outdir, safe_name)
    with open(out_path, "wb") as f:
        f.write(plain)
    print(f"Received from {addr[0]}; decrypted to '{out_path}'")
    print(f"Decrypted SHA-256: {sha256_hex(plain)}")
    return out_path


# ------------------------------------------------------------------- CLI
def get_password() -> str:
    pw = os.environ.get("SFT_PASSWORD") or getpass.getpass("Password: ")
    if len(pw) < 8:
        sys.exit("Use a password of at least 8 characters.")
    return pw


def main() -> None:
    p = argparse.ArgumentParser(description="AES-256-GCM secure file transfer")
    sub = p.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("encrypt"); e.add_argument("file"); e.add_argument("-o")
    d = sub.add_parser("decrypt"); d.add_argument("file"); d.add_argument("-o")
    s = sub.add_parser("send"); s.add_argument("file")
    s.add_argument("--host", default="127.0.0.1"); s.add_argument("--port", type=int, default=5001)
    r = sub.add_parser("receive"); r.add_argument("--port", type=int, default=5001)
    r.add_argument("--outdir", default="received")

    a = p.parse_args()
    pw = get_password()
    try:
        if a.cmd == "encrypt":
            out = a.o or a.file + ".enc"
            encrypt_file(a.file, out, pw); print(f"Encrypted -> {out}")
        elif a.cmd == "decrypt":
            out = a.o or (a.file[:-4] if a.file.endswith(".enc") else a.file + ".dec")
            decrypt_file(a.file, out, pw); print(f"Decrypted -> {out}")
        elif a.cmd == "send":
            send_file(a.file, a.host, a.port, pw)
        elif a.cmd == "receive":
            receive_file(a.port, a.outdir, pw)
    except (ValueError, OSError) as ex:
        sys.exit(f"Error: {ex}")


if __name__ == "__main__":
    main()
