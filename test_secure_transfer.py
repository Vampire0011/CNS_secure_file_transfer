import os
import tempfile
import threading
import unittest

import secure_transfer as st

PW = "StrongPass#123"


class TestCrypto(unittest.TestCase):
    def test_round_trip(self):
        data = b"Confidential Q3 financial report " * 1000
        self.assertEqual(st.decrypt_bytes(st.encrypt_bytes(data, PW), PW), data)

    def test_ciphertext_is_unreadable(self):
        data = b"account_number=1234567890"
        self.assertNotIn(b"account_number", st.encrypt_bytes(data, PW))

    def test_wrong_password_fails(self):
        blob = st.encrypt_bytes(b"secret", PW)
        with self.assertRaises(ValueError):
            st.decrypt_bytes(blob, "WrongPassword!")

    def test_tampering_detected(self):
        blob = bytearray(st.encrypt_bytes(b"secret data", PW))
        blob[-1] ^= 1
        with self.assertRaises(ValueError):
            st.decrypt_bytes(bytes(blob), PW)

    def test_same_input_different_output(self):
        self.assertNotEqual(st.encrypt_bytes(b"x", PW), st.encrypt_bytes(b"x", PW))


class TestTransfer(unittest.TestCase):
    def test_end_to_end_over_socket(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "report.txt")
            payload = os.urandom(200_000)
            with open(src, "wb") as f:
                f.write(payload)
            outdir = os.path.join(tmp, "inbox")
            ready = threading.Event()
            t = threading.Thread(target=st.receive_file,
                                 args=(50123, outdir, PW, "127.0.0.1", ready))
            t.start()
            ready.wait(5)
            st.send_file(src, "127.0.0.1", 50123, PW)
            t.join(10)
            with open(os.path.join(outdir, "report.txt"), "rb") as f:
                self.assertEqual(f.read(), payload)
            with open(os.path.join(outdir, "report.txt.enc"), "rb") as f:
                self.assertNotIn(payload[:32], f.read())


if __name__ == "__main__":
    unittest.main(verbosity=2)
