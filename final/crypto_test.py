import unittest
import binascii
import crypto

class TestAESCounterMode(unittest.TestCase):

    def setUp(self):
        self.cipher = crypto.AESCounterMode()

    def test_decrypt_rfc3686_128_1(self):
        key = binascii.unhexlify("AE 68 52 F8 12 10 67 CC 4B F7 A5 76 55 77 F3 9E".replace(" ", ""))
        ctr_iv = "00 00 00 00 00 00 00 00".replace(" ", "")
        nonce = "00 00 00 30".replace(" ", "")
        ciphertext = binascii.unhexlify("E4 09 5D 4F B7 A7 B3 79 2D 61 75 A3 26 13 11 B8".replace(" ", ""))

        plaintext = self.cipher.decrypt(key, nonce, ctr_iv, ciphertext)

        self.assertEqual(plaintext, "Single block msg")

        counter = binascii.hexlify(self.cipher.counter()).upper()
        self.assertEqual(counter, "00 00 00 30 00 00 00 00 00 00 00 00 00 00 00 02".replace(" ", ""))

    def test_decrypt_rfc3686_128_2(self):
        key = binascii.unhexlify("7E 24 06 78 17 FA E0 D7 43 D6 CE 1F 32 53 91 63".replace(" ", ""))
        ctr_iv = "C0 54 3B 59 DA 48 D9 0B".replace(" ", "")
        nonce = "00 6C B6 DB".replace(" ", "")
        ciphertext = "51 04 A1 06 16 8A 72 D9 79 0D 41 EE 8E DA D3 88".replace(" ", "")
        ciphertext += "EB 2E 1E FC 46 DA 57 C8 FC E6 30 DF 91 41 BE 28".replace(" ", "")

        plaintext = self.cipher.decrypt(key, nonce, ctr_iv, binascii.unhexlify(ciphertext))

        expected_plaintext = "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F".replace(" ", "")
        expected_plaintext += "10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F".replace(" ", "")

        self.assertEqual(expected_plaintext, binascii.hexlify(plaintext).upper())

        counter = binascii.hexlify(self.cipher.counter()).upper()
        self.assertEqual(counter, "00 6C B6 DB C0 54 3B 59 DA 48 D9 0B 00 00 00 03".replace(" ", ""))

    def test_decrypt_rfc3686_128_3(self):
        key = binascii.unhexlify("76 91 BE 03 5E 50 20 A8 AC 6E 61 85 29 F9 A0 DC".replace(" ", ""))
        ctr_iv = "27 77 7F 3F  4A 17 86 F0".replace(" ", "")
        nonce = "00 E0 01 7B".replace(" ", "")
        ciphertext = "C1 CF 48 A8 9F 2F FD D9 CF 46 52 E9 EF DB 72 D7".replace(" ", "")
        ciphertext += "45 40 A4 2B DE 6D 78 36 D5 9A 5C EA AE F3 10 53".replace(" ", "")
        ciphertext += "25 B2 07 2F".replace(" ", "")

        plaintext = self.cipher.decrypt(key, nonce, ctr_iv, binascii.unhexlify(ciphertext))

        expected_plaintext = "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F".replace(" ", "")
        expected_plaintext += "10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F".replace(" ", "")
        expected_plaintext += "20 21 22 23".replace(" ", "")

        self.assertEqual(expected_plaintext, binascii.hexlify(plaintext).upper())

        counter = binascii.hexlify(self.cipher.counter()).upper()
        self.assertEqual(counter, "00 E0 01 7B 27 77 7F 3F 4A 17 86 F0 00 00 00 04".replace(" ", ""))

    def test_encrypt_rfc3686_128_1(self):
        key = binascii.unhexlify("AE 68 52 F8 12 10 67 CC 4B F7 A5 76 55 77 F3 9E".replace(" ", ""))
        ctr_iv = "00 00 00 00 00 00 00 00".replace(" ", "")
        nonce = "00 00 00 30".replace(" ", "")
        expected_ciphertext = "E4 09 5D 4F B7 A7 B3 79 2D 61 75 A3 26 13 11 B8".replace(" ", "")
        plaintext = "53 69 6E 67 6C 65 20 62 6C 6F 63 6B 20 6D 73 67".replace(" ", "")

        ciphertext = self.cipher.encrypt(key, nonce, ctr_iv, binascii.unhexlify(plaintext))

        self.assertEqual(expected_ciphertext, binascii.hexlify(ciphertext).upper())

        counter = binascii.hexlify(self.cipher.counter()).upper()
        self.assertEqual(counter, "00 00 00 30 00 00 00 00 00 00 00 00 00 00 00 02".replace(" ", ""))

    def test_encrypt_rfc3686_128_2(self):
        key = binascii.unhexlify("7E 24 06 78 17 FA E0 D7 43 D6 CE 1F 32 53 91 63".replace(" ", ""))
        ctr_iv = "C0 54 3B 59 DA 48 D9 0B".replace(" ", "")
        nonce = "00 6C B6 DB".replace(" ", "")
        expected_ciphertext = "51 04 A1 06 16 8A 72 D9 79 0D 41 EE 8E DA D3 88".replace(" ", "")
        expected_ciphertext += "EB 2E 1E FC 46 DA 57 C8 FC E6 30 DF 91 41 BE 28".replace(" ", "")
        plaintext = "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F".replace(" ", "")
        plaintext += "10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F".replace(" ", "")

        ciphertext = self.cipher.encrypt(key, nonce, ctr_iv, binascii.unhexlify(plaintext))

        self.assertEqual(expected_ciphertext, binascii.hexlify(ciphertext).upper())

        counter = binascii.hexlify(self.cipher.counter()).upper()
        self.assertEqual(counter, "00 6C B6 DB C0 54 3B 59 DA 48 D9 0B 00 00 00 03".replace(" ", ""))

    def test_encrypt_rfc3686_128_3(self):
        key = binascii.unhexlify("76 91 BE 03 5E 50 20 A8 AC 6E 61 85 29 F9 A0 DC".replace(" ", ""))
        ctr_iv = "27 77 7F 3F  4A 17 86 F0".replace(" ", "")
        nonce = "00 E0 01 7B".replace(" ", "")
        expected_ciphertext = "C1 CF 48 A8 9F 2F FD D9 CF 46 52 E9 EF DB 72 D7".replace(" ", "")
        expected_ciphertext += "45 40 A4 2B DE 6D 78 36 D5 9A 5C EA AE F3 10 53".replace(" ", "")
        expected_ciphertext += "25 B2 07 2F".replace(" ", "")
        plaintext = "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F".replace(" ", "")
        plaintext += "10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F".replace(" ", "")
        plaintext += "20 21 22 23".replace(" ", "")

        ciphertext = self.cipher.encrypt(key, nonce, ctr_iv, binascii.unhexlify(plaintext))

        self.assertEqual(expected_ciphertext, binascii.hexlify(ciphertext).upper())

        counter = binascii.hexlify(self.cipher.counter()).upper()
        self.assertEqual(counter, "00 E0 01 7B 27 77 7F 3F 4A 17 86 F0 00 00 00 04".replace(" ", ""))
