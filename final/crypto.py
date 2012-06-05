from Crypto.Cipher import AES
from Crypto.Util import Counter
import binascii


class AESCounterMode:

    def decrypt(self, key, nonce, ctr_iv, ciphertext):
        """
        key: (byte string) - The secret key to use in the symmetric cipher 
        nonce: (hex string) - MUST be 4 bytes
        ctr_iv: (hex string) - MUST be 8 bytes
        ciphertext: (byte string) - ciphertext to decrypt

        Returns the decrypted ciphertext as a binary string.

        This code works for the first three test vectors documented in
        http://tools.ietf.org/html/rfc3686#section-6
        These are all 128-bit key tests.
        """

        assert(len(nonce) == 8) # 8 octets = 4 bytes
        assert(len(ctr_iv) == 16) # 16 octets = 8 bytes

        prefix = binascii.unhexlify(nonce + ctr_iv)
        self.counter = Counter.new(32, prefix=prefix)

        cipher = AES.new(key, AES.MODE_CTR, counter=self.counter)
        plaintext = cipher.decrypt(ciphertext)

        return plaintext

    def encrypt(self, key, nonce, ctr_iv, plaintext):
        """
        key: (byte string) - The secret key to use in the symmetric cipher 
        nonce: (hex string) - MUST be 4 bytes
        ctr_iv: (hex string) - MUST be 8 bytes
        plaintext: (byte string) - plaintext to encrypt

        Returns the encrypted ciphertext as a binary string.

        This code works for the first three test vectors documented in
        http://tools.ietf.org/html/rfc3686#section-6
        These are all 128-bit key tests.
        """

        assert(len(nonce) == 8) # 8 octets = 4 bytes
        assert(len(ctr_iv) == 16) # 16 octets = 8 bytes

        prefix = binascii.unhexlify(nonce + ctr_iv)
        self.counter = Counter.new(32, prefix=prefix)

        cipher = AES.new(key, AES.MODE_CTR, counter=self.counter)
        ciphertext = cipher.encrypt(plaintext)

        return ciphertext

    def __get__(self, instance, owner):
        return self.value
