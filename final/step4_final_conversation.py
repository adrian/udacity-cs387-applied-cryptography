from final_challenge import base
from final_challenge import initialize
from final_challenge import send_key
from final_challenge import recieve_msg
from final_challenge import send_msg
import sys
import hashlib
import binascii
import crypto
import Crypto.Util.number

def final_conversation():
    alice = base + "/alice"

    # Initialize a session with Alice
    alice_data = initialize(alice)
    sys.stdout.write("%s's public data: %s\n" % ("alice", alice_data))

    # Send Alice a value of 1 for Eve's public data. Obviously we could
    # send anything here since Alice really is communicating with us (Eve)
    secret_bytes = Crypto.Util.number.long_to_bytes(1)
    secret_hex = binascii.hexlify(secret_bytes)
    print "sending the secret_hex as: %s" % secret_hex
    result = send_key(alice, alice_data['token'], secret_hex, "eve")
    assert result['status'] == 'success'

    # Calculate a value for S, the shared secret (SS)
    # The SS is g^(x_j * x_i) (mod p)
    # Since we told Alice that Eve's public value is 1 this means she will
    # calculate the SS as 1^x_i (mod p) => 1
    shared_secret_hash = hashlib.sha1(chr(1)).hexdigest()
    key = binascii.unhexlify(shared_secret_hash[0:32])
    nonce = shared_secret_hash[32:]

    # Get the first encrypted message from Alice
    msg = recieve_msg(alice, alice_data['token'])
    message_cipher = msg['msg']
    message_iv = msg['iv']

    cipher = crypto.AESCounterMode()
    plaintext = cipher.decrypt(key, nonce, message_iv, binascii.unhexlify(message_cipher))
    sys.stdout.write("From Alice to Eve: %s\n" % (plaintext))

    # Encrypt the message we found and send it to Alice
    ciphertext = cipher.encrypt(key, nonce, message_iv, "An important question: What do you get if you multiply six by nine?")
    response = send_msg(alice, alice_data['token'], binascii.hexlify(ciphertext), message_iv)
    assert response['status'] == 'success'

    # Decrypt the response from Alice
    message_cipher = response['reply']['msg']
    message_iv = response['reply']['iv']
    plaintext = cipher.decrypt(key, nonce, message_iv, binascii.unhexlify(message_cipher))
    sys.stdout.write("From Alice to Eve: %s\n" % (plaintext))

final_conversation()
