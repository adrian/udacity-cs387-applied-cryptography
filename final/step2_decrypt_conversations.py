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

def relay_messages(party1_name, party2_name):
    party1 = base + '/' + party1_name
    party2 = base + '/' + party2_name

    # Initialize a session for each party
    party1_data = initialize(party1)
    sys.stdout.write("%s's public data: %s\n" % (party1_name, party1_data))
    party2_data = initialize(party2)
    sys.stdout.write("%s's public data: %s\n" % (party2_name, party2_data))

    # Send each party the value 1 in place of the other parties public value
    primed_secret_bytes = Crypto.Util.number.long_to_bytes(1)
    primed_secret_hex = binascii.hexlify(primed_secret_bytes)
    print "sending the primed_secret_hex as: %s" % primed_secret_hex
    result = send_key(party1, party1_data['token'], primed_secret_hex, party2_name)
    assert result['status'] == 'success'
    result = send_key(party2, party2_data['token'], primed_secret_hex, party1_name)
    assert result['status'] == 'success'

    # Calculate a value for S, the shared secret (SS)
    # The SS is g^(x_j * x_i) (mod p)
    # Since we told each party that the others public value is 1 this means,
    #   party1 will calculate the SS as 1^x_i (mod p) => 1
    #   party2 will calculate the SS as 1^x_j (mod p) => 1
    p1_shared_secret_hash = hashlib.sha1(chr(1)).hexdigest()
    key = binascii.unhexlify(p1_shared_secret_hash[0:32])
    nonce = p1_shared_secret_hash[32:]

    # Get the first encrypted message from party1
    msg = recieve_msg(party1, party1_data['token'])

    recipient = party2
    recipient_name = party2_name
    recipient_token = party2_data['token']
    from_name = party1_name
    message_cipher = msg['msg']
    message_iv = msg['iv']

    while (True):
        try:
            # Decrypt this message
            cipher = crypto.AESCounterMode()
            plaintext = cipher.decrypt(key, nonce, message_iv, binascii.unhexlify(message_cipher))
            sys.stdout.write("From %s to %s: %s\n" % (from_name, recipient_name, plaintext))
        except TypeError:
            plaintext = "CLEARTEXT => %s" % message_cipher
            sys.stdout.write("From %s to %s: %s\n" % (from_name, recipient_name, plaintext))
            break

        response = send_msg(recipient, recipient_token, message_cipher, message_iv)
        assert response['status'] == 'success'

        if not 'reply' in response:
            break

        if recipient == party1:
            recipient = party2
            recipient_name = party2_name
            recipient_token = party2_data['token']
            from_name = party1_name
        else:
            recipient = party1
            recipient_name = party1_name
            recipient_token = party1_data['token']
            from_name = party2_name

        message_cipher = response['reply']['msg']
        message_iv = response['reply']['iv']

#relay_messages("bob", "alice")
relay_messages("alex", "alice")
#relay_messages("alice", "betty")
#relay_messages("bob", "alex")
#relay_messages("bob", "betty")
#relay_messages("alex", "betty")
