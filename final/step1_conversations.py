from final_challenge import base
from final_challenge import initialize
from final_challenge import send_key
from final_challenge import recieve_msg
from final_challenge import send_msg
import sys

def relay_messages(party1_name, party2_name):
    party1 = base + '/' + party1_name
    party2 = base + '/' + party2_name

    # Initialize a session for each party
    party1_data = initialize(party1)
    sys.stdout.write("%s's public data: %s\n" % (party1_name, party1_data))
    party2_data = initialize(party2)
    sys.stdout.write("%s's public data: %s\n" % (party2_name, party2_data))

    result = send_key(party1, party1_data['token'], party2_data['public'], party2_name)
    assert result['status'] == 'success'
    result = send_key(party2, party2_data['token'], party1_data['public'], party1_name)
    assert result['status'] == 'success'

    # Get the first encrypted message from party1
    response = recieve_msg(party1, party1_data['token'])
    msg = response['msg']
    iv = response['iv']

    recipient = party2
    recipient_name = party2_name
    recipient_token = party2_data['token']
    from_name = party1_name

    while (True):
        sys.stdout.write("From %s to %s: %s\n" % (from_name, recipient_name, msg))
        response = send_msg(recipient, recipient_token, msg, iv)
        assert response['status'] == 'success'

        if not 'reply' in response:
            break

        msg = response['reply']['msg']
        iv = response['reply']['iv']

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

relay_messages("bob", "alice")
