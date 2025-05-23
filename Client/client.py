import ssl
import sys
import asyncio
import pickle
import zlib
import pandas as pd
import numpy as np
from phe import paillier
import ShamirSecret
import DLClient
import time
from auth import get_hashed_serial, generate_hmac_signature


# ======= Client Parameters =======
HOST = '10.0.8.36'
PORT = 65432
client_id = int(sys.argv[1])

# ======= Generate Paillier Key Pair =======
public_key, secret_key = paillier.generate_paillier_keypair()

# ======= Server Parameters =======
BIG_P = None
THRESHOLD = None
ACTIVITY = 'run'

final_weights = None
dataset = None
score = 0


# ======= Initialize =======
async def initialize():
    global dataset

    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE  # In production, set to CERT_REQUIRED

    reader, writer = await asyncio.open_connection(HOST, PORT, ssl=ssl_context)

    try:
        # Send public key to server
        serial = get_hashed_serial()
        timestamp = int(time.time())
        signature = generate_hmac_signature(serial, timestamp)
        
        data = {
            'serial': serial,
            'timestamp': timestamp,
            'signature': signature,
            'client_id': client_id,
            'public_key': public_key
        }

        compressed_data = zlib.compress(pickle.dumps(data))
        writer.write(compressed_data)
        await writer.drain()
        
        dataset = pd.read_csv(f"s{client_id}_{ACTIVITY}_processed.csv")
        print(f"Client {client_id}'s data : ", dataset.shape)

        global THRESHOLD, BIG_P

        # Receive parameters
        data = await reader.read(4096)
        data = pickle.loads(zlib.decompress(data))
        THRESHOLD = data['threshold']
        BIG_P = data['p']

        round_no = 1
        while True:
            if not await aggregate_weight(reader, writer, round_no):
                break
            print(f"[CLIENT {client_id}] Round {round_no} has been completed. Proceeding to the next round ...")
            round_no += 1

        print(f"[CLIENT {client_id}] All the rounds has been completed")

    except KeyboardInterrupt:
        print(f"\n[CLIENT {client_id}] Ctrl+C detected. Sending dropout signal to server...")

        # Send a special dropout message
        try:
            dropout_message = zlib.compress(pickle.dumps(None))  # None as dropout indicator
            writer.write(dropout_message)
            await writer.drain()
        except Exception as e:
            print(f"[CLIENT {client_id}] Failed to notify server about dropout: {e}")

    except Exception as e:
        print(f"[CLIENT {client_id}] Error occurred: {e}")

    finally:
        print(f"Terminating CLIENT {client_id} !!!")
        writer.close()
        await writer.wait_closed()


async def aggregate_weight(reader, writer, round_no):
    global final_weights, score

    data = {'alive': False if dataset.shape[0] < (round_no - 1) * 2**15 else True}
    compressed_data = zlib.compress(pickle.dumps(data))
    writer.write(compressed_data)
    await writer.drain()

    if not data['alive']:
        return False

    print(f"[CLIENT {client_id}] Round {round_no} has been started.")

    # ======= Generate Local Model =======
    if round_no == 1:
        local_weights = DLClient.modelTraining(dataset[:2**15])
        score = 1 / THRESHOLD
    else:
        local_weights = DLClient.modelTraining(dataset[(round_no - 1)*2**15 : min(dataset.shape[0], (round_no)*2**15)], final_weights)
    print('Initial score : ', score)
    # Receive public keys of all clients in the round
    data = await reader.read(2**20)
    public_keys = pickle.loads(zlib.decompress(data))
    
    print(f"[CLIENT {client_id}] Received Public Keys from {list(public_keys.keys())}")

    # ======= Generate masking value =======
    shamir_secret = np.random.randint(1, BIG_P - 1)
    print(f"[CLIENT {client_id}] Round {round_no} Shamir Secret Key: {shamir_secret}")

    # ======= Generate Shamir Secret Shares =======
    shares = ShamirSecret.generate_share(shamir_secret, list(public_keys.keys()))

    # ======= Encrypt Weights =======
    ciphertext = [w * score + shamir_secret for w in local_weights]

    # Encrypt and store shares
    encrypted_shares = {
        cid: public_keys[cid].encrypt(shares[cid])
        for cid in public_keys
    }

    # Compress and send encrypted ciphertext and shares to server
    data = {
        'ciphertext': ciphertext,
        'shares': encrypted_shares,
        'round_no': round_no,
        'score': score
    }
    compressed_data = zlib.compress(pickle.dumps(data))
    writer.write(compressed_data)
    await writer.drain()
    print(f"[CLIENT {client_id}] Round {round_no} : Sent ciphertext and encrypted shares to server")

    # Receive Aggregated Share from Server
    data = await reader.read(4096)
    if not data:
        print(f"[CLIENT {client_id}] Round {round_no} : Couldn't receive aggregated share from the server")
        return False

    aggregated_share = pickle.loads(zlib.decompress(data))

    # Decrypt aggregated share using secret key
    decrypted_share = secret_key.decrypt(aggregated_share)
    
    # Send back decrypted share to server
    compressed_data = zlib.compress(pickle.dumps(decrypted_share))
    writer.write(compressed_data)
    await writer.drain()
    print(f"[CLIENT {client_id}] Round {round_no} : Sent decrypted share to server")

    # ======= Receive Final Aggregated Global Model =======
    data = await reader.read(2**20)
    if not data:
        print(f"[CLIENT {client_id}] Round {round_no} : Couldn't receive final aggregated global model from the server")
        return False
    data = pickle.loads(zlib.decompress(data))

    aggregated_shamir_secret = secret_key.decrypt(data['aggregated_shamir_secret'])
    aggregated_ciphertext = data['aggregated_ciphertext']
    n = data['n']

    # Compute final model after unmasking
    final_weights = [(ct - aggregated_shamir_secret) / n for ct in aggregated_ciphertext]
    score = DLClient.GMMScore(local_weights, final_weights)
    print('Final score : ', score)
    
    print(f"[CLIENT {client_id}] Round {round_no} : Training and aggregation complete.")

    return True


# Start client connection
asyncio.run(initialize())
