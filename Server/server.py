import asyncio
import ssl
import hmac
import hashlib
import time
import pickle
import zlib
import numpy as np
import ShamirSecret
from SmartSemaphore import SmartSemaphore


# ======= Server Parameters =======
HOST = '10.0.8.36'
PORT = 65432
THRESHOLD = 5
BIG_P = 104729  # Large prime for modular operation

# Shared Variables
public_keys = {}
clients = set()
ciphertexts = {}
scores = []
encrypted_shares = {}
aggregated_ciphertext = None
aggregated_shares = {}
decrypted_shares = {}
aggregated_shamir_secret = None
count = 0
count_temp = 0

lock = asyncio.Lock()
semaphore = SmartSemaphore(THRESHOLD)


PASSKEY = b'\xcaV\xd4Q\xbeR:\x01vT\x1c\xdc\x03\xbf]K\xd2[\x9b\xce\xfbm\xe8\xe5\xee\xcfY\xcd}\xf9\xfd\x92\xc0j\xab{8^\xe0\x7f\xd5#t\xa7A`.\xdb3\x87\x97\xf2\xba\xb7\xcf\xeaOeRN;\x7f\x0c\xc8\xc1I\nN\xea\xa3\xb4\xe6\xb6/+Q\xfc\x01\x82\x9f\x98\xbb#YVL1\xb1ZC$\xb4\xa7\x16+\xad\x05i\xb2\x98\x9c\xb8\xf9\x8b\xae\xd6D^\xdePE\x9d\xd3\xd5z\xc8\xdaI\x0fu\xc7h4S>\x97\xc3\xd6H4\xbc\xf0\xc4\xdc\xf5\x99\xacgW\x0b\xe7\xde\xda\x01\x13\xb6a\xb2\x16\x030\xf5\xcf \x82K\xba\x85T\x80\xd8\xb6\x89!4\xbb\x00B}\x8c\x8ak\x11\xfb.y\xfd\xf9\x9b&+\x95\xf06\xbc\xe2\xad\xf9\x10\xec\xd7\xf2\xad\xc7\xf5\xfe=\xecbi4\x15\x84Wu\x9e\xb7\xef\xd9\xb3\xf4\xd4PPh\t\x11\xda\xc8\x86OW\xc6@"\xb2\xd7\x19\xd4\x11Z\xaa\x93\xfd\xa7\x95\x9b:\xc8u\xd2:\xcc\x18\xf8\x14\xe9i\xb7\xe1\xfcZe\xb9\xfa\xd2'
valid_serial = {
    '6df3b2ec92dfafb3fb4dc16d54982d8d2c31e4656868d0ac3ae450440043ecf8',     # Samuel
    '0e1606c2aa396a622538f55784f602207d5bb083b3749cba21e0178c7dcdd07e'      # Renga
}

def validate_message(data):
    serial = data['serial']
    timestamp = data['timestamp']
    signature = data['signature']

    # Basic replay protection: 3 min expiry
    if abs(time.time() - timestamp) > 180:
        return False

    # Machine Locking
    if serial not in valid_serial:
        return False

    expected = hmac.new(PASSKEY, f"{serial}{timestamp}".encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected)


# ======= Handle Client Connection =======
async def handle_client(reader, writer):
    global public_keys

    # Receive public key from client
    data = await reader.read(2**20)
    data = pickle.loads(zlib.decompress(data))

    if not validate_message(data):
        print ('Authentication Failed! Cannot Connect to Server !!')
        writer.close()
        await writer.wait_closed()
        return False

    client_id = data['client_id']
    public_keys[client_id] = data['public_key']

    print(f"[SERVER] Authenticated and Received public key from Client {client_id}")

    # Send shared parameters
    response = {
        'threshold' : THRESHOLD,
        'p': BIG_P
    }
    compressed_response = zlib.compress(pickle.dumps(response))
    writer.write(compressed_response)
    await writer.drain()
    print(f"[SERVER] Sent parameters to Client {client_id}")

    try:
        while True:  # Multiple rounds
            if not await aggregate_weight(reader, writer, client_id):
                break
    except Exception as e:
        print(f"[SERVER] Exception for Client {client_id}: {e}")
        semaphore.drop()
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        print(f"[SERVER] Connection closed for Client {client_id}")

async def aggregate_weight(reader, writer, client_id):
    global clients, scores, ciphertexts, encrypted_shares, aggregated_ciphertext, aggregated_shares, decrypted_shares, aggregated_shamir_secret, count, count_temp

    # Alive Check
    data = await reader.read(1028)
    data = pickle.loads(zlib.decompress(data))
    if not data.get("alive"):
        return False


    await semaphore.wait()
    # ====== Start of Critical Section ======

    # Select clients
    async with lock:
        clients.add(client_id)
    print(f"[SERVER] Client {client_id} is selected for the round")

    while len(clients) < semaphore._initial:
        print(f"[SERVER] Waiting for all clients to join ({client_id})... ({len(clients)}/{semaphore._initial})")
        await asyncio.sleep(1)

    # Send public keys
    response = {client: public_keys[client] for client in clients}
    compressed_response = zlib.compress(pickle.dumps(response))
    writer.write(compressed_response)
    await writer.drain()
    print(f"[SERVER] Sent public keys to Client {client_id}")

    # Receive ciphertext and shares
    data = await reader.read(2**20)
    if not data:
        print(f"[SERVER] No data from Client {client_id}")
        await semaphore.drop()
        return False

    data = pickle.loads(zlib.decompress(data))

    if not data:
        print(f"[SERVER] Client {client_id} dropped during ciphertext upload")
        await semaphore.drop()
        return False

    ciphertexts[client_id] = data['ciphertext']
    encrypted_shares[client_id] = data['shares']
    scores.append(data['score'])

    print(f"[SERVER] Received ciphertext and shares from Client {client_id}")
    while len(encrypted_shares) < semaphore.active():
        print(f"[SERVER] Waiting for ciphertexts ({client_id})... ({len(encrypted_shares)}/{semaphore.active()})")
        await asyncio.sleep(1)

    async with lock:
        count += 1

    if count == len(ciphertexts):
        ciphertext_list = list(ciphertexts.values())
        aggregated_ciphertext = [
            np.sum(np.array(layer_ciphertexts), axis=0)
            for layer_ciphertexts in zip(*ciphertext_list)
        ]
        print(f"[SERVER] Aggregated Ciphertext.")

        aggregated_shares = encrypted_shares[list(ciphertexts.keys())[0]].copy()
        for cid in list(ciphertexts.keys())[1:]:
            for j in aggregated_shares:
                aggregated_shares[j] += encrypted_shares[cid][j]

        count = 0

    while count > 0:
        print(f"[SERVER] Waiting for Aggregation ({client_id})...")
        await asyncio.sleep(1)


    # Send aggregated shares to client
    compressed_data = zlib.compress(pickle.dumps(aggregated_shares[client_id]))
    writer.write(compressed_data)
    await writer.drain()
    print(f"[SERVER] Sent aggregated share to Client {client_id}")

    # Receive decrypted share
    data = await reader.read(4096)
    if not data:
        print(f"[SERVER] No decrypted share from Client {client_id}")
        await semaphore.drop()
        return False

    data = pickle.loads(zlib.decompress(data))
    if not data:
        print(f"[SERVER] Client {client_id} dropped during decryption")
        await semaphore.drop()
        return False

    decrypted_shares[client_id] = data
    print(f"[SERVER] Received decrypted share from Client {client_id}")

    while len(decrypted_shares) < semaphore.active():
        print(f"[SERVER] Waiting for decrypted shares ({client_id})... ({len(decrypted_shares)}/{semaphore.active()})")
        await asyncio.sleep(1)

    async with lock:
        count_temp += 1
    
    if count_temp == semaphore.active():
        aggregated_shamir_secret = ShamirSecret.reconstruct_secret(decrypted_shares)
        print(f"[SERVER] Reconstructed Shamir Secret.")
        count_temp = 0

    while count_temp > 0:
        print(f"[SERVER] Waiting for Reconstructing Shamir Secret ({client_id})...")
        await asyncio.sleep(1)


    # Send final model
    final_model = {
        'aggregated_shamir_secret': public_keys[client_id].encrypt(aggregated_shamir_secret),
        'aggregated_ciphertext': aggregated_ciphertext,
        'n': sum(scores)
    }
    compressed_data = zlib.compress(pickle.dumps(final_model))
    writer.write(compressed_data)
    await writer.drain()
    print(f"[SERVER] Sent Final Model to Client {client_id}")


    async with lock:
        count += 1

    if count == semaphore.active():
        clients.clear()
        ciphertexts.clear()
        encrypted_shares.clear()
        decrypted_shares.clear()
        aggregated_ciphertext = None
        aggregated_shares.clear()
        aggregated_shamir_secret = None
        count_temp = 0
        await semaphore.finalize_round()
        scores = []
        count = 0
        print(f"[SERVER] Round completed, server is ready for next round.")

    while count > 0:
        print(f"[SERVER] Waiting for all clients to finish ({client_id})...")
        await asyncio.sleep(1)

    # ====== End of Critical Section ======
    await semaphore.signal()

    return True


# ======= Start Server =======
async def main():
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')

    server = await asyncio.start_server(
        handle_client, HOST, PORT, ssl=ssl_context
    )

    addr = server.sockets[0].getsockname()
    print(f"[SERVER] TLS Server started on {addr}")

    async with server:
        await server.serve_forever()

# Run server
asyncio.run(main())
