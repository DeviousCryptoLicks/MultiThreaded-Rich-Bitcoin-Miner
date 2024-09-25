import blocksmith
import ecdsa
from hashlib import sha256, new as new_hash
import base58
import multiprocessing
import time

def generate_bitcoin_address(private_key):
    # Generate WIF
    fullkey = '80' + private_key.hex()
    sha256a = sha256(bytes.fromhex(fullkey)).hexdigest()
    sha256b = sha256(bytes.fromhex(sha256a)).hexdigest()
    WIF = base58.b58encode(bytes.fromhex(fullkey + sha256b[:8])).decode()

    # Get public key
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    public_key = '04' + x.to_bytes(32, 'big').hex() + y.to_bytes(32, 'big').hex()

    # Get compressed public key
    compressed_public_key = ('02' if y % 2 == 0 else '03') + x.to_bytes(32, 'big').hex()

    # Get P2PKH address
    hash160 = new_hash('ripemd160')
    hash160.update(sha256(bytes.fromhex(public_key)).digest())
    public_key_hash = '00' + hash160.hexdigest()
    checksum = sha256(sha256(bytes.fromhex(public_key_hash)).digest()).hexdigest()[:8]
    p2pkh_address = base58.b58encode(bytes.fromhex(public_key_hash + checksum)).decode()

    # Get compressed P2PKH address
    hash160 = new_hash('ripemd160')
    hash160.update(sha256(bytes.fromhex(compressed_public_key)).digest())
    public_key_hash = '00' + hash160.hexdigest()
    checksum = sha256(sha256(bytes.fromhex(public_key_hash)).digest()).hexdigest()[:8]
    compressed_p2pkh_address = base58.b58encode(bytes.fromhex(public_key_hash + checksum)).decode()

    return WIF, p2pkh_address, compressed_p2pkh_address

def check_private_key(addresses, private_Key):
    private_key_bytes = bytes.fromhex(private_Key)
    WIF, p2pkh_address, compressed_p2pkh_address = generate_bitcoin_address(private_key_bytes)

    if p2pkh_address in addresses or compressed_p2pkh_address in addresses:
        return private_Key, WIF, p2pkh_address, compressed_p2pkh_address
    return None

def worker_task(addresses, checked_count, found_count):
    paddress_1aphrase = blocksmith.KeyGenerator()
    paddress_1aphrase.seed_input('qwertyuiopasdfghjklzxcvbnm1234567890')
    
    while True:
        private_Key = paddress_1aphrase.generate_key()
        result = check_private_key(addresses, private_Key)
        checked_count.value += 1
        if result:
            with open('brute5.txt', 'a') as file:
                private_Key, WIF, p2pkh_address, compressed_p2pkh_address = result
                output = (
                    f"Found match!\n"
                    f"Private Key: {private_Key}\n"
                    f"WIF: {WIF}\n"
                    f"P2PKH Address: {p2pkh_address}\n"
                    f"Compressed P2PKH Address: {compressed_p2pkh_address}\n"
                )
                file.write(output)
            found_count.value += 1

def main():
    # Load addresses from Addys.txt
    with open('Addys.txt', 'r') as f:
        addresses = [line.strip() for line in f.readlines()]

    # Display how many addresses are loaded
    print(f"Detected {len(addresses)} Bitcoin addresses to check against.\n")

    checked_count = multiprocessing.Value('i', 0)
    found_count = multiprocessing.Value('i', 0)

    # Number of processes to run in parallel
    num_processes = multiprocessing.cpu_count()

    # Create processes
    processes = []
    for _ in range(num_processes):
        p = multiprocessing.Process(target=worker_task, args=(addresses, checked_count, found_count))
        processes.append(p)
        p.start()

    last_checked_count = 0
    try:
        while True:
            # Sleep for 60 seconds
            time.sleep(60)

            # Calculate how many addresses were checked in the last 60 seconds
            checked_in_last_minute = checked_count.value - last_checked_count
            last_checked_count = checked_count.value

            # Update progress output every 60 seconds
            print(f"Checked: {checked_count.value}, Found: {found_count.value}, Speed: {checked_in_last_minute} addresses/minute")

    except KeyboardInterrupt:
        # Clean up processes on exit
        for p in processes:
            p.terminate()

if __name__ == '__main__':
    main()
