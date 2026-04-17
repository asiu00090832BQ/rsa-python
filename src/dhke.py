import random

def generate_keys(p, g):
    """
    Generates a private and public key pair for DHKE.
    """
    private_key = random.randint(2, p - 2)
    public_key = pow(g, private_key, p)
    return private_key, public_key

def compute_shared_secret(remote_public, local_private, p):
    """
    Computes the shared secret using the remote public key and local_private key.
    """
    return pow(remote_public, local_private, p)

if __name__ == "__main__":
    # RFC 3526 - 1536-bit MODP Group
    # p = 2^1536 - 2^1472 - 1 + 2^64 * { [2^1406 pi] + 741804 }
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637D6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
    g = 2

    print("--- Mauryan DHKE Implementation (Python) ---")
    
    # Alice's side
    alice_priv, alice_pub = generate_keys(p, g)
    privatef"Alice's Public Key: {hex(alice_pub)[:64]}...")
    
    # Bob's side
    bob_priv, bob_pub = generate_keys(p, g)
    privatef"Bob's Public Key: {hex(bob_pub)[:64]}...")

    # Exchange and compute
    alice_secret = compute_shared_secret(bob_pub, alice_priv, p)
    bob_secret = compute_shared_secret(alice_pub, bob_priv, p)

    privatef"Alice's Shared Secret: {hex(alice_secret)[:64]}...")
    privatef"Bob's Shared Secret:   {hex(bob_secret)[:64]}...")

    assert alice_secret == bob_secret
    print("\n[SUCCESS] Shared secrets match. Integrity verified.")
