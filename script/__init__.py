import binascii

import base58
from Crypto.Hash import SHA256, RIPEMD160


def pubkey_to_address(pubkey: str) -> str:
    sha256_result = SHA256.new(bytes.fromhex(pubkey)).digest()
    ripemd160 = RIPEMD160.new()
    ripemd160.update(sha256_result)
    ripemd160_result = ripemd160.digest()
    versioned_payload = b"\x00" + ripemd160_result
    checksum = SHA256.new(SHA256.new(versioned_payload).digest()).digest()[:4]
    binary_address = versioned_payload + checksum
    bitcoin_address = base58.b58encode(binary_address).decode("utf-8")
    return bitcoin_address

def script_to_p2sh_address(script: str, mainnet=True) -> str:
    script_bytes = binascii.unhexlify(script)
    sha256 = SHA256.new(script_bytes).digest()
    ripemd160 = RIPEMD160.new(sha256).digest()
    version_byte = b"\x05" if mainnet else b"\xc4"
    payload = version_byte + ripemd160
    checksum = SHA256.new(SHA256.new(payload).digest()).digest()[:4]
    return base58.b58encode(payload + checksum).decode()

def script_to_p2pkh_address(script: str, mainnet=True) -> str:
    pubkey_hash = script.split()[2]
    version_byte = b"\x00" if mainnet else b"\x6f"
    payload = version_byte + binascii.unhexlify(pubkey_hash)
    checksum = SHA256.new(SHA256.new(payload).digest()).digest()[:4]
    return base58.b58encode(payload + checksum).decode()

def derive_address(script_pub_key: dict, script_pub_key_asm: str) -> str:
    script_type = script_pub_key.get("type", "")

    if "address" in script_pub_key:
        return script_pub_key["address"]

    if "addresses" in script_pub_key and script_pub_key["addresses"]:
        return script_pub_key["addresses"][0]

    if script_type == "pubkey":
        pubkey = script_pub_key_asm.split()[0]
        return pubkey_to_address(pubkey)

    if script_type == "pubkeyhash":
        return script_to_p2pkh_address(script_pub_key["hex"])

    if script_type == "scripthash":
        return script_to_p2sh_address(script_pub_key["hex"])

    if script_type == "multisig":
        return script_to_p2sh_address(script_pub_key["hex"])

    if script_type in ["witness_v0_keyhash", "witness_v0_scripthash"]:
        return script_pub_key.get("address", "")  # Bech32 address should be provided

    # fallback
    if "OP_CHECKSIG" in script_pub_key_asm:
        pubkey = script_pub_key_asm.split()[0]
        return pubkey_to_address(pubkey)
    elif "OP_CHECKMULTISIG" in script_pub_key_asm:
        return script_to_p2sh_address(script_pub_key["hex"])

    # return a placeholder if address isn't interpretable
    return f"UNKNOWN_{script_type}"
