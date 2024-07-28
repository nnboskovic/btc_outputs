import binascii

import base58
from Crypto.Hash import SHA256, RIPEMD160


def pubkey_to_address(pubkey: str) -> str:
    if not all(c in '0123456789abcdefABCDEF' for c in pubkey):
        raise ValueError(f"Invalid pubkey: {pubkey}. Contains non-hexadecimal characters.")

    # Step 1: SHA-256 hashing on the public key
    sha256_result = SHA256.new(bytes.fromhex(pubkey)).digest()

    # Step 2: RIPEMD-160 hashing on the result of SHA-256 using PyCryptodome
    ripemd160 = RIPEMD160.new()
    ripemd160.update(sha256_result)
    ripemd160_result = ripemd160.digest()

    # Step 3: Add version byte (0x00 for Mainnet)
    versioned_payload = b"\x00" + ripemd160_result

    # Step 4 and 5: Calculate checksum and append to the payload
    checksum = SHA256.new(SHA256.new(versioned_payload).digest()).digest()[:4]
    binary_address = versioned_payload + checksum

    # Step 6: Encode the binary address in Base58
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
    try:
        # Check if the script is unusually long
        if len(script) > 50:  # Normal P2PKH script is 50 characters
            # Extract only the relevant part of the script
            script = script[:50]

        if not script.startswith("76a914"):  # OP_DUP OP_HASH160
            raise ValueError(f"Script does not start with P2PKH pattern: {script[:10]}...")

        pubkey_hash = script[6:46]

        if len(pubkey_hash) != 40:  # 20 bytes in hex = 40 characters
            raise ValueError(f"Invalid pubkey hash length: {pubkey_hash}")

        version_byte = b"\x00" if mainnet else b"\x6f"
        payload = version_byte + binascii.unhexlify(pubkey_hash)
        checksum = SHA256.new(SHA256.new(payload).digest()).digest()[:4]
        return base58.b58encode(payload + checksum).decode()
    except Exception as e:
        print(f"Error in script_to_p2pkh_address: {e}")
        print(f"Script (truncated): {script[:50]}...")
        return f"INVALID_P2PKH_SCRIPT_{script[:10]}"


def derive_address(script_pub_key: dict, script_pub_key_asm: str) -> str:
    script_type = script_pub_key.get("type", "")

    if "address" in script_pub_key:
        return script_pub_key["address"]

    if "addresses" in script_pub_key and script_pub_key["addresses"]:
        return script_pub_key["addresses"][0]

    hex_script = script_pub_key.get("hex", "")

    try:
        if script_type == "pubkey":
            pubkey = script_pub_key_asm.split()[0]
            return pubkey_to_address(pubkey)

        if script_type == "pubkeyhash" or (script_type == "" and hex_script.startswith("76a914")):
            return script_to_p2pkh_address(hex_script)

        if script_type == "scripthash" or (script_type == "" and hex_script.startswith("a914")):
            return script_to_p2sh_address(hex_script)

        if script_type == "multisig":
            return script_to_p2sh_address(hex_script)

        if script_type == "witness_v0_keyhash":
            return script_pub_key.get("address", "")  # Bech32 address should be provided

        if script_type == "witness_v0_scripthash":
            return script_pub_key.get("address", "")  # Bech32 address should be provided

        # Handle "cosmic ray" transactions with long, repeating OP_CHECKSIG
        if script_pub_key_asm.count("OP_CHECKSIG") > 100:
            return f"UNKNOWN_{script_pub_key_asm[:20]}..."

        # fallback
        if "OP_CHECKSIG" in script_pub_key_asm:
            asm_parts = script_pub_key_asm.split()
            if len(asm_parts) == 2 and asm_parts[1] == "OP_CHECKSIG":
                # This is likely a P2PK script
                pubkey = asm_parts[0]
                return pubkey_to_address(pubkey)
            elif "OP_DUP OP_HASH160" in script_pub_key_asm and "OP_EQUALVERIFY OP_CHECKSIG" in script_pub_key_asm:
                # This is likely a P2PKH script
                return script_to_p2pkh_address(hex_script)
        elif "OP_CHECKMULTISIG" in script_pub_key_asm:
            return script_to_p2sh_address(hex_script)

        # If we've reached this point, we couldn't derive an address
        raise ValueError(f"Unable to derive address for script type: {script_type}")

    except Exception as e:
        print(f"Error in derive_address: {e}")
        print(f"Script type: {script_type}")
        print(f"Script pub key: {script_pub_key}")
        print(f"Script pub key ASM: {script_pub_key_asm[:100]}...")  # Print only the first 100 characters
        return f"UNKNOWN_{script_type}"
