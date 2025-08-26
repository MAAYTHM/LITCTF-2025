#!/usr/bin/env python3
#
# Solves the "signs" crypto challenge from LITCTF.
#
# The vulnerability lies in the signing process. Instead of signing a
# one-way cryptographic hash of the flag, the server signs a reversibly
# padded version of the flag.
#
# The solution is to perform the public key verification step on the signature,
# which recovers the padded flag. We then simply unpad it to get the secret message.
#

from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import unpad

# --- Challenge Constants ---
# These values are taken from the output.txt file provided.

# Public exponent
E = 65537

# RSA modulus (n = p*q)
N = 28720310163698579785590409431244488502590518896114002560615035101872706254575673226701273452266044763379371347175490772833687557638193161203442701390842338726680883158060043516615180759468749002859934101042225109339060841430076215460950001496422014817369538803906181940671644497607497588494548107578139030246710304659121835681466614082387895636652987625506231425635937025960541486880824071903428563319272223449602650009455406871550491147456125891228766395361048688453313744200332284228661669385987688182529904303370060855844163590429388043008170533746319606379457862846257781629063966348729803646974228947658975816397

# The provided signature
SIGNATURE = 13347520343804927847619065202065217836879984453006249407611353191409157302332065972903532015282229744284677309671725411375707706894638641694057135257768299781877077021376667459594883760258356475573151469487363169214012061817199685037363785333516662036329205820120312268834684818014608203312923165179884189461072393686643809307452885991065622646622558149438096015921040528472490412757534851295013865651002130260213027431057502650933677854772978321133895346051674016006963172506825876634054025209746-903230914159762719784407670815205227721887604953882373776567997690485937876918420481954105325928897076354153411410671


def solve():
    """
    Recovers the flag by reversing the flawed signature process.
    """
    # Step 1: Perform the public signature verification step.
    # This works because signing is just encrypting with the private key (d).
    # Verifying is decrypting with the public key (e).
    # result = (sign^d)^e mod n = sign^(d*e) mod n = sign^1 mod n = padded_flag
    print("[-] Reversing the signature with the public key...")
    padded_flag_int = pow(SIGNATURE, E, N)

    # Step 2: Convert the resulting integer back into bytes.
    print("[-] Converting integer to bytes...")
    padded_flag_bytes = long_to_bytes(padded_flag_int)

    # Step 3: Unpad the bytes to remove the PKCS#7 padding.
    # The block size is 256 bytes (2048 bits) as specified in gen.py.
    print("[-] Removing cryptographic padding...")
    try:
        flag_bytes = unpad(padded_flag_bytes, 256)
    except ValueError as e:
        print(f"[!] Unpadding failed: {e}")
        print("[!] This might happen if the recovered data is not correctly padded.")
        return None

    # Step 4: Decode the final bytes to get the flag string.
    try:
        flag = flag_bytes.decode()
        return flag
    except UnicodeDecodeError:
        print("[!] Failed to decode the final bytes as UTF-8.")
        return None


def main():
    """Main function to run the solver."""
    flag = solve()
    if flag:
        print("\n" + "="*50)
        print(f"[*] Success! Recovered Flag: {flag}")
        print("="*50)
    else:
        print("\n[!] Failed to recover the flag.")


if __name__ == "__main__":
    main()