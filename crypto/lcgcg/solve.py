#!/usr/bin/env python3
#
# Solves the "lcgcg" crypto challenge from LITCTF.
#
# The solution involves three main steps:
# 1. Crack the final LCG in a 100-layer chain using its three consecutive outputs.
# 2. Mathematically reverse the generation process, working backwards from the
#    final LCG to the root LCG to recover its original parameters (a, b, x).
# 3. Use the recovered root LCG to calculate the value 'r', which is then
#    used to derive the AES key and decrypt the flag.
#

from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes as l2b
from Crypto.Util.Padding import pad, unpad

# --- Challenge Constants from out.txt ---
P = 15471456606036645889  # Modulus for all LCGs
Y0 = 3681934504574973317 # First output of the final LCG
Y1 = 4155039551524372589 # Second output
Y2 = 9036939555423197298 # Third output
IV = bytes.fromhex("6c9315b13f092fbc49adffbf1c770b54")
ENC_FLAG = bytes.fromhex("af9dc7dfd04bdf4b61a1cf5ec6f9537819592e44b4a20c87455d01f67d738c035837915903330b67168ca91147299c422616390dae7be68212e37801b76a74d4")


def crack_lcg(y0, y1, y2, m):
    """
    Recovers the parameters (a, b) of an LCG given three consecutive outputs.
    y1 = (a*y0 + b) % m
    y2 = (a*y1 + b) % m
    Subtracting the equations gives: y2 - y1 = a * (y1 - y0) % m
    From this, we can solve for 'a' and then 'b'.
    """
    diff_y1_y0 = y1 - y0
    diff_y2_y1 = y2 - y1
    
    # a = (y2 - y1) / (y1 - y0) mod m
    a = (diff_y2_y1 * pow(diff_y1_y0, -1, m)) % m
    
    # b = y1 - a*y0 mod m
    b = (y1 - a * y0) % m
    
    # The state x before y0 was generated is found by reversing the formula once:
    # y0 = (a * x + b) % m  =>  x = (y0 - b) / a mod m
    x = ((y0 - b) * pow(a, -1, m)) % m
    
    return a, b, x


def main():
    """Main function to solve the challenge."""
    # === Step 1: Crack the final LCG (LCG_100) ===
    print("[-] Cracking the parameters of the final LCG (LCG_100)...")
    a_curr, b_curr, x_curr = crack_lcg(Y0, Y1, Y2, P)
    print("[+] LCG_100 parameters recovered.")

    # === Step 2: Work backwards to the root LCG (LCG_0) ===
    print("[-] Working backwards through 100 layers of LCGs...")
    # The parameters of LCG_i are (a_i, b_i, x_i).
    # These were generated as 3 consecutive outputs of LCG_{i-1}.
    # So: a_i = lcg_{i-1}.next(), b_i = lcg_{i-1}.next(), x_i = lcg_{i-1}.next()
    # Let the parameters of the previous LCG be a_prev, b_prev.
    # We have:
    #   b_i = (a_prev * a_i + b_prev) % P
    #   x_i = (a_prev * b_i + b_prev) % P
    # Subtracting gives: x_i - b_i = a_prev * (b_i - a_i) % P
    # We can solve for a_prev, then b_prev, then the state of the prev LCG.
    for i in range(99, -1, -1):
        a_prev = ((x_curr - b_curr) * pow(b_curr - a_curr, -1, P)) % P
        b_prev = (b_curr - a_prev * a_curr) % P
        x_prev = ((a_curr - b_prev) * pow(a_prev, -1, P)) % P
        a_curr, b_curr, x_curr = a_prev, b_prev, x_prev

    a_root, b_root, x_root = a_curr, b_curr, x_curr
    print("[+] Successfully recovered the root LCG parameters:")
    print(f"    a = {a_root}\n    b = {b_root}\n    x = {x_root}")

    # === Step 3: Calculate 'r' and derive the AES key ===
    # The gen.py script advances the root LCG state 3 times to create LCG_1,
    # and then one more time to get 'r'. So we need the 4th output.
    print("[-] Calculating the value of 'r' from the root LCG...")
    
    x_n1 = (a_root * x_root + b_root) % P # 1st call for LCG_1.a
    x_n2 = (a_root * x_n1 + b_root) % P   # 2nd call for LCG_1.b
    x_n3 = (a_root * x_n2 + b_root) % P   # 3rd call for LCG_1.x
    r = (a_root * x_n3 + b_root) % P      # 4th call for the AES key
    
    print(f"[+] Found r = {r}")

    # The AES key is the padded square of r.
    aes_key = pad(l2b(r**2), AES.block_size)

    # === Step 4: Decrypt the flag ===
    print("[-] Decrypting the flag with the recovered key...")
    cipher = AES.new(aes_key, AES.MODE_CBC, IV)
    decrypted_padded_flag = cipher.decrypt(ENC_FLAG)
    
    try:
        flag = unpad(decrypted_padded_flag, AES.block_size).decode()
        print("\n" + "="*60)
        print(f"[*] Success! Recovered Flag: {flag}")
        print("="*60)
    except ValueError as e:
        print(f"\n[!] Unpadding failed: {e}. The recovered key may be incorrect.")

if __name__ == "__main__":
    main()