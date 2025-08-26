#!/usr/bin/env python3
#
# Solves the "Encryption Two Ways" crypto challenge from LITCTF.
# The script recovers RSA primes p and q by combining information from
# an RSA public key (N = p*q) and a related XOR cipher (A = flag^p, B = flag^q).
#

import sys
import re

# --- Challenge Constants ---
# These values are taken from the netcat connection to the server.

# A = flag ^ p
A = 157542500938059609321147127366709215903865280761402930796852498194316983086274777045153035347470657299388415446830260048914253627239010753996025580390094111694487743159112641632113309875447880958194077315270059859279311561918994552888451775507228544140444638934367967578750262775169674480130223371188979574521

# B = flag ^ q
B = 124605968855813508207307258612831006729721601201990832243888204388581341026628946929965390458893604926958918043038708106253630270723847743141407064874738696809313683842300337384593918574124994733932317459054446598118221245943642151388919492817677083142023717774107715755926786577201814071519008782964213454873

# e = RSA public exponent
E = 65537

# N = p * q (RSA modulus)
N = 19630735965354826080717149626667009379555777228584545913835016304969420956200411875316108612728081074296690667724061100762156312359493274642644631853945594936840189052879985793013057843841424603539112799993501735676507341630716732708547822613540976388360942127559462372692834140564284489180326896802616003297291239334788932739653088993542958981055497144621348392773206879794245392820104940514703171681674495461966384782758907901041147889471807806373930545773138827422095613745815415397503596023079991997038875015069328274742114714185912827262364373697015671378878847003203355677729377904669249568627123200790627849953

# c = pow(flag, e, N) (RSA ciphertext)
C = 19318912578134386410916785608891550714647900327987108040522572890526041890085386531206056166628351441661425236108108169656849485565738749381858741112191115612274680112682956837511873403814947059767337608752213438518062515077519421150450625085520338782556183900014387277154701232830377253377091331290324604441773817240597923608992115824235856864920625769850525037266348249135005789581023226166119670257527276621896593430113129632715958411751522268828801053885195332631319826183688604935924395049225767102295344217881128643694269689308092478853842967959838767959318758398477327428033711371916702254320186408378788277257


def recover_pq_from_xor_with_backtracking(A, B, N):
    """
    Recovers primes p and q given N=p*q, A=flag^p, and B=flag^q.

    This works by reconstructing p and q bit-by-bit from LSB to MSB.
    For each bit, it guesses the corresponding flag bit (0 or 1) and calculates
    the potential bits of p and q. It then checks if the multiplication of the
    partially constructed p and q is consistent with N. If not, it backtracks.
    """
    nbits = (N.bit_length() + 1) // 2
    # Increase recursion limit for deep searches, typical for 1024-bit primes.
    sys.setrecursionlimit(max(10000, nbits + 100))

    # Pre-compute masks for checking partial products efficiently.
    N_bits_mask = [(1 << (i + 1)) - 1 for i in range(nbits)]

    def search(i, p, q):
        """Recursively search for the correct bits of p and q at position i."""
        if i == nbits:
            # Base case: if we've built all bits, check if the final product is N.
            return (p, q) if p * q == N else None

        # Extract the i-th bits from the known XOR ciphertexts.
        ai = (A >> i) & 1
        bi = (B >> i) & 1
        mask = N_bits_mask[i]

        # Iterate through the two possibilities for the i-th bit of the flag.
        for flag_bit in (0, 1):
            # Calculate the potential i-th bits of p and q based on the guessed flag bit.
            p_bit = ai ^ flag_bit
            q_bit = bi ^ flag_bit

            # Construct the partial primes up to the i-th bit.
            p_partial = p | (p_bit << i)
            q_partial = q | (q_bit << i)

            # THE CRUCIAL CHECK: Is (p_partial * q_partial) consistent with N so far?
            # This prunes the search space dramatically, making the search feasible.
            if (p_partial * q_partial) & mask == (N & mask):
                # If consistent, recurse to the next bit.
                result = search(i + 1, p_partial, q_partial)
                if result is not None:
                    return result # Solution found, propagate it up.
        
        return None # No solution found down this path.

    # Start the search from the LSB (bit 0) with initial p and q as 0.
    result = search(0, 0, 0)
    if result is None:
        raise ValueError("Backtracking failed. Could not recover p and q.")
    
    p, q = result
    # Final sanity check to ensure the recovered primes are correct.
    if p * q != N:
        raise ValueError("Recovered p and q do not multiply to N. Logic error.")
    
    return p, q


def read_all_ints_from_stdin():
    """Utility function to parse the 5 integers from stdin."""
    data = sys.stdin.read()
    nums = list(map(int, re.findall(r"-?\d+", data)))
    if len(nums) < 5:
        raise ValueError("Expected at least 5 integers: A, B, e, N, c")
    return nums[0], nums[1], nums[2], nums[3], nums[4]


def main():
    """Main function to solve the challenge."""
    print("[-] Starting recovery of primes p and q. This may take a moment...")
    p, q = recover_pq_from_xor_with_backtracking(A, B, N)
    print("[+] Successfully recovered p and q!")

    # With p known, we can easily find the flag by XORing it with A.
    # We can also use B and q as a sanity check.
    m_from_p = A ^ p
    m_from_q = B ^ q
    if m_from_p != m_from_q:
        raise ValueError("Mismatch between recovered messages. Something is wrong.")
    
    flag_int = m_from_p
    
    # Optional: Verify our recovered flag against the RSA ciphertext.
    # This confirms our entire solution is correct.
    try:
        if pow(flag_int, E, N) == C:
            print("[+] RSA verification successful!")
        else:
            print("[!] Warning: RSA verification failed.")
    except Exception as e:
        print(f"[!] RSA verification skipped: {e}")

    # Convert the flag integer back to bytes to read it.
    flag_bytes = flag_int.to_bytes((flag_int.bit_length() + 7) // 8, 'big')
    
    print("\n" + "="*40)
    # The flag is usually ASCII, so we decode and print.
    try:
        flag_str = flag_bytes.decode('utf-8', errors='ignore')
        print(f"[*] Recovered Flag: {flag_str}")
    except:
        print(f"[*] Recovered Flag (in bytes): {flag_bytes}")
    print("="*40)


if __name__ == "__main__":
    main()