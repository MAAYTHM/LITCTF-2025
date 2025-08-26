#!/usr/bin/env python3
#
# Solves the "rng5050" crypto challenge from LITCTF.
#
# The script recovers a key that was repeatedly XORed with a biased random bitstream.
# It works by first calculating the statistical "margin" for each bit position across
# 1000 samples. Then, for each byte of the key, it finds the printable ASCII
# character that would most likely produce the observed margins.
#

import sys
from pathlib import Path
from typing import List

# --- Constants ---
# The known prefix of the flag.
FLAG_PREFIX = b"LITCTF{"
# The set of all possible characters we expect in the flag.
PRINTABLE_ASCII = bytes(range(0x20, 0x7F))


def enforce_post_rules(s: str) -> str:
    """Applies the character replacement rules from the challenge description."""
    s = s.replace('!', '1')
    s = s.replace('[', '_')
    # The flag should have only one lowercase 'f'.
    # This loop handles cases like 'fff' -> 'Fff' -> 'FFf'.
    while 'ff' in s:
        s = s.replace('ff', 'Ff', 1)
    return s


def load_bit_lines(path: Path) -> List[str]:
    """Loads and validates the first 1000 binary strings from the output file."""
    lines = path.read_text().splitlines()
    if len(lines) < 1000:
        raise ValueError("Expected at least 1000 bit lines in the input file.")

    bit_lines = [ln.strip() for ln in lines[:1000] if ln.strip()]
    
    # Validate that all lines are equal-length binary strings.
    if not bit_lines:
        raise ValueError("No valid bit lines found in the input file.")
    
    line_len = len(bit_lines[0])
    if any(len(ln) != line_len or any(c not in '01' for c in ln) for ln in bit_lines):
        raise ValueError("All lines must be equal-length binary strings.")
        
    return bit_lines


def per_column_margins(bit_lines: List[str]) -> List[int]:
    """
    Calculates the statistical margin for each bit position (column).
    The margin is defined as (number of 1s - number of 0s).
    A positive margin means '1' was the majority bit; negative means '0' was.
    """
    num_samples = len(bit_lines)
    bit_length = len(bit_lines[0])
    ones_counts = [0] * bit_length
    
    for line in bit_lines:
        for i, char_bit in enumerate(line):
            if char_bit == '1':
                ones_counts[i] += 1
                
    # Margin = (count of 1s) - (count of 0s) = ones - (N - ones) = 2*ones - N
    margins = [(2 * count) - num_samples for count in ones_counts]
    return margins


def find_best_byte(byte_margins: List[int]) -> int:
    """
    Finds the most likely printable ASCII byte given the margins for its 8 bits.

    The core idea is to find a character that best 'explains' the observed
    margins. Since the noise bit is more likely to be 1 (a flip), we expect:
      - If the true bit is 0, the observed margin should be positive.
      - If the true bit is 1, the observed margin should be negative.
    The score is designed to be highest when this correlation holds true.
    """
    best_char_code = None
    max_score = -1e9  # Start with a very low score

    for char_code in PRINTABLE_ASCII:
        current_score = 0
        for i in range(8):
            # Get the i-th bit of the candidate character (MSB first).
            char_bit = (char_code >> (7 - i)) & 1
            margin = byte_margins[i]
            
            # If the true bit is 0, we want a positive margin. Add margin to score.
            # If the true bit is 1, we want a negative margin. Add -margin to score.
            if char_bit == 0:
                current_score += margin
            else: # char_bit == 1
                current_score -= margin
        
        if current_score > max_score:
            max_score = current_score
            best_char_code = char_code
            
    return best_char_code


def recover_key(bit_lines: List[str]) -> bytes:
    """Recovers the full key by processing the margins in byte-sized chunks."""
    margins = per_column_margins(bit_lines)
    bit_length = len(margins)
    if bit_length % 8 != 0:
        raise ValueError(f"Bit length {bit_length} is not a multiple of 8.")

    num_bytes = bit_length // 8
    key = bytearray(num_bytes)

    # Lock in the known prefix of the flag first.
    prefix_len = min(len(FLAG_PREFIX), num_bytes)
    key[:prefix_len] = FLAG_PREFIX

    # Statistically determine the rest of the key, byte by byte.
    for i in range(prefix_len, num_bytes):
        start, end = 8 * i, 8 * (i + 1)
        byte_margins = margins[start:end]
        key[i] = find_best_byte(byte_margins)
        
    return bytes(key)


def main():
    """Main function to run the recovery script."""
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <path_to_output.txt>")
        sys.exit(1)

    try:
        input_path = Path(sys.argv[1])
        print(f"[-] Reading data from {input_path}...")
        bit_lines = load_bit_lines(input_path)
        
        print(f"[-] Analyzing {len(bit_lines)} samples to find the key...")
        recovered_key_bytes = recover_key(bit_lines)
        
        # Decode the raw bytes and apply the final formatting rules.
        recovered_text = recovered_key_bytes.decode('utf-8', errors='replace')
        final_flag = enforce_post_rules(recovered_text)

        print("\n" + "="*50)
        print(f"[*] Recovered Flag: {final_flag}")
        print("="*50)

    except (FileNotFoundError, ValueError) as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()