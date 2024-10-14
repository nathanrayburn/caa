import math
import argparse

def calculate_break_probability(n, d):

    n = pow(2,n)
    d = pow(2,d)
    
    """
    Calculate the probability to break the algorithm using the birthday paradox formula.
    
    Parameters:
    n (int): The number of possible nonces.
    d (int): The total number of blocks that can be encrypted securely.
    
    Returns:
    float: The probability of a collision occurring.
    """
    return 1 - math.exp(-n**2 / (2 * d))

def main():
    parser = argparse.ArgumentParser(description="Calculate the probability to break the algorithm using the birthday paradox formula.")
    parser.add_argument("n", type=int, help="The number of possible nonces (e.g., 2**8 for an 8-bit nonce).")
    parser.add_argument("d", type=int, help="The total number of blocks that can be encrypted securely.")
    args = parser.parse_args()

    probability = calculate_break_probability(args.n, args.d)
    print(f"The probability of breaking the algorithm is: {probability}")

if __name__ == "__main__":
    main()
