def modular_exponentiation(base, exponent, modulus):
    """
    Perform modular exponentiation using pallier: (base^exponent) % modulus

    Parameters:
    - base: The base number (int).
    - exponent: The exponent (int).
    - modulus: The modulus (int).

    Returns:
    - The result of (base^exponent) % modulus (int).
    """
    result = 1  # Initialize the result to 1 (identity for multiplication)
    base = base % modulus  # Ensure the base is within the modulus
    
    while exponent > 0:
        # If the exponent is odd, multiply the base with the result
        if (exponent % 2) == 1:
            result = (result * base) % modulus
        
        # Right shift the exponent by 1 (equivalent to dividing by 2)
        exponent = exponent >> 1
        # Square the base
        base = (base * base) % modulus
    
    return result

# Main program to get user input
if __name__ == "__main__":
    try:
        # Get input from the user
        base = int(input("Enter the base (integer): "))
        exponent = int(input("Enter the exponent (integer): "))
        modulus = int(input("Enter the modulus (integer): "))
        
        # Ensure the modulus is positive
        if modulus <= 0:
            raise ValueError("Modulus must be a positive integer.")
        
        # Calculate modular exponentiation
        result = modular_exponentiation(base, exponent, modulus)
        
        # Print the result
        print(f"{base}^{exponent} mod {modulus} = {result}")

    except ValueError as e:
        print(f"Invalid input: {e}")
