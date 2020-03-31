# Addition in Galois Field of 2 elements
def gf2_addition(a, b):
    """Addition of two binary strings in Galois Field of two elements.

    """
    if len(a) >= len(b):
        length = len(a)
    else:
        length = len(b)

    # XOR a and b
    return("{:0{width}b}".format(int(a, 2) ^ int(b, 2), width=length))

# Multiplication in Galois Field of 2 elements
def gf2_multiplication(a, b, modulus):
    """Multiplication of two binary strings in Galois Field of two elements.

    """
    output = "0"
    modulus = modulus.lstrip("0")
    length = len(modulus) - 1

    for i in range(len(a)):
        if a[i] == "1":
            degree = len(a) - i - 1
            new_output = gf2_mult_by_x(b, degree, modulus)
            output = "{:b}".format(int(output, 2) ^ int(new_output, 2))
    
    return("{:0{width}b}".format(int(output, 2), width=length))

# Multiplication of a polynomial by x^n in Galois Field of 2 elements
def gf2_mult_by_x(polynomial, degree, modulus):
    """Multiplication of binary string polynomial by polynoimal of form
       x^degree.

    """
    if degree < 1:
        return(polynomial)
    
    # Clean input
    polynomial = polynomial.lstrip("0")
    modulus = modulus.lstrip("0")
    length = len(polynomial)

    while degree > 0:
        # Shift left
        polynomial = polynomial + "0"

        # XOR with modulus if needed
        if polynomial[0] == "1" and len(polynomial) == len(modulus):
            polynomial = "{:b}".format(int(modulus, 2) ^ int(polynomial, 2))
        degree -= 1

    # Return binary of original length
    return("{:0{width}b}".format(int(polynomial, 2), width=length))
