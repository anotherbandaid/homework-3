"""This module contains implementations of classical cryptography,
modern cryptography, and tools for cryptanalysis."""

import mathematics


####################
## Main Execution ##
####################
def main():
    """Function for testing and running functions in this file.

    """
    input_string = "0123456789abcdeffedcba9876543210"
    # input_string = "ea835cf00445332d655d98ad8596b0c5"
    input_string = "8123456789abcdeffedcba9876543210"
    input_key = "0f1571c947d9e8590cb7add6af7f6798"
    input_key = "0f1571c947d9e8591cb7add6af7f6798"

    print("\n\nPlaintext:\n", input_string)
    print("\nKey:\n", input_key)
    
    # Round 0
    state = bytes_to_state(input_string)
    round_key = key_to_matrix(input_key)
    round_key_state = matrix_to_state(round_key)

    for i in range(4):
        print("{:s} & & & & {:s} \\\\".format(" ".join(state[i]), " ".join(round_key_state[i])))
    
    print("\\hline")

    # Generate Round Constants
    Rcons = ["01", "02", "04", "08", "10", "20", "40", "80", "1B", "36"]

    # Round 1 - 9
    mixed = state
    for round_ in range(9):
        state = add_round_key(mixed, round_key_state)
        substituted = substitute_bytes(state, AES_SBOX)
        shifted = shift_rows(substituted)
        mixed = mix_columns(shifted, AES_MIX_COL)
        round_key = iterate_round_key(round_key, Rcons[round_])
        round_key_state = matrix_to_state(round_key)

        for i in range(4):
            col1 = " ".join(state[i])
            col2 = " ".join(substituted[i])
            col3 = " ".join(shifted[i])
            col4 = " ".join(mixed[i])
            col5 = " ".join(round_key_state[i])
            print("{:s} & {:s} & {:s} & {:s} & {:s} \\\\".format(col1, col2, col3, col4,  col5))

        print("\\hline")

    # Round 10
    state = add_round_key(mixed, round_key_state)
    substituted = substitute_bytes(state, AES_SBOX)
    shifted = shift_rows(substituted)
    round_key = iterate_round_key(round_key, Rcons[9])
    round_key_state = matrix_to_state(round_key)


    for i in range(4):
        col1 = " ".join(state[i])
        col2 = " ".join(substituted[i])
        col3 = " ".join(shifted[i])
        col5 = " ".join(round_key_state[i])
        print("{:s} & {:s} & {:s} & & {:s} \\\\".format(col1, col2, col3, col5))

    print("\\hline")

    
    # Get ciphertext
    ciphertext = add_round_key(shifted, round_key_state)

    for i in range(4):
        col1 = " ".join(ciphertext[i])
        print("{:s} & & & & \\\\".format(col1))

    print("\\hline")

    print("\n\n")



####################
## AES Encryption ##
####################
AES_SBOX = \
    [
        ['63', '7c', '77', '7b', 'f2', '6b', '6f', 'c5',
         '30', '01', '67', '2b', 'fe', 'd7', 'ab', '76'],
        ['ca', '82', 'c9', '7d', 'fa', '59', '47', 'f0',
         'ad', 'd4', 'a2', 'af', '9c', 'a4', '72', 'c0'],
        ['b7', 'fd', '93', '26', '36', '3f', 'f7', 'cc',
         '34', 'a5', 'e5', 'f1', '71', 'd8', '31', '15'],
        ['04', 'c7', '23', 'c3', '18', '96', '05', '9a',
         '07', '12', '80', 'e2', 'eb', '27', 'b2', '75'],
        ['09', '83', '2c', '1a', '1b', '6e', '5a', 'a0',
         '52', '3b', 'd6', 'b3', '29', 'e3', '2f', '84'],
        ['53', 'd1', '00', 'ed', '20', 'fc', 'b1', '5b',
         '6a', 'cb', 'be', '39', '4a', '4c', '58', 'cf'],
        ['d0', 'ef', 'aa', 'fb', '43', '4d', '33', '85',
         '45', 'f9', '02', '7f', '50', '3c', '9f', 'a8'],
        ['51', 'a3', '40', '8f', '92', '9d', '38', 'f5',
         'bc', 'b6', 'da', '21', '10', 'ff', 'f3', 'd2'],
        ['cd', '0c', '13', 'ec', '5f', '97', '44', '17',
         'c4', 'a7', '7e', '3d', '64', '5d', '19', '73'],
        ['60', '81', '4f', 'dc', '22', '2a', '90', '88',
         '46', 'ee', 'b8', '14', 'de', '5e', '0b', 'db'],
        ['e0', '32', '3a', '0a', '49', '06', '24', '5c',
         'c2', 'd3', 'ac', '62', '91', '95', 'e4', '79'],
        ['e7', 'c8', '37', '6d', '8d', 'd5', '4e', 'a9',
         '6c', '56', 'f4', 'ea', '65', '7a', 'ae', '08'],
        ['ba', '78', '25', '2e', '1c', 'a6', 'b4', 'c6',
         'e8', 'dd', '74', '1f', '4b', 'bd', '8b', '8a'],
        ['70', '3e', 'b5', '66', '48', '03', 'f6', '0e',
         '61', '35', '57', 'b9', '86', 'c1', '1d', '9e'],
        ['e1', 'f8', '98', '11', '69', 'd9', '8e', '94',
         '9b', '1e', '87', 'e9', 'ce', '55', '28', 'df'],
        ['8c', 'a1', '89', '0d', 'bf', 'e6', '42', '68',
         '41', '99', '2d', '0f', 'b0', '54', 'bb', '16']
    ]


AES_ISBOX = \
    [
        ['52', '09', '6a', 'd5', '30', '36', 'a5', '38',
         'bf', '40', 'a3', '9e', '81', 'f3', 'd7', 'fb'],
        ['7c', 'e3', '39', '82', '9b', '2f', 'ff', '87',
         '34', '8e', '43', '44', 'c4', 'de', 'e9', 'cb'],
        ['54', '7b', '94', '32', 'a6', 'c2', '23', '3d',
         'ee', '4c', '95', '0b', '42', 'fa', 'c3', '4e'],
        ['08', '2e', 'a1', '66', '28', 'd9', '24', 'b2',
         '76', '5b', 'a2', '49', '6d', '8b', 'd1', '25'],
        ['72', 'f8', 'f6', '64', '86', '68', '98', '16',
         'd4', 'a4', '5c', 'cc', '5d', '65', 'b6', '92'],
        ['6c', '70', '48', '50', 'fd', 'ed', 'b9', 'da',
         '5e', '15', '46', '57', 'a7', '8d', '9d', '84'],
        ['90', 'd8', 'ab', '00', '8c', 'bc', 'd3', '0a',
         'f7', 'e4', '58', '05', 'b8', 'b3', '45', '06'],
        ['d0', '2c', '1e', '8f', 'ca', '3f', '0f', '02',
         'c1', 'af', 'bd', '03', '01', '13', '8a', '6b'],
        ['3a', '91', '11', '41', '4f', '67', 'dc', 'ea',
         '97', 'f2', 'cf', 'ce', 'f0', 'b4', 'e6', '73'],
        ['96', 'ac', '74', '22', 'e7', 'ad', '35', '85',
         'e2', 'f9', '37', 'e8', '1c', '75', 'df', '6e'],
        ['47', 'f1', '1a', '71', '1d', '29', 'c5', '89',
         '6f', 'b7', '62', '0e', 'aa', '18', 'be', '1b'],
        ['fc', '56', '3e', '4b', 'c6', 'd2', '79', '20',
         '9a', 'db', 'c0', 'fe', '78', 'cd', '5a', 'f4'],
        ['1f', 'dd', 'a8', '33', '88', '07', 'c7', '31',
         'b1', '12', '10', '59', '27', '80', 'ec', '5f'],
        ['60', '51', '7f', 'a9', '19', 'b5', '4a', '0d',
         '2d', 'e5', '7a', '9f', '93', 'c9', '9c', 'ef'],
        ['a0', 'e0', '3b', '4d', 'ae', '2a', 'f5', 'b0',
         'c8', 'eb', 'bb', '3c', '83', '53', '99', '61'],
        ['17', '2b', '04', '7e', 'ba', '77', 'd6', '26',
         'e1', '69', '14', '63', '55', '21', '0c', '7d']
    ]

AES_MIX_COL = \
    [
        ["02", "03", "01", "01"],
        ["01", "02", "03", "01"],
        ["01", "01", "02", "03"],
        ["03", "01", "01", "02"]
    ]

AES_INV_MIX = \
    [
        ["0e", "0b", "0d", "09"],
        ["09", "0e", "0b", "0d"],
        ["0d", "09", "0e", "0b"],
        ["0b", "0d", "09", "0e"]
    ]

AES_MODULUS = "100011011"



def bytes_to_state(input_string):
    """Convert 16 byte hexadecimal string into AES state array format.

    """
    
    # Verify correct input
    if len(input_string) != 32:
        raise ValueError("Input is not a 16 byte hexadecimal string.")

    # Build state array
    state_array = [[], [], [], []]
   
    for i in range(0, 32, 8):
        for j in range(4):
            offset = j * 2
            state_array[j].append(input_string[i + offset:i + 2 + offset])

    return(state_array)


def substitute_bytes(state_array, s_box):
    """Apply AES S-Box transformation on AES state array.
    
    """
    output = copy_state_array(state_array)

    for row in range(4):
        for column in range(4):
            output[row][column] = aes_sbox_lookup(
                output[row][column], s_box)
    
    return(output) 


def shift_rows(state_array):
    """Apply AES row shift of AES state array.
    
    """
    output = []
    for row in range(4):
        output.append(rotate_list(state_array[row], row))

    return(output)


def mix_columns(state_array, mix_matrix):
    """Apply matrix multiplication of AES column mix matrix.

    """
    output = copy_state_array(state_array)
    for row in range(4):
        for col in range(4):
            row_list = mix_matrix[row]
            col_list = get_column(state_array, col)
            output[row][col] = matrix_multiply_element(row_list, col_list)
    
    return(output)


def add_round_key(state_array, round_key):
    """Bitwise XOR of the AES state array with the round key.

    """
    output = copy_state_array(state_array)

    for row in range(4):
        for col in range(4):
            temp1 = int(state_array[row][col], 16)
            temp2 = int(round_key[row][col], 16)
            output[row][col] = "{:02x}".format(temp1 ^ temp2)

    return(output)


#######################
## AES Key Expansion ##
#######################
def key_to_matrix(key):
    hex_length = len(key) // 4
    
    key_words = []

    for i in range(4):
        sub_word = key[i * hex_length: i * hex_length + hex_length]
        
        word_bytes = []
        for j in range(0, hex_length, 2):
            word_bytes.append(sub_word[j:j + 2])

        key_words.append(word_bytes)

    return(key_words)


def matrix_to_state(key_matrix):
    output = [[], [], [], []]

    for i in range(4):
        for j in range(4):
            output[j].append(key_matrix[i][j])

    return(output)


def iterate_round_key(key_matrix, r_const):
    # Copy input matrix
    output = []

    for row in range(len(key_matrix)):
        output.append([])
        for col in range(len(key_matrix[0])):
            output[row].append(key_matrix[row][col])

    # generate_round_key with last row of input
    z = round_key_generation(output[-1], r_const)

    # XOR rows
    # for row in range(3), row + 1 = row + 1 XOR row
    output[0] = xor_lists(z, output[0])
    for i in range(len(output) - 1):
        output[i + 1] = xor_lists(output[i], output[i + 1])

    return(output)


def round_key_generation(byte_list, r_const):
    # Left rotation
    output = rotate_list(byte_list, 1)
    # print("RotWord (w) = {:s} = x".format(" ".join(output)))

    # Substitute Bytes
    for i in range(len(output)):
        output[i] = aes_sbox_lookup(output[i], AES_SBOX)
    # print("SubWord (x) = {:s} = y".format(" ".join(output)))

    # Round Constant XOR
    output[0] = "{:2x}".format(int(output[0], 16) ^ int(r_const, 16))
    # print("Rcon () = {:s} 00 00 00".format(r_const))
    # print("y $\\oplus$ Rcon () = {:s} = z".format("  ".join(output)))
    
    return(output)


#############################
## Common Helper Functions ##
#############################
def hex_to_bin(hex_string):
    """Converts a hexadecimal string into a binary string.

    """
    length = len(hex_string) * 4
    return("{:0{width}b}".format(int(hex_string, 16), width=length))


def bin_to_hex(bin_string):
    """Converts a binary string into a hexadecimal string.

    """
    if len(bin_string) % 4 == 0:
        length = len(bin_string) // 4
    else:
        length = len(bin_string) // 4 + 1

    return("{:0{width}x}".format(int(bin_string, 2), width=length))


def xor_lists(hex_list1, hex_list2):
    """XOR two lists of hexadecimal elements.

    """
    
    output = []

    for i in range(len(hex_list1)):
        input1 = int(hex_list1[i], 16)
        input2 = int(hex_list2[i], 16)

        output.append("{:02x}".format(input1 ^ input2))

    return(output)
        

def copy_state_array(state_array):
    """Return a copy of the supplied state array.
    
    """
    output = [[], [], [], []]

    for row in range(len(state_array)):
        for col in range(len(state_array[0])):
            output[row].append(state_array[row][col])

    return(output)


def rotate_list(list_obj, n):
    """Returns a copy of a list rotated left 'n' times.

    """
    return(list_obj[n:] + list_obj[:n])


def aes_sbox_lookup(hex_byte, sbox):
    """Returns the corresponding S-Box lookup for the given byte.

    """
    row = int(hex_byte[0], 16)
    column = int(hex_byte[1], 16)
    return(sbox[row][column])


def get_column(state_array, index):
    """Return of list of the column at the given index.

    """
    output = []

    for i in range(4):
        output.append(state_array[i][index])

    return(output)


def matrix_multiply_element(row, column):
    """Returns the element for matrix multiplication of a row by column.

    """
    output = "0"
    
    for i in range(4):
        row_bin = hex_to_bin(row[i])
        col_bin = hex_to_bin(column[i])

        temp = mathematics.gf2_multiplication(row_bin, col_bin, AES_MODULUS)
        output = mathematics.gf2_addition(output, temp)

    return(bin_to_hex(output))


##################
## Execute Main ##
##################
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        quit()
