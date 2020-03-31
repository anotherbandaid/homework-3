#############
## Modules ##
#############
import mathematics


# Matrix used for AES mix columns
AES_MIX_COL = \
    [
        ["02", "03", "01", "01"],
        ["01", "02", "03", "01"],
        ["01", "01", "02", "03"],
        ["03", "01", "01", "02"]
    ]

# Matrix used for inverse AES mix columns
AES_INV_MIX = \
    [
        ["0e", "0b", "0d", "09"],
        ["09", "0e", "0b", "0d"],
        ["0d", "09", "0e", "0b"],
        ["0b", "0d", "09", "0e"]
    ]

# AES modulus function in bit representaiton
AES_MODULUS = "100011011"


#####################
## AES Mix Columns ##
#####################
def mix_columns(state_array, mix_matrix):
    """Apply matrix multiplication of AES column mix matrix.

    """
    # Make copy of the state array
    output = copy_state_array(state_array)

    # Iterate over each element in the state array
    for row in range(4):
        for col in range(4):
            row_list = mix_matrix[row]
            col_list = get_column(state_array, col)
            # Perform matrix multiplication on each element
            output[row][col] = matrix_multiply_element(row_list,
                                                       col_list)
    
    return(output)


#######################
##  Helper Functions ##
#######################
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

def copy_state_array(state_array):
    """Return a copy of the supplied state array.
    
    """
    output = [[], [], [], []] 

    for row in range(len(state_array)):
        for col in range(len(state_array[0])):
            output[row].append(state_array[row][col])

    return(output)

def get_column(state_array, index):
    """Return of list of the column at the given index.

    """
    output = []

    for i in range(4):
        output.append(state_array[i][index])

    return(output)

def matrix_multiply_element(row, column):
    """Returns a single element of matrix multiplication for a given 
       row & column.

    """
    output = "0"
    
    for i in range(4):
        row_bin = hex_to_bin(row[i])
        col_bin = hex_to_bin(column[i])

        temp = mathematics.gf2_multiplication(row_bin,
                                              col_bin,
                                              AES_MODULUS)
        output = mathematics.gf2_addition(output, temp)

    return(bin_to_hex(output))
