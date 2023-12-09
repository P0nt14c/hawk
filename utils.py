from textwrap import wrap


def kill_subprocess(process):
    """Kills the process

    Args:
        process (Process): process to kill
    """
    if process.poll() is None:
        print("[+] Terminating subprocess.")
        process.terminate()
        process.wait()


def split_string_into_chunks(input_string, chunk_size=6):
    # This function will return a list of strings of size 6
    for i in range(0, len(input_string), chunk_size):
        yield input_string[i : i + chunk_size]


def binary_to_ascii(binary_string):
    # Convert binary string to integer
    decimal_value = int(binary_string, 2)

    # Convert integer to ASCII character
    ascii_character = chr(decimal_value)

    # return character
    return ascii_character


def parse(input):
    # split into chunks of 6
    chunks = wrap(input, 6)
    msg = []
    # add 01 to start of string to convert back to 8-bit ascii in binary representation
    for i in chunks:
        msg.append("01" + i)
    string = []
    # convert message to ascii
    for i in msg:
        string.append(binary_to_ascii(i))

    # turn it into a string
    final = "".join(string)

    # print message

    return final


def convert(input):
    # turn ints into binary
    if input == 0:
        return "000"
    elif input == 1:
        return "001"
    elif input == 2:
        return "010"
    elif input == 3:
        return "011"
    elif input == 4:
        return "100"
    elif input == 5:
        return "101"
    elif input == 6:
        return "110"
    elif input == 7:
        return "111"
