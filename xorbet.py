"""
XOR shellcode ofbuscator - obfuscate shellcode payloads

A small command line tool to obfuscate shellcode, used to evade detection by AV's. Supports multiple output formats for easy use with different loaders.
"""

import argparse
import sys
from dataclasses import dataclass

#Automatically identifies which key type the user has entered, single byte or string
#This can be seen as more user friendly but could have just as easily been achieved with another key type argument by the user
def parse_key(key: str, verbose: bool) -> bytes:
    """
    Parses the command line -k or --key into either a string or single byte key.

    Supports two formats:
    - Hexadecimal: 0x42, prefix with 0x.
    - String: password, secretkey.

    Args:
        key: Key string from user input.
        verbose: Will print additional information to terminal if true.

    Returns:
        Parsed key as bytes.
    
    Examples:
    >>> parse_key("0x42")
    b'B'
    >>> parse_key("SECRET")
    b'SECRET'
    """
    if verbose: print(f"[i] Parsing key...")
    if key.startswith("0x") or key.startswith("0X"):
        byte_string = key[2:]
        if len(byte_string) % 2 != 0:
            byte_string = "0" + byte_string
            if verbose: print(f"[i] Padded hex key to even length: 0x{byte_string}")
        
        if verbose: print(f"[+] Continuing with single-byte key: {bytes.fromhex(byte_string)}")
        return bytes.fromhex(byte_string)
    else:
        if verbose: print(f"[+] Continuing with string key: '{key}'")
        return key.encode("utf-8")

@dataclass
class FormattedData:
    path: str | None
    data: bytes | str
    write_mode: str

#Formats the obfuscated shellcode to the format specified by the user
def format_output(name: str, data, format: str, verbose: bool) -> FormattedData:
    """
    Formats and returns all the necessary data to be used for saving to file or printing to terminal.

    Args:
        name: File output name string from user input.
        data: Binary data input, read from filename provided bu user input.
        format: File output format string from user input.
        verbose: Will print additional information to terminal if true.
    
    Returns:
        A FormattedData dataclass with complete information to print or save to file.

    Examples:
    - Raw binary format:
    >>> out = format_output("test", b'TEST', "raw")
    >>> out.path
        'test.bin'
    >>> out.data
        b'\x16\x07\x11\x16'
    >>> out.write_mode
        'xb'

    - Python format:
    >>> out = format_output("test", b'TEST', "python")
    >>> out.path
        'test.py'
    >>> 'shellcode = b"\x16\x07\x11\x16"' in out.data
        True

    - C format:
    >>> out = format_output("test", b'TEST', "c")
    >>> 'unsigned char buf [] = {' in out.data
        True
    
    - No file output, print to terminal only
    >>> out = format_output(None, b'test', "c")
    >>> out.path is None
        True

    Notes:
        "path" will be returned as None if no argument is passed by the user.
    """
    if verbose: print(f"[i] Formatting data to {format.capitalize()} format...")
    match format:
        case "raw":
            path = None if name == None else f"{name}.bin"
            output = data
            return FormattedData(
                path = path,
                data = output,
                write_mode = "xb"
            )
        case "python":
            #Output as string in Python, with \\x as prefix
            #[0x42, 0xc0] -> \x42\xc0
            path = None if name == None else f"{name}.py"
            hex_string = "".join(f"\\x{byte:02x}" for byte in data)
            output = f'shellcode = b"{hex_string}"\n'
            return FormattedData(
                path = path,
                data = output,
                write_mode = "x"
            )
        case "c":
            path = None if name == None else f"{name}.c"
            #C output starts as an arry of strings to later be pieced together in the end
            lines = ["unsigned char buf[] = {"]
            bytes_per_row = 8
            #Splits the data into chunks of a given number of bytes per row/chunk
            for i in range(0, len(data), bytes_per_row):
                chunk = data[i:i+bytes_per_row]
                #Formats bytes as hex with the prefix 0x, as used in C
                hex_values = ", ".join(f"0x{byte:02x}" for byte in chunk)
                
                if i + bytes_per_row < len(data):
                    lines.append(f"    {hex_values},")
                else:
                    lines.append(f"    {hex_values}")
            #
            lines.append("};")
            lines.append(f"unsigned int buf_len = {len(data)};")
            output = "\n".join(lines)
            return FormattedData(
                path = path,
                data = output,
                write_mode = "x"
            )

#Attempts to save to file with parameters path, write mode and data to write
#Catches FileExistsError if a file with the specified name already exists and exits the program
def save_to_file(path, data, write_mode, verbose: bool):
    """
    Saves data to file using provided file path and write mode

    Args:
        path: String with filename and extension.
        data: Binary data to save.
        write_mode: Specifies what mode to use.

    Raises:
        FileExistsError: If the provided filepath already exists.

    Examples:
    >>> save_to_file("test.bin", b'\x16\x07\x11\x16', "xb")
    """
    try:
        with open(path, write_mode) as file:
            file.write(data)
    except FileExistsError as err:
        raise FileExistsError

#Attempts to read binary input data from specified file
#Catches FileNotFoundError if the specified file does not exist and exits the program
def read_binary_file(path, verbose: bool) -> bytes:
    """
    Reads binary data from binary file input by user.

    Args:
        path: File input name string from user input.
        verbose: Will print additional information to terminal if true.
    
    Returns:
        Bytes of the input data.

    Raises:
        FileNotFoundError: If the provided filepath does not exist.
    
    Examples:
    >>> read_shellcode_file("input.bin")
    b'TEST'
    """
    if verbose: print(f"[i] Attempting to retrieve input-data from '{path}'")
    try:
        with open(path, "rb") as file:
            data = file.read().decode().strip()
            data = data.replace("\\x", "").replace(",","").replace("\\n", "").replace("","")
        return bytes.fromhex(data)
    except FileNotFoundError as err:
        raise FileNotFoundError

#Executes XOR-operation on provided data with specified key
#Usage of the modulo operator ensures proper XOR-operation regardless of single byte key or string key
#The key is iterated through, XOR-operation therefore works for "too" short or long keys
def xor_operation(input_data, key) -> bytes:
    """
    XOR obfuscate data with auto-repeating key.

    Args:
        input: Data to encrypt.
        key: XOR key, repeats if necessary.
        verbose: Will print additional information to terminal if true.

    Returns:
        Encrypted data as bytes (same length as input).

    Notes:
        XOR is symmetric, the same operation both encrypts and decrypts.
    """
    output = []
    for i, byte in enumerate(input_data):
        output.append(byte ^ (key[i % len(key)]))
    return bytes(output)

def main():
    #Instantiates argparse and defines the necessary arguments to be used
    parser = argparse.ArgumentParser("Basic shellcode XOR-obfuscator")
    parser.add_argument("-i", "--input", 
        help="Path to file with binary shellcode.",
        required=True
    )
    parser.add_argument("-o", "--output", 
        help="Filename to save obfuscated shellcode to, will save to current working directory. Optional and will only print output to terminal if left empty. Name only, file will be saved as .bin."
    )
    parser.add_argument("-k", "--key", 
        help="Key to use for XOR-operation, can be either single-byte key or string. For example 0x42, stringkey",
        required=True
    )
    parser.add_argument("-f", "--format", 
        choices=["c", "python", "raw"], 
        help="Specifies the output format of the obfuscated shellcode.",
        required=True
    )
    parser.add_argument("-v", "--verbose",
        action="store_true",
        help="Will print more information to terminal, otherwise minimal amount of information."
    )

    args = parser.parse_args()

    try:
        #Executes XOR-operation with key specified by user as argument, binary read from file, also specified by the user as an argument
        encrypted = xor_operation(read_binary_file(args.input, args.verbose), parse_key(args.key, args.verbose))

        #If no output option is specified by the user, the result is ONLY printed to the terminal, otherwise it is also saved to the file specified by the user
        save_params = format_output(args.output, encrypted, args.format, args.verbose)
        if save_params.path == None:
            if args.verbose: print(f"[i] Printing to terminal...")
            print("\n", save_params.data, "\n")
        else:
            save_to_file(save_params.path, save_params.data, save_params.write_mode, args.verbose)
            print("\n", save_params.data, "\n")
            print(f"[+] Successfully saved as {args.format if args.format == "raw" else args.format.capitalize()} format to {save_params.path}")
    except FileNotFoundError as err:
        print(f"[!] '{args.input}' could not be found, exiting.")
        sys.exit(1)
    except FileExistsError as err:
        print(f"[!] '{save_params.path}' already exists, exiting.")
        sys.exit(1)
    except Exception as unexpected_error:
        print(f"[!] An unexpeceted error has occurred: {unexpected_error}")
        sys.exit(1)
    
if __name__ == "__main__":
    main()