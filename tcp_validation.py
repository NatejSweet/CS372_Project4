import os
# Read in the tcp_addrs_0.txt file.
def read_tcp_addrs(file_name):
    with open(file_name, 'r') as file:
        lines = file.readlines()
        return [line.strip() for line in lines]

# Split the line in two, the source and destination addresses.
def split_tcp_addrs(tcp_addrs):
    return [addr.split() for addr in tcp_addrs]

# Write a function that converts the dots-and-numbers IP addresses into bytestrings.
def convert_ip(ip):
    return bytes([int(num) for num in ip.split('.')])

# Read in the tcp_data_0.dat file.
def read_tcp_data(file_name):
    with open(file_name, "rb") as fp:
        tcp_data = fp.read()
        tcp_length = len(tcp_data)
    return tcp_data, tcp_length

# Write a function that generates the IP pseudo header bytes from the IP addresses from tcp_addrs_0.txt and the TCP length from the tcp_data_0.dat file.
def generate_pseudo_header(tcp_addrs, tcp_len):
    source_ip = convert_ip(tcp_addrs[0])
    dest_ip = convert_ip(tcp_addrs[1])
    return source_ip + dest_ip + b'\x00' + b'\x06' + tcp_len.to_bytes(2, 'big')

# Build a new version of the TCP data that has the checksum set to zero.
def zero_checksum(tcp_data):
    return tcp_data[:16] + b'\x00\x00' + tcp_data[18:]

# Concatenate the pseudo header and the TCP data with zero checksum.
def concatenate(tcp_data, pseudo_header):
    return pseudo_header + tcp_data

# Compute the checksum of that concatenation
def compute_checksum(pseudoheader, checksum):
    if len(checksum) % 2 == 1:
        checksum += b'\x00'

    data = pseudoheader + checksum
    offset = 0 
    total = 0  

    while offset < len(data):
        word = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2 
        total += word
        total = (total & 0xffff) + (total >> 16)
    
    return (~total) & 0xffff
    
# Extract the checksum from the original data in tcp_data_0.dat.
def extract_checksum(tcp_data):
    return int.from_bytes(tcp_data[16:18], "big")

# Compare the two checksums. If they’re identical, it works!
def compare_checksums(checksum1, checksum2):
    return checksum1 == checksum2

def main():
    for i in range(10):
        tcp_addrs = read_tcp_addrs(f'./tcp_data/tcp_addrs_{i}.txt')
        tcp_addrs = split_tcp_addrs(tcp_addrs)[0]

        tcp_data, tcp_len = read_tcp_data(f'./tcp_data/tcp_data_{i}.dat')
        tcp_data_zerod = zero_checksum(tcp_data)

        pseudo_header = generate_pseudo_header(tcp_addrs, tcp_len)
        checksum = compute_checksum(pseudo_header, tcp_data_zerod)

        original_checksum = extract_checksum(tcp_data)
        print(compare_checksums(checksum, original_checksum))
if __name__ == '__main__':
    main()
