import socket

PORT = 53
SERVER_IP = "0.0.0.0"

RECORD_TYPE_A = b"\x00\x01"
RECORD_TYPE_AAAA = b"\x00\x1c"
TRUSTFUL_IP = "1.1.1.1"
TTL = 0

REDIRECTS = dict()


def get_flags(flags):
    # Byte 1
    byte1 = bytes(flags[0:1])

    qr = "1"
    opcode = ""
    for bit in range(1, 5):
        opcode += str(ord(byte1) & (1 << bit))
    aa = "1"
    tc = "0"
    rd = "0"

    # Byte 2
    ra = "0"
    z = "000"
    rcode = "0000"
    return int(qr + opcode + aa + tc + rd, 2).to_bytes(1, byteorder='big') + \
           int(ra + z + rcode, 2).to_bytes(1, byteorder='big')


def parse_query(dns_query):
    data = dns_query[12:]

    expected_length = 0
    domain_string = ''
    domain_parts = []
    x = 0
    y = 0

    for byte in data:
        if expected_length == 0:
            if byte == 0:
                break
            expected_length = byte
        else:
            x += 1
            domain_string += chr(byte)
            if x == expected_length:
                domain_parts.append(domain_string)
                domain_string = ""
                x = 0
                expected_length = 0
        y += 1

    requested_record_type = data[y + 1:y + 3]

    return domain_parts, requested_record_type


def get_target_ip(domain: str):

    target_ip = ".".join(domain.split("-"))

    if REDIRECTS.get(target_ip) is None:
        REDIRECTS[target_ip] = True
        print(f"Request for {target_ip} resolved to {TRUSTFUL_IP}")
        return TRUSTFUL_IP
    else:
        REDIRECTS.pop(target_ip)
        print(f"Request for {target_ip} resolved to {target_ip}")
        return target_ip


def generate_body(domain_parts, requested_record_type):
    dns_body = b"\xc0\x0c"
    dns_body += requested_record_type
    dns_body += b"\x00\x01"
    dns_body += int(TTL).to_bytes(4, byteorder='big')

    if requested_record_type != RECORD_TYPE_A:
        print(f"ERROR: unsupported record type: {requested_record_type}")
        exit()

    dns_body += b"\x00\x04"

    target = get_target_ip(domain_parts[0])

    for part in target.split('.'):
        dns_body += bytes([int(part)])

    return dns_body


def parse_question(domain_parts, requested_record_type):
    question_bytes = b""

    for part in domain_parts:
        length = len(part)
        question_bytes += bytes([length])

        for char in part:
            question_bytes += ord(char).to_bytes(1, byteorder='big')

    question_bytes += b"\x00"  # end byte
    question_bytes += requested_record_type
    question_bytes += b"\x00\x01"  # class IN
    return question_bytes


def build_response(dns_query: bytes):
    # Transaction ID
    dns_transaction_id = dns_query[0:2]

    # Get Flags
    flags = get_flags(dns_query[2:4])

    # Question Count
    question_count = b"\x00\x01"

    # Answer Count
    answer_count = b"\x00\x01"

    # Nameserver Count
    nameserver_count = b"\x00\x00"

    # Additional Count
    additional_count = b"\x00\x00"

    # Response Header
    dns_header = dns_transaction_id + flags + question_count + \
                 answer_count + nameserver_count + additional_count

    domain_parts, requested_record_type = parse_query(dns_query)

    # DNS Question
    dns_question = parse_question(domain_parts, requested_record_type)

    # Response Body
    dns_body = generate_body(domain_parts, requested_record_type)

    return dns_header + dns_question + dns_body


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SERVER_IP, PORT))
    print(f"---: DNS Server running at {SERVER_IP}:{PORT} :---")

    while True:
        data, addr = sock.recvfrom(512)
        response = build_response(data)
        sock.sendto(response, addr)


if __name__ == "__main__":
    main()
