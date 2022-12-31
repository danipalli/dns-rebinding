class DnsQuery:
    def __init__(self, raw_query_data: bytes):
        self.raw_query_data: bytes = raw_query_data
        domain, record_type = self.parse_query()

        record_type_a = b"\x00\x01"
        record_type_aaaa = b"\x00\x1c"

        if record_type == record_type_aaaa:
            raise RuntimeError(f"Unsupported record type: AAAA")

        if record_type != record_type_a:
            raise RuntimeError(f"Unsupported record type: {record_type}")

        self.requested_domain: str = domain
        self.requested_record_type: bytes = record_type

    def _get_dns_transaction_id(self) -> bytes:
        return self.raw_query_data[0:2]

    def _get_flags(self) -> bytes:
        flags = self.raw_query_data[2:4]

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

    def _get_question_count(self) -> bytes:
        return b"\x00\x01"

    def _get_answer_count(self) -> bytes:
        return b"\x00\x01"

    def _get_nameserver_count(self) -> bytes:
        return b"\x00\x00"

    def _get_additional_count(self) -> bytes:
        return b"\x00\x00"

    def build_header(self) -> bytes:
        return self._get_dns_transaction_id() + self._get_flags() + \
               self._get_question_count() + self._get_answer_count() + \
               self._get_nameserver_count() + self._get_additional_count()

    def build_question(self, requested_domain: str, requested_record_type: bytes) -> bytes:
        question_bytes = b""

        for part in requested_domain.split("."):
            length = len(part)
            question_bytes += bytes([length])

            for char in part:
                question_bytes += ord(char).to_bytes(1, byteorder='big')

        question_bytes += b"\x00"  # end byte
        question_bytes += requested_record_type
        question_bytes += b"\x00\x01"  # class IN
        return question_bytes

    def build_body(self, resolved_ip: str, record_type: bytes, ttl=0) -> bytes:

        dns_body = b"\xc0\x0c"
        dns_body += record_type
        dns_body += b"\x00\x01"
        dns_body += int(ttl).to_bytes(4, byteorder='big')

        dns_body += b"\x00\x04"

        for part in resolved_ip.split('.'):
            dns_body += bytes([int(part)])

        return dns_body

    def parse_query(self) -> (str, bytes):
        data = self.raw_query_data[12:]

        expected_length = 0
        domain_string = ''
        requested_domain_parts = []
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
                    requested_domain_parts.append(domain_string)
                    domain_string = ""
                    x = 0
                    expected_length = 0
            y += 1

        requested_record_type = data[y + 1:y + 3]

        return ".".join(requested_domain_parts), requested_record_type
