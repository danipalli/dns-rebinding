import socket

from lib.dns import DnsQuery
from lib.dns_resolver import DnsResolver

PORT = 53
SERVER_IP = "0.0.0.0"


def build_dns_response(raw_dns_query: bytes) -> bytes:
    dns_query = DnsQuery(raw_dns_query)

    # Response Header
    dns_header = dns_query.build_header()

    # DNS Question
    requested_domain, requested_record_type = dns_query.parse_query()
    dns_question = dns_query.build_question(requested_domain, requested_record_type)

    # Response Body
    resolved_ip = DnsResolver(requested_domain).resolve()
    dns_body = dns_query.build_body(resolved_ip, requested_record_type, ttl=0)

    return dns_header + dns_question + dns_body


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SERVER_IP, PORT))
    print(f"---: DNS Server running at {SERVER_IP}:{PORT} :---")

    while True:
        try:
            dns_query_data, addr = sock.recvfrom(512)
            response = build_dns_response(dns_query_data)
            sock.sendto(response, addr)
        except RuntimeError as error:
            print(f"[ERROR] {error}")


if __name__ == "__main__":
    main()
