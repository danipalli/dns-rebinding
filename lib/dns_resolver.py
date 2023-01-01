import random
import re

IP_FORMAT_REGEX = "^([1-9]-)?[A-Fa-f0-9]{8}$"
REDIRECTS = dict()


class DnsResolver:
    def __init__(self, full_domain: str):
        self.full_domain: str = full_domain
        self.domain_parts: list[str] = full_domain.split(".")

    @staticmethod
    def _hex_to_ip(hexadecimal_ip: str) -> str:
        parsed_ip = []
        for i in range(0, 4):
            parsed_ip.append(str(int(hexadecimal_ip[i * 2:i * 2 + 2], 16)))
        return ".".join(parsed_ip)

    def _resolve_with_state(self) -> str:

        # cleanup to save memory
        if len(REDIRECTS) > 100:
            REDIRECTS.clear()

        target_ip_1 = self._hex_to_ip(self.domain_parts[0][2:])
        target_ip_1_count = int(self.domain_parts[0][0:1])
        target_ip_2 = self._hex_to_ip(self.domain_parts[1][2:])
        target_ip_2_count = int(self.domain_parts[1][0:1])

        if REDIRECTS.get(self.full_domain) is None:
            REDIRECTS[self.full_domain] = [target_ip_1_count - 1, target_ip_2_count]
            return target_ip_1
        else:
            if REDIRECTS[self.full_domain][0] > 0:
                REDIRECTS[self.full_domain] = [REDIRECTS[self.full_domain][0] - 1,
                                               REDIRECTS[self.full_domain][1]]
                return target_ip_1
            else:
                if REDIRECTS[self.full_domain][1] > 1:
                    REDIRECTS[self.full_domain] = [REDIRECTS[self.full_domain][0],
                                                   REDIRECTS[self.full_domain][1] - 1]
                    return target_ip_2
                else:
                    REDIRECTS.pop(self.full_domain)
                    return target_ip_2

    def _resolve_randomly(self) -> str:
        if self.domain_parts[0].__contains__("-") or self.domain_parts[1].__contains__("-"):
            raise RuntimeError(f"Domain can not be parsed: {self.domain_parts}")

        target_ip_id = random.randint(0, 1)
        return self._hex_to_ip(self.domain_parts[target_ip_id])

    def resolve(self) -> str:
        if len(self.domain_parts) < 4 \
                or re.match(IP_FORMAT_REGEX, self.domain_parts[0]) is None \
                or re.match(IP_FORMAT_REGEX, self.domain_parts[1]) is None:
            raise RuntimeError(f"Domain can not be parsed: {self.domain_parts}")

        if self.domain_parts[0].__contains__("-") and self.domain_parts[1].__contains__("-"):
            return self._resolve_with_state()
        else:
            return self._resolve_randomly()
