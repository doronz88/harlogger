from abc import abstractmethod
from typing import List, Mapping, MutableMapping, Union

from cached_property import cached_property


class HTTPTransaction:
    def __init__(self, url: str, http_version: str, headers: Mapping = None, body: Union[str, bytes] = None):
        self.url = url
        self.http_version = http_version
        self.headers = headers
        self.body = body

    @staticmethod
    def parse_transaction(message: str) -> 'HTTPTransaction':
        res = None
        parsed_transaction = HTTPTransaction._parse_fields(message=message)

        if 'Protocol Enqueue' in parsed_transaction:
            info = parsed_transaction.pop('Protocol Enqueue').split()[1:]
            if len(info) == 2:
                method, url = info
                http_version = 'unknown'
            else:
                method, url, http_version = info
            parsed_transaction.pop('Message')
            parsed_transaction.pop('Request')
            res = HTTPRequest(url, method, http_version, parsed_transaction)

        elif 'Protocol Received' in parsed_transaction:
            url = parsed_transaction.pop('Protocol Received').split()[2]
            http_version, status, *status_text = parsed_transaction.pop('Response').split(' ', 2)
            res = HTTPResponse(url, http_version, status, status_text, parsed_transaction)
        return res

    @staticmethod
    def _parse_fields(message: str) -> MutableMapping:
        result = {}
        for line in message.split('\n'):
            if ': ' not in line:
                continue

            line = line.strip()
            k, v = line.split(':', 1)
            k = k.strip()
            v = v.strip()
            result[k] = v
        return result

    @abstractmethod
    def _start_line(self) -> str:
        pass

    @cached_property
    def formatted(self) -> str:
        formatted_headers = ''
        for k, v in self.headers.items():
            formatted_headers += f'{k}: {v}\n'
        return f'{self._start_line()}\n{formatted_headers}\n{self.body if self.body else ""}\n'


class HTTPRequest(HTTPTransaction):
    def __init__(self, url: str, method: str, http_version: str, headers: Mapping = None,
                 body: Union[str, bytes] = None):
        super().__init__(url, http_version, headers, body)
        self.method = method

    def _start_line(self) -> str:
        return f'{self.method} {self.url} {self.http_version}'


class HTTPResponse(HTTPTransaction):
    def __init__(self, url: str, http_version: str, status: int, status_text: List, headers: Mapping = None,
                 body: Union[str, bytes] = None):
        super().__init__(url, http_version, headers, body)
        self.status = status
        self.status_text = ' '.join(status_text)

    def _start_line(self) -> str:
        return f'{self.http_version} {self.status} {self.status_text}'
