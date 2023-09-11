import json
import os
import posixpath
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import IO, Optional, Tuple

from haralyzer import HarEntry
from maclog.log import get_logger
from pygments import highlight
from pygments.formatters.terminal256 import TerminalTrueColorFormatter
from pygments.lexers.textfmts import HttpLexer
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.os_trace import OsTraceService

from harlogger.exceptions import HTTPParseError
from harlogger.haralyzer_patches import add_text_base64_support_for_haralyzer
from harlogger.http_transaction import HTTPRequest, HTTPResponse, HTTPTransaction

add_text_base64_support_for_haralyzer()


@dataclass
class EntryHash:
    pid: int
    process_name: str
    image: str
    url: str


@dataclass(repr=True)
class Filters:
    pids: Tuple = None
    process_names: Tuple = None
    images: Tuple = None
    black_list: bool = True

    def should_keep(self, entry_hash: EntryHash) -> bool:
        """ Filter out entry if one of the criteria specified (pid,image,process_name) """
        in_filters = (self.pids is not None and entry_hash.pid in self.pids or
                      self.process_names is not None and entry_hash.process_name in self.process_names or
                      self.images is not None and entry_hash.image in self.images)

        return self.black_list and not in_filters or not self.black_list and in_filters


class SnifferBase(ABC):
    def __init__(self, filters: Filters = None, unique: bool = False, request: bool = True,
                 response: bool = True, color: bool = True, style: str = 'autumn'):
        self._filters = filters
        self._request = request
        self._response = response
        self._unique = unique
        self._color = color
        self._style = style
        self._shown_list = []

    def show(self, entry_hash: EntryHash, transaction: str, direction: str, extra: str = '') -> None:
        if self._unique:
            if entry_hash in self._shown_list:
                return
            else:
                self._shown_list.append(entry_hash)

        print(f'{direction}   {entry_hash.process_name} ({entry_hash.pid}) {extra}')
        if self._color:
            print(highlight(transaction, HttpLexer(), TerminalTrueColorFormatter(style=self._style)))
        else:
            print(transaction)

    @abstractmethod
    def sniff(self) -> None:
        pass


class MobileSnifferBase(SnifferBase, ABC):
    def __init__(self, lockdown: LockdownClient, filters: Filters = None, unique: bool = False, request: bool = True,
                 response: bool = True, color: bool = True, style: str = 'autumn'):
        super().__init__(filters, unique, request, response, color, style)
        self._lockdown = lockdown
        self._os_trace_service = OsTraceService(self._lockdown)


class SnifferPreference(SnifferBase):
    """
    Sniff using the secret com.apple.CFNetwork.plist configuration.

    This sniff includes the request/response body as well but requires the device to be jailbroken for
    the sniff to work
    """

    def __init__(self, lockdown: LockdownClient, filters: Filters = None, unique: bool = False, request: bool = True,
                 response: bool = True, color: bool = True, style: str = 'autumn', out: IO = None):
        super().__init__(lockdown, filters, unique, request, response, color, style)
        self.out = out
        self.har = {
            'log': {
                'version': '0.1',
                'creator': {
                    'name': 'remote-har-listener',
                    'version': '0.1',
                },
                'entries': [],
            }
        }

    def sniff(self) -> None:
        try:
            self._sniff()
        except KeyboardInterrupt:
            if self.out:
                self.out.write(json.dumps(self.har, indent=4))

    def _sniff(self) -> None:
        incomplete = ''
        for line in self._os_trace_service.syslog():
            if line.label is None:
                continue
            if line.label.category != 'HAR':
                continue

            message = line.message

            try:
                entry = HarEntry(json.loads(incomplete + message))
                incomplete = ''
                entry_hash = EntryHash(line.pid,
                                       posixpath.basename(line.filename),
                                       os.path.basename(line.image_name),
                                       entry.url)

                if not self._filters.should_keep(entry_hash):
                    continue

                self.har['log']['entries'].append(entry)
                if self._request:
                    self.show(entry_hash, entry.request.formatted, '➡️')
                if self._response:
                    self.show(entry_hash, entry.response.formatted, '⬅️')

            except json.decoder.JSONDecodeError:
                if message.startswith('<incomplete>'):
                    incomplete += message.split('<incomplete>', 1)[1]
                    continue
                elif len(incomplete) > 0:
                    incomplete += message
                    continue


class SnifferProfileBase(SnifferBase, ABC):
    def _handle_entry(self, pid: int, message: str, filename: str, image_name: str, subsystem: Optional[str] = None,
                      category: Optional[str] = None):
        if subsystem != 'com.apple.CFNetwork' or category != 'Diagnostics':
            return

        if 'Protocol Received' not in message and 'Protocol Enqueue' not in message:
            return

        lines = message.split('\n')
        if len(lines) < 2:
            return

        http_transaction = HTTPTransaction.parse_transaction(message)
        if not http_transaction:
            raise HTTPParseError()
        entry_hash = EntryHash(pid,
                               posixpath.basename(filename),
                               os.path.basename(image_name),
                               http_transaction.url)

        if not self._filters.should_keep(entry_hash):
            return

        if self._request and isinstance(http_transaction, HTTPRequest):
            self.show(entry_hash, http_transaction.formatted, '➡️')
        if self._response and isinstance(http_transaction, HTTPResponse):
            self.show(entry_hash, http_transaction.formatted, '⬅️', f'({http_transaction.url})')


class MobileSnifferProfile(MobileSnifferBase, SnifferProfileBase):
    """
    Sniff using CFNetworkDiagnostics.mobileconfig profile.

    This requires the specific Apple profile to be installed for the sniff to work.
    """

    def __init__(self, lockdown: LockdownClient, filters: Filters = None, unique: bool = False, request: bool = True,
                 response: bool = True, color: bool = True, style: str = 'autumn'):
        super().__init__(lockdown, filters, unique, request, response, color, style)

    def sniff(self) -> None:
        for entry in self._os_trace_service.syslog():
            subsystem = None
            category = None
            if entry.label is not None:
                subsystem = entry.label.subsystem
                category = entry.label.category
            self._handle_entry(entry.pid, entry.message, entry.filename, entry.image_name, subsystem=subsystem,
                               category=category)


class HostSnifferProfile(SnifferProfileBase):
    """
    Sniff using CFNetworkDiagnostics.mobileconfig profile.

    This requires the specific Apple profile to be installed for the sniff to work.
    """

    def __init__(self, filters: Filters = None, unique: bool = False, request: bool = True,
                 response: bool = True, color: bool = True, style: str = 'autumn'):
        super().__init__(filters, unique, request, response, color, style)

    def sniff(self) -> None:
        for entry in get_logger():
            self._handle_entry(entry.process_id, entry.event_message, entry.process_image_path, entry.sender_image_path,
                               subsystem=entry.subsystem, category=entry.category)
