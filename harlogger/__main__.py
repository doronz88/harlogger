import json
import os
import posixpath
from urllib.parse import urlparse

import click
from pygments import highlight
from pygments.formatters.terminal256 import TerminalTrueColorFormatter
from pygments.lexers.textfmts import HttpLexer
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.os_trace import OsTraceService


def get_header_from_list(name, headers):
    for header in headers:
        if header['name'].lower() == name.lower():
            return header['value']
    return None


def is_in_insensitive_list(needle, haystack):
    for h in haystack:
        if needle.lower() == h.lower():
            return True
    return False


def show_http_packet(http_packet, filter_headers):
    buf = ''
    version = 'HTTP/1.0'
    if http_packet['httpVersion'] == 'h2':
        version = 'HTTP/2.0'

    if 'url' in http_packet:
        # request
        url = urlparse(http_packet['url'])
        uri = url.path
        if url.query:
            uri += f'?{url.query}'

        buf += f'{http_packet["method"]} {uri} {version}\r\n'
    else:
        # response
        if http_packet['status'] == 0:
            # isn't a real packet
            return
        buf += f'{version} {http_packet["status"]} {http_packet["statusText"]}\r\n'

    for header in http_packet['headers']:
        if (filter_headers is not None) and (len(filter_headers) > 0) and \
                not is_in_insensitive_list(header['name'], filter_headers):
            continue
        buf += f'{header["name"]}: {header["value"]}\r\n'

    buf += '\r\n'

    content = {}

    if 'postData' in http_packet:
        content = http_packet['postData']

    if 'content' in http_packet:
        content = http_packet['content']

    print(highlight(buf, HttpLexer(), TerminalTrueColorFormatter(style='autumn')))

    if 'text' in content:
        print(content['text'])


def show_har_entry(entry, filter_headers=None, show_request=True, show_response=True):
    image = entry['image']
    pid = entry['pid']

    process = f'{image}({pid})'

    if show_request:
        request = entry['request']

        print(f'➡️   {process} {request["method"]} {request["url"]}')
        show_http_packet(request, filter_headers)

    if show_response:
        response = entry['response']
        print(f'⬅️   {process} {response["status"]} {response["statusText"]}')
        show_http_packet(response, filter_headers)


def parse_fields(message: str):
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


@click.group()
def cli():
    pass


@cli.command('profile')
@click.option('pids', '-p', '--pid', multiple=True, help='filter pid list')
@click.option('process_names', '-pn', '--process-name', multiple=True, help='filter process name list')
@click.option('--color/--no-color', default=True)
@click.option('--request/--no-request', is_flag=True, default=True, help='show requests')
@click.option('--response/--no-response', is_flag=True, default=True, help='show responses')
def cli_profile(pids, process_names, color, request, response):
    """
    Sniff using CFNetowrkDiagnostics.mobileconfig profile.

    This requires the specific Apple profile to be installed for the sniff to work.
    """
    lockdown = LockdownClient()

    for entry in OsTraceService(lockdown).syslog():
        if entry.label is None or entry.label.subsystem != 'com.apple.CFNetwork' or \
                entry.label.category != 'Diagnostics':
            continue

        if pids and (entry.pid not in pids):
            continue

        if process_names and (posixpath.basename(entry.filename) not in process_names):
            continue

        lines = entry.message.split('\n')
        if len(lines) < 2:
            continue

        buf = ''

        if lines[1].strip().startswith('Protocol Enqueue: request') and request:
            # request
            print('➡️   ', end='')
            fields = parse_fields(entry.message)
            buf += f'{fields["Message"]}\n'
            for name, value in fields.items():
                if name in ('Protocol Enqueue', 'Request', 'Message'):
                    continue
                buf += f'{name}: {value}\n'

        elif lines[1].strip().startswith('Protocol Received: request') and response:
            # response
            print('⬅️   ', end='')
            fields = parse_fields(entry.message)
            buf += f'{fields["Response"]} ({fields["Protocol Received"]})\n'
            for name, value in fields.items():
                if name in ('Protocol Received', 'Response'):
                    continue
                buf += f'{name}: {value}\n'

        if buf:
            if color:
                print(highlight(buf, HttpLexer(), TerminalTrueColorFormatter(style='autumn')))
            else:
                print(buf)


@cli.command('preference')
@click.option('--udid')
@click.option('-o', '--out', type=click.File('w'), help='file to store the har entries into upon exit (ctrl+c)')
@click.option('pids', '-p', '--pid', multiple=True, help='filter pid list')
@click.option('images', '-i', '--image', multiple=True, help='filter image list')
@click.option('headers', '-h', '--header', multiple=True, help='filter header list')
@click.option('--request/--no-request', is_flag=True, default=True, help='show requests')
@click.option('--response/--no-response', is_flag=True, default=True, help='show responses')
@click.option('-u', '--unique', is_flag=True, help='show only unique requests per image/pid/method/uri combination')
def cli_preference(udid, out, pids, images, headers, request, response, unique):
    """
    Sniff using the secret com.apple.CFNetwork.plist configuration.

    This sniff includes the request/response body as well but requires the device to be jailbroken for
    the sniff to work
    """
    shown_set = set()
    har = {
        'log': {
            'version': '0.1',
            'creator': {
                'name': 'remote-har-listener',
                'version': '0.1',
            },
            'entries': [],
        }
    }

    lockdown = LockdownClient(udid=udid)
    os_trace_service = OsTraceService(lockdown)

    try:
        for line in os_trace_service.syslog():
            if line.label is None:
                continue
            if line.label.category != 'HAR':
                continue

            image = os.path.basename(line.image_name)
            pid = line.pid
            message = line.message

            if (len(pids) > 0) and (pid not in pids):
                continue

            if (len(images) > 0) and (image not in images):
                continue

            try:
                entry = json.loads(message)
            except json.decoder.JSONDecodeError:
                print(f'failed to decode: {message}')
                continue

            # artificial HAR information extracted from syslog line
            entry['image'] = image
            entry['pid'] = pid

            if unique:
                entry_hash = (image, pid, entry['request']['method'], entry['request']['url'])

                if entry_hash in shown_set:
                    continue

                shown_set.add(entry_hash)
            show_har_entry(entry, filter_headers=headers, show_request=request, show_response=response)

            har['log']['entries'].append(entry)
    except KeyboardInterrupt:
        if out:
            out.write(json.dumps(har, indent=4))


if __name__ == '__main__':
    cli()
