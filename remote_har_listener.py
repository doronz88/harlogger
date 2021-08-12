#!/usr/local/bin/python3
import json
import os
from urllib.parse import urlparse

import click
from pygments import highlight
from pygments.formatters import TerminalTrueColorFormatter
from pygments.lexers import HttpLexer
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.os_trace import OsTraceService
from pymobiledevice3.services.syslog import SyslogService


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


@click.command()
@click.option('-o', '--out', type=click.File('w'), help='file to store the har entries into upon exit (ctrl+c)')
@click.option('pids', '-p', '--pid', multiple=True, help='filter pid list')
@click.option('images', '-i', '--image', multiple=True, help='filter image list')
@click.option('headers', '-h', '--header', multiple=True, help='filter header list')
@click.option('--request/--no-request', is_flag=True, default=True, help='show requests')
@click.option('--response/--no-response', is_flag=True, default=True, help='show responses')
@click.option('-u', '--unique', is_flag=True, help='show only unique requests per image/pid/method/uri combination')
def main(out, pids, images, headers, request, response, unique):
    """
    Simple utility to filter out the HAR log messages from device's syslog, assuming HAR logging is enabled.
    If not, please use the `harlogger` binary beforehand.
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

    lockdown = LockdownClient()
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
    main()
