#!/usr/local/bin/python3

import subprocess
import textwrap
import json

from termcolor import colored
import click

# i hope this match is unique enough. apple didn't provide with a really nicer magic to grep on
HAR_TELEMETRY_UNIQUE_IDENTIFIER = 'startedDateTime'

INDENT = '    '


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


def show_headers(headers, filter_headers, indent=''):
    for header in headers:
        if (filter_headers is not None) and (len(filter_headers) > 0) and \
                not is_in_insensitive_list(header['name'], filter_headers):
            continue
        print(textwrap.indent(f'{header["name"]}: {header["value"]}', indent))
    print('')


def show_har_entry(entry, filter_headers=None, show_request=True, show_response=True):
    image = entry['image']
    pid = entry['pid']

    process = f'{image}({pid})'

    if show_request:
        request = entry['request']

        print(f'➡️   {colored(process, "cyan")} {request["method"]} {request["url"]}')
        show_headers(request['headers'], filter_headers, INDENT)

    if show_response:
        response = entry['response']

        print(f'{INDENT}⬅️   {response["status"]} {response["statusText"]}')
        show_headers(response['headers'], filter_headers, INDENT * 2)

        if 'content' in response:
            content = response['content']

            if 'text' in content:
                text = content['text']

                print(textwrap.indent(text, INDENT * 2))

        print('')


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
    args = ['idevicesyslog', '--no-colors', '-q', '-m', HAR_TELEMETRY_UNIQUE_IDENTIFIER]

    p = subprocess.Popen(args,
                         stdout=subprocess.PIPE)

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

    line = p.stdout.readline().strip()
    assert line == b'[connected]'

    try:
        while True:
            line = p.stdout.readline().strip().decode('utf8')
            splitted_lines = line.split('(CFNetwork)', 1)
            image = splitted_lines[0].rsplit(' ', 1)[1]
            pid = splitted_lines[1].split('[', 1)[1].split(']', 1)[0]
            raw_entry = splitted_lines[1].split('<Notice>: ', 1)[1].replace(r'\134', '\\')

            if (len(pids) > 0) and (pid not in pids):
                continue

            if (len(images) > 0) and (image not in images):
                continue

            try:
                entry = json.loads(raw_entry)
            except json.decoder.JSONDecodeError:
                print(f'failed to decode: {raw_entry}')
                continue

            # artificial HAR information extracted from syslog line
            entry['image'] = image
            entry['pid'] = pid

            if unique:
                hash = (image, pid, entry['request']['method'], entry['request']['url'])

                if hash in shown_set:
                    continue

                shown_set.add(hash)
            show_har_entry(entry, filter_headers=headers, show_request=request, show_response=response)

            har['log']['entries'].append(entry)
    except KeyboardInterrupt:
        if out:
            out.write(json.dumps(har, indent=4))


if __name__ == '__main__':
    main()
