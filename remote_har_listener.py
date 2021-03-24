#!/usr/local/bin/python3

import subprocess
import textwrap
import json

from termcolor import colored
import click

HAR_TELEMETRY_UNIQUE_IDENTIFIER = 'startedDateTime'

INDENT = '    '


def show_har_entry(entry):
    request = entry['request']
    image = entry['image']
    pid = entry['pid']

    process = f'{image}({pid})'

    print(f'➡️   {colored(process, "cyan")} {request["method"]} {request["url"]}')
    for header in request['headers']:
        print(textwrap.indent(f'{header["name"]}: {header["value"]}', INDENT))

    print('')

    response = entry['response']

    print(f'{INDENT}⬅️   {response["status"]} {response["statusText"]}')
    for header in response['headers']:
        print(textwrap.indent(f'{header["name"]}: {header["value"]}', INDENT * 2))

    print('')

    if 'content' in response:
        content = response['content']

        if 'text' in content:
            text = content['text']

            print(textwrap.indent(text, INDENT * 2))

    print('')


@click.command()
@click.option('-o', '--out', type=click.File('w'))
@click.option('pids', '-p', '--pid', multiple=True)
@click.option('images', '-i', '--image', multiple=True)
def main(out, pids, images):
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

            show_har_entry(entry)

            har['log']['entries'].append(entry)
    except KeyboardInterrupt:
        if out:
            out.write(json.dumps(har, indent=4))


if __name__ == '__main__':
    main()
