#!/usr/local/bin/python3

import subprocess
import click
import json

HAR_TELEMETRY_UNIQUE_IDENTIFIER = 'startedDateTime'


@click.command()
@click.option('-o', '--out', type=click.File('w'))
@click.option('-p', '--process')
def main(out, process):
    args = ['idevicesyslog', '--no-colors', '-q', '-m', HAR_TELEMETRY_UNIQUE_IDENTIFIER]
    if process is not None:
        args += ['-p', process]

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
            raw_entry = splitted_lines[1].split('<Notice>: ', 1)[1].replace(r'\134', '\\')
            try:
                entry = json.loads(raw_entry)
            except json.decoder.JSONDecodeError:
                print(f'failed to decode: {raw_entry}')
                continue

            print(json.dumps(entry, indent=4))
            har['log']['entries'].append(entry)
    except KeyboardInterrupt:
        if out:
            out.write(json.dumps(har, indent=4))


if __name__ == '__main__':
    main()
