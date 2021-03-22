#!/usr/local/bin/python3

import subprocess
import click
import json


@click.command()
@click.option('-o', '--out', type=click.File('w'))
def main(out):
    p = subprocess.Popen(['idevicesyslog', '--no-colors', '-q', '-m', 'startedDateTime'], stdout=subprocess.PIPE)

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
            date = splitted_lines[0][:splitted_lines[0].rfind(' ')].strip()
            namespace = splitted_lines[0][splitted_lines[0].rfind(' '):].strip()
            entry = json.loads(splitted_lines[1].split('<Notice>: ', 1)[1].replace(r'\134', '\\'))

            print(json.dumps(entry, indent=4))
            har['log']['entries'].append(entry)
    except KeyboardInterrupt:
        if out:
            out.write(json.dumps(har, indent=4))


if __name__ == '__main__':
    main()
