import click
from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider

from harlogger.sniffers import Filters, HostSnifferProfile, MobileSnifferProfile, SnifferPreference


@click.group()
def cli():
    pass


@cli.group()
def mobile():
    """ Mobile sniffing options """
    pass


@mobile.command('profile', cls=Command)
@click.option('pids', '-p', '--pid', type=click.INT, multiple=True, help='filter pid list')
@click.option('--color/--no-color', default=True)
@click.option('process_names', '-pn', '--process-name', multiple=True, help='filter process name list')
@click.option('images', '-i', '--image', multiple=True, help='filter image list')
@click.option('--request/--no-request', is_flag=True, default=True, help='show requests')
@click.option('--response/--no-response', is_flag=True, default=True, help='show responses')
@click.option('-u', '--unique', is_flag=True, help='show only unique requests per image/pid/method/uri combination')
@click.option('--black-list/--white-list', default=True, is_flag=True)
def mobile_profile(service_provider: LockdownServiceProvider, pids, process_names, color, request, response, images,
                   unique, black_list):
    """
    Sniff using CFNetworkDiagnostics.mobileconfig profile.

    This requires the specific Apple profile to be installed for the sniff to work.
    """
    filters = Filters(pids, process_names, images, black_list)
    MobileSnifferProfile(service_provider, filters=filters, request=request, response=response, color=color,
                         unique=unique).sniff()


@mobile.command('preference', cls=Command)
@click.option('-o', '--out', type=click.File('w'), help='file to store the har entries into upon exit (ctrl+c)')
@click.option('pids', '-p', '--pid', type=click.INT, multiple=True, help='filter pid list')
@click.option('--color/--no-color', default=True)
@click.option('process_names', '-pn', '--process-name', multiple=True, help='filter process name list')
@click.option('images', '-i', '--image', multiple=True, help='filter image list')
@click.option('--request/--no-request', is_flag=True, default=True, help='show requests')
@click.option('--response/--no-response', is_flag=True, default=True, help='show responses')
@click.option('-u', '--unique', is_flag=True, help='show only unique requests per image/pid/method/uri combination')
@click.option('--black-list/--white-list', default=True, is_flag=True)
def mobile_preference(service_provider: LockdownServiceProvider, out, pids, process_names, images, request, response,
                      color, unique, black_list):
    """
    Sniff using the secret com.apple.CFNetwork.plist configuration.

    This sniff includes the request/response body as well but requires the device to be jailbroken for
    the sniff to work
    """
    filters = Filters(pids, process_names, images, black_list)
    SnifferPreference(service_provider, filters=filters, request=request, response=response, out=out, color=color,
                      unique=unique).sniff()


@cli.command('profile')
@click.option('pids', '-p', '--pid', type=click.INT, multiple=True, help='filter pid list')
@click.option('--color/--no-color', default=True)
@click.option('process_names', '-pn', '--process-name', multiple=True, help='filter process name list')
@click.option('images', '-i', '--image', multiple=True, help='filter image list')
@click.option('--request/--no-request', is_flag=True, default=True, help='show requests')
@click.option('--response/--no-response', is_flag=True, default=True, help='show responses')
@click.option('-u', '--unique', is_flag=True, help='show only unique requests per image/pid/method/uri combination')
@click.option('--black-list/--white-list', default=True, is_flag=True)
def host_profile(pids, process_names, color, request, response, images, unique, black_list):
    """
    Sniff using CFNetworkDiagnostics.mobileconfig profile.

    This requires the specific Apple profile to be installed for the sniff to work.
    """
    filters = Filters(pids, process_names, images, black_list)
    HostSnifferProfile(filters=filters, request=request, response=response, color=color,
                       unique=unique).sniff()


if __name__ == '__main__':
    cli()
