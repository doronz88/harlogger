from typing import Annotated, Optional

import typer
from pymobiledevice3.cli.cli_common import ServiceProviderDep
from typer_injector import InjectingTyper

from harlogger.sniffers import Filters, HostSnifferProfile, MobileSnifferProfile, SnifferPreference

cli = InjectingTyper(
    help="Monitor HTTP traffic on given macOS/iOS devices.",
    no_args_is_help=True,
)
mobile = InjectingTyper(help="Mobile sniffing options")
cli.add_typer(mobile, name="mobile")


@mobile.command("profile")
def mobile_profile(
    service_provider: ServiceProviderDep,
    pids: Annotated[Optional[list[int]], typer.Option("-p", "--pid", help="filter pid list")] = None,
    process_names: Annotated[
        Optional[list[str]],
        typer.Option("-pn", "--process-name", help="filter process name list"),
    ] = None,
    color: Annotated[bool, typer.Option("--color/--no-color")] = True,
    request: Annotated[bool, typer.Option("--request/--no-request", help="show requests")] = True,
    response: Annotated[bool, typer.Option("--response/--no-response", help="show responses")] = True,
    images: Annotated[Optional[list[str]], typer.Option("-i", "--image", help="filter image list")] = None,
    unique: Annotated[
        bool,
        typer.Option("-u", "--unique", help="show only unique requests per image/pid/method/uri combination"),
    ] = False,
    black_list: Annotated[bool, typer.Option("--black-list/--white-list")] = True,
):
    """
    Sniff using CFNetworkDiagnostics.mobileconfig profile.

    This requires the specific Apple profile to be installed for the sniff to work.
    """
    filters = Filters(pids, process_names, images, black_list)
    MobileSnifferProfile(
        service_provider, filters=filters, request=request, response=response, color=color, unique=unique
    ).sniff()


@mobile.command("preference")
def mobile_preference(
    service_provider: ServiceProviderDep,
    out: Annotated[
        Optional[typer.FileTextWrite],
        typer.Option("-o", "--out", help="file to store the har entries into upon exit (ctrl+c)"),
    ] = None,
    pids: Annotated[Optional[list[int]], typer.Option("-p", "--pid", help="filter pid list")] = None,
    process_names: Annotated[
        Optional[list[str]],
        typer.Option("-pn", "--process-name", help="filter process name list"),
    ] = None,
    color: Annotated[bool, typer.Option("--color/--no-color")] = True,
    images: Annotated[Optional[list[str]], typer.Option("-i", "--image", help="filter image list")] = None,
    request: Annotated[bool, typer.Option("--request/--no-request", help="show requests")] = True,
    response: Annotated[bool, typer.Option("--response/--no-response", help="show responses")] = True,
    unique: Annotated[
        bool,
        typer.Option("-u", "--unique", help="show only unique requests per image/pid/method/uri combination"),
    ] = False,
    black_list: Annotated[bool, typer.Option("--black-list/--white-list")] = True,
):
    """
    Sniff using the secret com.apple.CFNetwork.plist configuration.

    This sniff includes the request/response body as well but requires the device to be jailbroken for
    the sniff to work
    """
    filters = Filters(pids, process_names, images, black_list)
    SnifferPreference(
        service_provider, filters=filters, request=request, response=response, out=out, color=color, unique=unique
    ).sniff()


@cli.command("profile")
def host_profile(
    pids: Annotated[Optional[list[int]], typer.Option("-p", "--pid", help="filter pid list")] = None,
    process_names: Annotated[
        Optional[list[str]],
        typer.Option("-pn", "--process-name", help="filter process name list"),
    ] = None,
    color: Annotated[bool, typer.Option("--color/--no-color")] = True,
    request: Annotated[bool, typer.Option("--request/--no-request", help="show requests")] = True,
    response: Annotated[bool, typer.Option("--response/--no-response", help="show responses")] = True,
    images: Annotated[Optional[list[str]], typer.Option("-i", "--image", help="filter image list")] = None,
    unique: Annotated[
        bool,
        typer.Option("-u", "--unique", help="show only unique requests per image/pid/method/uri combination"),
    ] = False,
    black_list: Annotated[bool, typer.Option("--black-list/--white-list")] = True,
):
    """
    Sniff using CFNetworkDiagnostics.mobileconfig profile.

    This requires the specific Apple profile to be installed for the sniff to work.
    """
    filters = Filters(pids, process_names, images, black_list)
    HostSnifferProfile(filters=filters, request=request, response=response, color=color, unique=unique).sniff()


if __name__ == "__main__":
    cli()
