"""
DEEP-mon
Copyright (C) 2020  Brondolin Rolando

This file is part of DEEP-mon

DEEP-mon is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

DEEP-mon is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import click
import yaml

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

if __name__ == "__main__":
    from userspace.monitor_main import MonitorMain
else:
    from .userspace.monitor_main import MonitorMain

# Load config file with default values
config = {}
try:
    with open("/home/config.yaml", "r") as config_file:
        config = yaml.load(config_file, Loader=yaml.FullLoader)
except IOError:
    try:
        with open("userspace/default_config.yaml", "r") as default_config_file:
            config = yaml.load(default_config_file, Loader=yaml.FullLoader)
    except IOError:
        print("Couldn't find a config file, check your path")
        config = {}

CONTEXT_SETTINGS = dict(default_map=config)


@click.command(context_settings=CONTEXT_SETTINGS)
@click.option("--container-regex", "-r", default="*")
@click.option("--window-mode", "-w", default="fixed")
@click.option("--output-format", "-o", default="json")
@click.option("--debug-mode", "-d")
@click.option("--net_monitor", "-n", default="True")
@click.option("--nat_trace", default="True")
@click.option("--print_net_details", default="True")
@click.option("--dynamic_tcp_client_port_masking")
@click.option("--power_measure", default="True")
@click.option("--memory_measure", default="True")
@click.option("--disk_measure", default="True")
@click.option("--file_measure", default="True")
def main(
    container_regex,
    window_mode,
    output_format,
    debug_mode,
    net_monitor,
    nat_trace,
    print_net_details,
    dynamic_tcp_client_port_masking,
    power_measure,
    memory_measure,
    disk_measure,
    file_measure,
):
    monitor = MonitorMain(
        container_regex,
        window_mode,
        output_format,
        debug_mode,
        net_monitor,
        nat_trace,
        print_net_details,
        dynamic_tcp_client_port_masking,
        power_measure,
        memory_measure,
        disk_measure,
        file_measure,
    )

    monitor.monitor_loop()


if __name__ == "__main__":
    main()
