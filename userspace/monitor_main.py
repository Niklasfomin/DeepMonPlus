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

from .bpf_collector import BpfCollector
from .proc_topology import ProcTopology
from .sample_controller import SampleController
from .process_table import ProcTable
from .net_collector import NetCollector
from .mem_collector import MemCollector
from .disk_collector import DiskCollector
from .rapl.rapl import RaplMonitor
import time
import pprint
import csv
import json
import os
import re
import prometheus_client as prom

seen_nxf_containers = set()
nxf_counter = 0

# Prometheus metrics
CONTAINER_METRICS = [
    ("container_cpu_usage", "CPU usage per container"),
    ("container_cycles", "Cycles per container"),
    ("container_weighted_cycles", "Weighted cycles per container"),
    ("container_instruction_retired", "Instructions retired per container"),
    ("container_cache_misses", "Cache misses per container"),
    ("container_cache_refs", "Cache references per container"),
    ("container_power", "Power usage per container"),
    ("container_mem_rss", "Resident Set Size memory per container"),
    ("container_mem_pss", "Proportional Set Size memory per container"),
    ("container_mem_uss", "Unique Set Size memory per container"),
    ("container_kb_r", "Kilobytes read per container"),
    ("container_kb_w", "Kilobytes written per container"),
    ("container_num_reads", "Number of reads per container"),
    ("container_num_writes", "Number of writes per container"),
    ("container_disk_avg_lat", "Average disk latency per container"),
]


class MonitorMain:
    def __init__(
        self,
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
        self.output_format = output_format
        self.container_regex = container_regex
        self.container_pattern = (
            re.compile(container_regex) if container_regex else None
        )

        # TODO: Don't hardcode the frequency
        self.frequency = 1
        self.window_mode = window_mode

        self.topology = ProcTopology()
        self.collector = BpfCollector(self.topology, debug_mode, power_measure)
        self.sample_controller = SampleController(self.topology.get_hyperthread_count())
        self.process_table = ProcTable()
        self.rapl_monitor = RaplMonitor(self.topology)
        self.started = False

        self.print_net_details = print_net_details
        self.net_monitor = net_monitor
        self.dynamic_tcp_client_port_masking = dynamic_tcp_client_port_masking
        self.net_collector = None

        self.mem_measure = memory_measure
        self.mem_collector = None

        self.disk_measure = disk_measure
        self.file_measure = file_measure
        self.disk_collector = None

        if self.net_monitor:
            self.net_collector = NetCollector(
                trace_nat=nat_trace,
                dynamic_tcp_client_port_masking=dynamic_tcp_client_port_masking,
            )

        if self.mem_measure:
            self.mem_collector = MemCollector()

        if self.disk_measure or self.file_measure:
            self.disk_collector = DiskCollector(disk_measure, file_measure)

    def get_window_mode(self):
        return self.window_mode

    def get_sample_controller(self):
        return self.sample_controller

    def _start_bpf_program(self, window_mode):
        if window_mode == "dynamic":
            self.collector.start_capture(self.sample_controller.get_timeslice())
            if self.net_monitor:
                self.net_collector.start_capture()
            if self.disk_measure or self.file_measure:
                self.disk_collector.start_capture()
        elif window_mode == "fixed":
            self.collector.start_timed_capture(frequency=self.frequency)
            if self.net_monitor:
                self.net_collector.start_capture()
            if self.disk_measure or self.file_measure:
                self.disk_collector.start_capture()
        else:
            print("Please provide a window mode")

    def get_sample(self):
        if not self.started:
            self._start_bpf_program(self.window_mode)
            self.started = True

        sample = self.collector.get_new_sample(
            self.sample_controller, self.rapl_monitor
        )
        # clear metrics for the new sample
        self.process_table.reset_metrics_and_evict_stale_processes(sample.get_max_ts())
        # add stuff to cumulative process table

        mem_dict = None
        disk_dict = None
        file_dict = {}

        if self.mem_collector:
            mem_dict = self.mem_collector.get_mem_dictionary()
        if self.disk_measure or self.file_measure:
            aggregate_disk_sample = self.disk_collector.get_sample()
            if self.disk_collector:
                disk_dict = aggregate_disk_sample["disk_sample"]
            if self.file_measure:
                file_dict = aggregate_disk_sample["file_sample"]

        nat_data = []
        if self.net_monitor:
            net_sample = self.net_collector.get_sample()
            self.process_table.add_process_from_sample(
                sample,
                net_dictionary=net_sample.get_pid_dictionary(),
                nat_dictionary=net_sample.get_nat_dictionary(),
            )
        else:
            self.process_table.add_process_from_sample(sample)

        # Now, extract containers!
        container_list = self.process_table.get_container_dictionary(
            mem_dict, disk_dict
        )

        return [
            sample,
            container_list,
            self.process_table.get_proc_table(),
            nat_data,
            file_dict,
        ]

    def write_container_metrics_csv(self, container_list, base_dir="/output"):
        """
        Writes container metrics to CSV files in a nested folder structure.
        Each container ID gets its own folder.
        Each metric (except container_id and container_name) gets its own subfolder.
        Each metric subfolder contains a CSV file with time series entries.
        """
        os.makedirs(base_dir, exist_ok=True)
        for container_id, value in container_list.items():
            container_name = getattr(value, "container_name", "")
            if not isinstance(container_name, str):
                container_name = str(container_name)
            if self.container_pattern and self.container_pattern.match(container_name):
                container_dir = os.path.join(base_dir, str(container_id))
                os.makedirs(container_dir, exist_ok=True)
            # Convert to dict if needed
                if hasattr(value, "to_json"):
                    data = value.to_json()
                    if isinstance(data, str):
                        data = json.loads(data)
                elif isinstance(value, dict):
                    data = value
                else:
                 continue

                for metric, metric_value in data.items():
                    if metric in ("container_id", "container_name"):
                        continue
                    metric_dir = os.path.join(container_dir, metric)
                    os.makedirs(metric_dir, exist_ok=True)
                    csv_path = os.path.join(metric_dir, "timeseries.csv")
                    # Check if file exists and is non-empty
                    file_exists = os.path.exists(csv_path)
                    file_empty = not file_exists or os.path.getsize(csv_path) == 0
                    with open(csv_path, "a", newline="") as csvfile:
                        writer = csv.writer(csvfile)
                        if file_empty:
                            writer.writerow(["timestamp", "container_name", "value"])
                        writer.writerow(
                            [int(time.time()), data.get("container_name", ""), metric_value]
                        )

    def log2prometheus(self, container_list, container_metrics):
        """
        Convert container list to Prometheus metrics.
        This function is called to update the Prometheus metrics with the latest container data.
        """

        metric_names = [
            "container_cpu_usage",
            "container_cycles",
            "container_weighted_cycles",
            "container_instruction_retired",
            "container_cache_misses",
            "container_cache_refs",
            "container_power",
            "container_mem_rss",
            "container_mem_pss",
            "container_mem_uss",
            "container_kb_r",
            "container_kb_w",
            "container_num_reads",
            "container_num_writes",
            "container_disk_avg_lat",
        ]

        try:
            for key, value in container_list.items():
                container_name = getattr(value, "container_name", "")
                if not isinstance(container_name, str):
                    container_name = str(container_name)
                cpu_usage = float(getattr(value, "cpu_usage", 0) or 0)
                cycles = float(getattr(value, "cycles", 0) or 0)
                weighted_cycles = float(getattr(value, "weighted_cycles", 0) or 0)
                instruction_retired = float(
                    getattr(value, "instruction_retired", 0) or 0
                )
                cache_misses = float(getattr(value, "cache_misses", 0) or 0)
                cache_refs = float(getattr(value, "cache_refs", 0) or 0)
                power = float(getattr(value, "power", 0) or 0)
                mem_RSS = float(getattr(value, "mem_RSS", 0) or 0)
                mem_PSS = float(getattr(value, "mem_PSS", 0) or 0)
                mem_USS = float(getattr(value, "mem_USS", 0) or 0)
                kb_r = float(getattr(value, "kb_r", 0) or 0)
                kb_w = float(getattr(value, "kb_w", 0) or 0)
                num_reads = float(getattr(value, "num_r", 0) or 0)
                num_writes = float(getattr(value, "num_w", 0) or 0)
                disk_avg_lat = float(getattr(value, "disk_avg_lat", 0) or 0)

                container_metrics["container_cpu_usage"].labels(container_id=key, name=container_name).set(
                    cpu_usage
                )
                container_metrics["container_cycles"].labels(container_id=key, name=container_name).set(
                    cycles
                )
                container_metrics["container_weighted_cycles"].labels(
                    container_id=key, name=container_name
                ).set(weighted_cycles)
                container_metrics["container_instruction_retired"].labels(
                    container_id=key, name=container_name, 
                ).set(instruction_retired)
                container_metrics["container_cache_misses"].labels(
                    container_id=key, name=container_name
                ).set(cache_misses)
                container_metrics["container_cache_refs"].labels(container_id=key, name=container_name).set(
                    cache_refs
                )
                container_metrics["container_power"].labels(container_id=key, name=container_name).set(power)
                container_metrics["container_mem_rss"].labels(container_id=key, name=container_name).set(
                    mem_RSS
                )
                container_metrics["container_mem_pss"].labels(container_id=key, name=container_name).set(
                    mem_PSS
                )
                container_metrics["container_mem_uss"].labels(container_id=key, name=container_name).set(
                    mem_USS
                )
                container_metrics["container_kb_r"].labels(container_id=key, name=container_name).set(kb_r)
                container_metrics["container_kb_w"].labels(container_id=key, name=container_name).set(kb_w)
                container_metrics["container_num_reads"].labels(container_id=key, name=container_name).set(
                    num_reads
                )
                container_metrics["container_num_writes"].labels(container_id=key, name=container_name).set(
                    num_writes
                )
                container_metrics["container_disk_avg_lat"].labels(
                    container_id=key, name=container_name
                ).set(disk_avg_lat)

            return metric_names
        except Exception as e:
            print(f"Failed to update Prometheus metrics for container {key}: {e}")
            return []

    def monitor_loop(self):
        if self.output_format == "prometheus":
            prom.start_http_server(8000)
            print("Prometheus metrics server started on port 8000")
            print("Initializing Prometheus metrics")
            # Define Prometheus metrics
            container_metrics = {
                name: prom.Gauge(name, desc, ["container_id", "name"])
                for name, desc in CONTAINER_METRICS
            }

        # Debug prints for counting nextflow containers
        nxf_counter = 0

        # Setting the monitoring interval
        time_to_sleep = 1 / self.frequency

        while True:
            if time_to_sleep > 0:
                time.sleep(time_to_sleep)
            start_time = time.time()
            sample_array = self.get_sample()
            container_list = sample_array[1]

            if self.output_format == "prometheus":
                print(
                    f"Exporting metrics to Prometheus at {time.strftime('%Y-%m-%d %H:%M:%S')}"
                )
                try:
                    found = False
                    if container_list:
                        for key, value in container_list.items():
                            container_name = getattr(value, "container_name", "")
                            if not isinstance(container_name, str):
                                container_name = str(container_name)
                            if self.container_pattern and self.container_pattern.match(
                                container_name
                            ):
                                print(f"Container {key} name matches: {container_name}")
                                found = True
                                if key not in seen_nxf_containers:
                                    seen_nxf_containers.add(key)
                                    nxf_counter += 1
                                    continue
                                metrics = self.log2prometheus(
                                    container_list, container_metrics
                                )
                                pprint.pprint(metrics)
                        if not found:
                            print("No nextflow container found yet.")
                            print(f"Nextflow unique task count: {nxf_counter}")
                    else:
                        print("No containers found in this sample.")
                except AttributeError as e:
                    print(f"AttributeError: {e}")
                except Exception as e:
                    print(f"Unexpected error: {e}")

            if self.output_format == "json":
                try:
                    # Print global/sample-level power and timing info ONCE
                    # print("Sample (global) stats:")
                    # print(sample.get_log_json())

                    # Then print each container's info
                    found = False
                    if container_list:
                        for key, value in container_list.items():
                            container_name = getattr(value, "container_name", "")
                            if self.container_pattern and self.container_pattern.match(
                                container_name
                            ):
                                found = True
                                if key not in seen_nxf_containers:
                                    seen_nxf_containers.add(key)
                                    nxf_counter += 1
                                    print(
                                        f"Container ID {key} name matches: {container_name}"
                                    )
                                    continue
                                if hasattr(value, "to_json"):
                                    print(value.to_json())
                                else:
                                    print(str(value))
                        if not found:
                            print("No nextflow container found yet.")
                        print(f"Nextflow unique task count: {nxf_counter}")
                        print("Caught Containers:")
                        pprint.pprint(seen_nxf_containers)
                    else:
                        print("No containers found in this sample.")
                except AttributeError as e:
                    print(f"AttributeError: {e}")
                except Exception as e:
                    print(f"Unexpected error: {e}")

            if self.output_format == "csv":
                try:
                    found = False
                    if container_list:
                        for key, value in container_list.items():
                            container_name = getattr(value, "container_name", "")
                            cpu_usage = getattr(value, "cpu_usage", 0)
                            if not isinstance(container_name, str):
                                container_name = str(container_name)
                            if self.container_pattern and self.container_pattern.match(
                                container_name
                            ):
                                found = True
                                if key not in seen_nxf_containers:
                                    seen_nxf_containers.add(key)
                                    nxf_counter += 1
                                    print(
                                        f"Container ID {key} name matches: {container_name}"
                                    )
                                    # continue
                                if not value:
                                    print(f"ALARM Container {key} has no metrics.")
                                else:
                                    # continue
                                    # print(f"Writing metrics for container {key} with values {value.to_json()}")
                                # print(value.to_json())
                                    self.write_container_metrics_csv(container_list)
                                    # print(value.to_json())
                                    # print(f"DEBUG Caught Containers with name: {container_name} and example metric: {cpu_usage}")
                        # if not found:
                            # print("No nextflow container found yet.")
                        # print(f"Nextflow unique task count: {nxf_counter}")
                        # pprint.pprint(seen_nxf_containers)
                    else:
                        print("No containers found in this sample.")
                except AttributeError as e:
                    print(f"AttributeError: {e}")
                except Exception as e:
                    print(f"Unexpected error: {e}")
            print(f"Sampling loop duration: {time.time() - start_time:.2f} seconds")
