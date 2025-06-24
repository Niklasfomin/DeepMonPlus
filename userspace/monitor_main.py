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
import re
import prometheus_client as prom

pattern = re.compile(r"^cadvisor.*")
seen_nxf_containers = set()
nxf_counter = 0

# Prometheus metrics
container_cpu_usage = prom.Gauge(
    "container_cpu_usage", "CPU usage per container", ["container_id"]
)
container_cycles = prom.Gauge(
    "container_cycles", "Cycles per container", ["container_id"]
)
container_weighted_cycles = prom.Gauge(
    "container_weighted_cycles",
    "Weighted cycles per container",
    ["container_id"],
)
container_instruction_retired = prom.Gauge(
    "container_instruction_retired",
    "Instructions retired per container",
    ["container_id"],
)
container_cache_misses = prom.Gauge(
    "container_cache_misses", "Cache misses per container", ["container_id"]
)
container_cache_refs = prom.Gauge(
    "container_cache_refs", "Cache references per container", ["container_id"]
)
container_power = prom.Gauge(
    "container_power", "Power usage per container", ["container_id"]
)
container_mem_RSS = prom.Gauge(
    "container_mem_rss",
    "Resident Set Size memory per container",
    ["container_id"],
)
container_mem_PSS = prom.Gauge(
    "container_mem_pss",
    "Proportional Set Size memory per container",
    ["container_id"],
)
container_mem_USS = prom.Gauge(
    "container_mem_uss",
    "Unique Set Size memory per container",
    ["container_id"],
)
container_kb_r = prom.Gauge(
    "container_kb_r", "Kilobytes read per container", ["container_id"]
)
container_kb_w = prom.Gauge(
    "container_kb_w", "Kilobytes written per container", ["container_id"]
)
container_num_reads = prom.Gauge(
    "container_num_reads", "Number of reads per container", ["container_id"]
)
container_num_writes = prom.Gauge(
    "container_num_writes", "Number of writes per container", ["container_id"]
)
container_disk_avg_lat = prom.Gauge(
    "container_disk_avg_lat",
    "Average disk latency per container",
    ["container_id"],
)


class MonitorMain:
    def __init__(
        self,
        output_format,
        window_mode,
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
        self.window_mode = window_mode
        # TODO: Don't hardcode the frequency
        self.frequency = 1

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

    def log2prometheus(self, container_list):
        """
        Convert container list to Prometheus metrics.
        This function is called to update the Prometheus metrics with the latest container data.
        """

        # Define Prometheus metrics

        for key, value in container_list.items():
            try:
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

                container_cpu_usage.labels(container_id=key).set(cpu_usage)
                container_cycles.labels(container_id=key).set(cycles)
                container_weighted_cycles.labels(container_id=key).set(weighted_cycles)
                container_instruction_retired.labels(container_id=key).set(
                    instruction_retired
                )
                container_cache_misses.labels(container_id=key).set(cache_misses)
                container_cache_refs.labels(container_id=key).set(cache_refs)
                container_power.labels(container_id=key).set(power)
                container_mem_RSS.labels(container_id=key).set(mem_RSS)
                container_mem_PSS.labels(container_id=key).set(mem_PSS)
                container_mem_USS.labels(container_id=key).set(mem_USS)
                container_kb_r.labels(container_id=key).set(kb_r)
                container_kb_w.labels(container_id=key).set(kb_w)
                container_num_reads.labels(container_id=key).set(num_reads)
                container_num_writes.labels(container_id=key).set(num_writes)
                container_disk_avg_lat.labels(container_id=key).set(disk_avg_lat)
            except Exception as e:
                print(f"Failed to update Prometheus metrics for container {key}: {e}")

    def monitor_loop(self):
        # Run the exporter server
        prom.start_http_server(8000)

        # Debug prints for counting nextflow containers
        nxf_counter = 0
        if self.window_mode == "dynamic":
            time_to_sleep = self.sample_controller.get_sleep_time()
        else:
            time_to_sleep = 1 / self.frequency

        while True:
            if time_to_sleep > 0:
                time.sleep(time_to_sleep)
            start_time = time.time()

            t1 = time.time()
            sample_array = self.get_sample()
            print(f"get_sample() duration: {time.time() - t1:.2f} seconds")
            t2 = time.time()
            sample = sample_array[0]
            container_list = sample_array[1]

            if self.output_format == "json":
                try:
                    # Print global/sample-level power and timing info ONCE
                    # print("Sample (global) stats:")
                    # print(sample.get_log_json())

                    # Then print each container's info
                    if container_list:
                        for key, value in container_list.items():
                            # container_name = value.get('container_name', '')
                            container_name = getattr(value, "container_name", "")
                            if pattern.match(container_name):
                                if key not in seen_nxf_containers:
                                    seen_nxf_containers.add(key)
                                    nxf_counter += 1
                                    print(
                                        f"Container {key} name matches: {container_name}"
                                    )
                                # Defensive: handle missing to_json
                                if hasattr(value, "to_json"):
                                    print(value.to_json())
                                    # Send stuff to prometheus
                                    self.log2prometheus(container_list)

                                else:
                                    print(str(value))
                            else:
                                print("No nextflow container found yet.")
                        print(f"Nextflow unique task count: {nxf_counter}")
                        pprint.pprint(seen_nxf_containers)
                    else:
                        print("No containers found in this sample.")
                except AttributeError as e:
                    print(f"AttributeError: {e}")
                except Exception as e:
                    print(f"Unexpected error: {e}")

            elif self.output_format == "console":
                if self.print_net_details:
                    nat_data = sample_array[3]
                    for nat_rule in nat_data:
                        print(nat_rule)

                if container_list:
                    for key, value in sorted(container_list.items()):
                        print(value)
                        if self.print_net_details:
                            for item in value.get_network_transactions():
                                print(item)
                            for item in value.get_nat_rules():
                                print(item)
                else:
                    print("No containers found in this sample.")

            if self.window_mode == "dynamic":
                time_to_sleep = self.sample_controller.get_sleep_time() - (
                    time.time() - start_time
                )
            else:
                time_to_sleep = 1 / self.frequency - (time.time() - start_time)

            print(f"Loop duration: {time.time() - start_time:.2f} seconds")
