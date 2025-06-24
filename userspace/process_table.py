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

import docker
from .process_info import ProcessInfo

# from .bpf_collector import BpfSample
from .container_info import ContainerInfo
import os


class ProcTable:
    def __init__(self):
        self.proc_table = {}
        self.docker_client = docker.from_env()

    # remove processes that did not receive updates in the last 8 seconds
    def reset_metrics_and_evict_stale_processes(self, ts):
        evicted_keys = []

        for proc_table_key, proc_table_value in self.proc_table.items():
            # if proc_table_value.get_last_ts() + 8000000000 < ts:
            if proc_table_value.get_last_ts() + 30000000000 < ts:
                evicted_keys.append(proc_table_key)
            else:
                proc_table_value.set_power(0)
                proc_table_value.set_cpu_usage(0)
                proc_table_value.reset_data()

        # remove evicted keys
        for k in evicted_keys:
            self.proc_table.pop(k, None)

    def add_process(self, proc_info):
        self.proc_table[proc_info.get_pid()] = proc_info

    def add_process_from_sample(self, sample, net_dictionary=None, nat_dictionary=None):
        # print(f"DEBUG: add_process_from_sample called with {len(sample.get_pid_dict())} processes")
        # reset counters for each entries
        for key, value in sample.get_pid_dict().items():
            if key in self.proc_table:
                # process already there, check if comm is the same
                if value.get_comm() == self.proc_table[key].get_comm():
                    # ok, update stuff
                    self.proc_table[key].set_power(value.get_power())
                    self.proc_table[key].set_cpu_usage(value.get_cpu_usage())
                    self.proc_table[key].set_instruction_retired(
                        value.get_instruction_retired()
                    )
                    self.proc_table[key].set_cycles(value.get_cycles())
                    self.proc_table[key].set_cache_misses(value.get_cache_misses())
                    self.proc_table[key].set_cache_refs(value.get_cache_refs())
                    self.proc_table[key].set_time_ns(value.get_time_ns())
                    self.proc_table[key].set_socket_data_array(value.get_socket_data())
                    # Accumulate metrics instead of overwriting

                    # self.proc_table[key].set_power(
                    #     self.proc_table[key].get_power() + value.get_power()
                    # )
                    # self.proc_table[key].set_cpu_usage(
                    #     self.proc_table[key].get_cpu_usage() + value.get_cpu_usage()
                    # )
                    # self.proc_table[key].set_instruction_retired(
                    #     self.proc_table[key].get_instruction_retired()
                    #     + value.get_instruction_retired()
                    # )
                    # self.proc_table[key].set_cycles(
                    #     self.proc_table[key].get_cycles() + value.get_cycles()
                    # )
                    # self.proc_table[key].set_cache_misses(
                    #     self.proc_table[key].get_cache_misses()
                    #     + value.get_cache_misses()
                    # )
                    # self.proc_table[key].set_cache_refs(
                    #     self.proc_table[key].get_cache_refs() + value.get_cache_refs()
                    # )
                    # self.proc_table[key].set_time_ns(
                    #     self.proc_table[key].get_time_ns() + value.get_time_ns()
                    # )
                    # # Optionally: merge socket data if needed
                    # # Optionally: update last seen timestamp
                    # self.proc_table[key].set_last_seen(sample.get_max_ts())
                else:
                    # process is changed, replace entry and find cgroup_id
                    try:
                        cgroup_id = self.find_cgroup_id(key, value.tgid)
                        if cgroup_id is not None:
                            value.set_cgroup_id(cgroup_id)
                            value.set_container_id(cgroup_id[0:12])
                            self.proc_table[key] = value
                            # print(f"DEBUG: Added PID {value.get_pid()} with container_id: {value.container_id}")
                    except Exception as e:
                        # print(f"Error finding cgroup_id for key {key}: {e}")
                        continue
            else:
                # new process, add it and find cgroup_id
                try:
                    cgroup_id = self.find_cgroup_id(key, value.tgid)
                    if cgroup_id is not None:
                        value.set_cgroup_id(cgroup_id)
                        value.set_container_id(cgroup_id[0:12])
                        self.proc_table[key] = value
                        # print(f"DEBUG: Added PID {value.get_pid()} with container_id: {value.container_id}")
                except Exception as e:
                    # print(f"Error finding cgroup_id for key {key}: {e}")
                    continue
            if net_dictionary and key in net_dictionary:
                try:
                    self.proc_table[key].set_network_transactions(net_dictionary[key])
                except KeyError:
                    pass

            if nat_dictionary and key in nat_dictionary:
                try:
                    self.proc_table[key].set_nat_rules(nat_dictionary[key])
                except KeyError:
                    pass

    # def add_process_from_sample(self, sample, net_dictionary=None, nat_dictionary=None):
    #     for key, value in sample.get_pid_dict().items():
    #         value.set_last_seen_ts(sample.get_max_ts())
    #         if key in self.proc_table:
    #             # process already there, check if comm is the same
    #             if value.get_comm() == self.proc_table[key].get_comm():
    #                 # Accumulate metrics instead of overwriting
    #                 self.proc_table[key].set_power(
    #                     self.proc_table[key].get_power() + value.get_power()
    #                 )
    #                 self.proc_table[key].set_cpu_usage(
    #                     self.proc_table[key].get_cpu_usage() + value.get_cpu_usage()
    #                 )
    #                 self.proc_table[key].set_instruction_retired(
    #                     self.proc_table[key].get_instruction_retired()
    #                     + value.get_instruction_retired()
    #                 )
    #                 self.proc_table[key].set_cycles(
    #                     self.proc_table[key].get_cycles() + value.get_cycles()
    #                 )
    #                 self.proc_table[key].set_cache_misses(
    #                     self.proc_table[key].get_cache_misses()
    #                     + value.get_cache_misses()
    #                 )
    #                 self.proc_table[key].set_cache_refs(
    #                     self.proc_table[key].get_cache_refs() + value.get_cache_refs()
    #                 )
    #                 self.proc_table[key].set_time_ns(
    #                     self.proc_table[key].get_time_ns() + value.get_time_ns()
    #                 )
    #                 # Optionally: merge socket data if needed
    #                 self.proc_table[key].set_last_seen(sample.get_max_ts())
    #             else:
    #                 # process is changed, replace entry and find cgroup_id
    #                 try:
    #                     cgroup_id = self.find_cgroup_id(key, value.tgid)
    #                     if cgroup_id is not None:
    #                         value.set_cgroup_id(cgroup_id)
    #                         value.set_container_id(cgroup_id[0:12])
    #                         value.set_last_seen(sample.get_max_ts())
    #                         self.proc_table[key] = value
    #                 except Exception:
    #                     continue
    #         else:
    #             # new process, add it and find cgroup_id
    #             try:
    #                 cgroup_id = self.find_cgroup_id(key, value.tgid)
    #                 if cgroup_id is not None:
    #                     value.set_cgroup_id(cgroup_id)
    #                     value.set_container_id(cgroup_id[0:12])
    #                     value.set_last_seen(sample.get_max_ts())
    #                     self.proc_table[key] = value
    #             except Exception:
    #                 continue

    #         if net_dictionary and key in net_dictionary:
    #             try:
    #                 self.proc_table[key].set_network_transactions(net_dictionary[key])
    #             except KeyError:
    #                 pass

    #         if nat_dictionary and key in nat_dictionary:
    #             try:
    #                 self.proc_table[key].set_nat_rules(nat_dictionary[key])
    #             except KeyError:
    #                 pass

    def find_cgroup_id(self, pid, tgid):
        # print(f"DEBUG: Looking for cgroup_id for PID {pid}, TGID {tgid}")
        for id in [pid, tgid]:
            # scan proc folder searching for the pid
            for path in ["/host/proc", "/proc"]:
                try:
                    # Non-systemd Docker
                    with open(os.path.join(path, str(id), "cgroup"), "r") as f:
                        for line in f:
                            line_array = line.split("/")
                            if (
                                len(line_array) > 1
                                and len(line_array[len(line_array) - 1]) == 65
                            ):
                                return line_array[len(line_array) - 1]
                except IOError:
                    continue

            for path in ["/host/proc", "/proc"]:
                try:
                    # systemd Docker
                    with open(os.path.join(path, str(id), "cgroup"), "r") as f:
                        for line in f:
                            line_array = line.split("/")
                            if (
                                len(line_array) > 1
                                and "docker-" in line_array[len(line_array) - 1]
                                and ".scope" in line_array[len(line_array) - 1]
                            ):
                                new_id = line_array[len(line_array) - 1].replace(
                                    "docker-", ""
                                )
                                new_id = new_id.replace(".scope", "")
                                if len(new_id) == 65:
                                    return new_id

                except IOError:  # proc has already terminated
                    continue
        return None

    def get_proc_table(self):
        return self.proc_table

    def get_container_dictionary(self, mem_dictionary=None, disk_dictionary=None):
        # print("DEBUG: get_container_dictionary called")
        container_dict = {}

        for key, value in self.proc_table.items():
            # print(f"DEBUG: proc_table PID {key} container_id: {value.container_id}")
            if value.container_id:
                if value.container_id not in container_dict:
                    container_dict[value.container_id] = ContainerInfo(
                        value.container_id
                    )

                    try:
                        # retrieve info from docker
                        container = self.docker_client.containers.get(
                            value.container_id
                        )
                        # print(f"Setting name for container {value.container_id}: {container.name}")
                        container_dict[value.container_id].set_container_name(
                            str(container.name)
                        )
                        # print(f"Setting image for container {value.container_id}: {container.image}")
                        container_dict[value.container_id].set_container_image(
                            str(container.image)
                        )
                        # print(f"Setting labels for container {value.container_id}: {container.labels}")
                        container_dict[value.container_id].set_container_labels(
                            container.labels
                        )
                    except docker.errors.NotFound:
                        # Handle the case where the container is not found gracefully
                        continue

                # print(f"Adding cycles for container {value.container_id}: {value.get_cycles()}")
                container_dict[value.container_id].add_cycles(value.get_cycles())
                # print(f"Adding weighted cycles for container {value.container_id}: {value.get_aggregated_weighted_cycles()}")
                container_dict[value.container_id].add_weighted_cycles(
                    value.get_aggregated_weighted_cycles()
                )
                # print(f"Adding instructions for container {value.container_id}: {value.get_instruction_retired()}")
                container_dict[value.container_id].add_instructions(
                    value.get_instruction_retired()
                )
                # print(f"Adding cache misses for container {value.container_id}: {value.get_cache_misses()}")
                container_dict[value.container_id].add_cache_misses(
                    value.get_cache_misses()
                )
                # print(f"Adding cache refs for container {value.container_id}: {value.get_cache_refs()}")
                container_dict[value.container_id].add_cache_refs(
                    value.get_cache_refs()
                )
                # print(f"Adding time_ns for container {value.container_id}: {value.get_time_ns()}")
                container_dict[value.container_id].add_time_ns(value.get_time_ns())
                # print(f"Adding power for container {value.container_id}: {value.get_power()}")
                container_dict[value.container_id].add_power(value.get_power())
                # print(f"Adding cpu usage for container {value.container_id}: {value.get_cpu_usage()}")
                container_dict[value.container_id].add_cpu_usage(value.get_cpu_usage())
                # print(f"Adding pid for container {value.container_id}: {value.get_pid()}")
                container_dict[value.container_id].add_pid(value.get_pid())
                # print(f"Setting last_ts for container {value.container_id}: {value.get_last_ts()}")
                container_dict[value.container_id].set_last_ts(value.get_last_ts())
                # print(f"Adding network transactions for container {value.container_id}: {value.get_network_transactions()}")
                container_dict[value.container_id].add_network_transactions(
                    value.get_network_transactions()
                )
                # print(f"Adding nat rules for container {value.container_id}: {value.get_nat_rules()}")
                container_dict[value.container_id].add_nat_rules(value.get_nat_rules())

        # aggregate stuff at the container level
        for key, value in container_dict.items():
            value.compute_aggregate_network_metrics()

        if mem_dictionary:
            for key, value in container_dict.items():
                if key in mem_dictionary:
                    value.set_mem_RSS(mem_dictionary[key]["RSS"])
                    value.set_mem_PSS(mem_dictionary[key]["PSS"])
                    value.set_mem_USS(mem_dictionary[key]["USS"])

        if disk_dictionary:
            for key, value in container_dict.items():
                if key in disk_dictionary:
                    value.set_disk_kb_r(disk_dictionary[key]["kb_r"])
                    value.set_disk_kb_w(disk_dictionary[key]["kb_w"])
                    value.set_disk_num_r(disk_dictionary[key]["num_r"])
                    value.set_disk_num_w(disk_dictionary[key]["num_w"])
                    value.set_disk_avg_lat(disk_dictionary[key]["avg_lat"])

        return container_dict
