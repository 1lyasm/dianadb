#!/usr/bin/python3

import fabric
import invoke


def make_ip_id_map(ips):
    ip_id_map = {}
    for i in range(len(ips)):
        ip_id_map[ips[i]] = i
    print(ip_id_map)
    return ip_id_map

def print_result(result, ip_id_map):
    for key, value in result.items():
        id = ip_id_map[key.host]
        print(f"{id}: \n{value.stdout}")

def run_command(command, group, ip_id_map):
    result = group.run(command, hide=True)
    print_result(result, ip_id_map)

def main():
    with open('server_ips.txt', 'r') as file:
        ips = file.read().split()
    ip_id_map = make_ip_id_map(ips)
    group = fabric.ThreadingGroup(*ips,
                               user="ubuntu",
                               connect_kwargs={"key_filename": "../../../key_pairs/dianadb_kp.pem"})
    while 1:
        command = input("> ")
        try:
            run_command(command, group, ip_id_map)
        except fabric.exceptions.GroupException:
            print("command failed")

if __name__ == "__main__":
    main()

