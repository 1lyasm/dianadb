#!/usr/bin/python3

import subprocess
import select

def start_server(addr):
    command = ["../target/debug/diserver", addr]
    return subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def non_blocking_readlines(fd):
    output = []
    while True:
        rlist, _, _ = select.select([fd], [], [], 0.1)
        if not rlist:
            break
        line = fd.readline().decode("utf-8")
        if not line:
            break
        output.append(line)
    return output

def main():
    addr_list = ["127.0.0.1:6789",
                 "127.0.0.2:6789",
                 "127.0.0.3:6789",
                 "127.0.0.4:6789",
                 "127.0.0.5:6789",
                 "127.0.0.6:6789"]
    processes = []

    for addr in addr_list:
        process = start_server(addr)
        processes.append(process)

    while processes:
        for process in processes:
            retcode = process.poll()
            if retcode is not None:  # Process has finished
                print(f"Process {process.pid} exited with code {retcode}")
                stdout, stderr = process.communicate()
                print("STDOUT:", stdout.decode("utf-8"))
                print("STDERR:", stderr.decode("utf-8"))
                processes.remove(process)
            else:
                # Process is still running, print its output if available
                stdout_lines = non_blocking_readlines(process.stdout)
                stderr_lines = non_blocking_readlines(process.stderr)
                if stdout_lines:
                    print(f"Process {process.pid} STDOUT:")
                    print("".join(stdout_lines))
                if stderr_lines:
                    print(f"Process {process.pid} STDERR:")
                    print("".join(stderr_lines))

if __name__ == "__main__":
    main()

