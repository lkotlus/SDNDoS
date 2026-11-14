import argparse
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

from mininet.cli import CLI

from sdndos_network.hosts import create_network, start_servers

ROOT = Path(__file__).resolve().parent
CONTROLLER_LOG = ROOT / "controller.log"
OPENFLOW_PORT = 6653


def elevate_privileges():
    if os.geteuid() != 0:
        try:
            os.execvp(
                "sudo",
                [
                    "sudo",
                    sys.executable,
                    os.path.abspath(__file__),
                    *sys.argv[1:]
                ]
            )
        except OSError as e:
            print(f"Something went wrong while elevating privileges: {e}")
            sys.exit(1)


def start_controller(switch_path: str) -> subprocess.Popen:
    manager = Path(sys.executable).parent / "osken-manager"
    # Add the repo root to the osken-manager path
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(ROOT), env.get("PYTHONPATH")]))
    with open(CONTROLLER_LOG, "w") as log:
        return subprocess.Popen(
            [str(manager), str(Path(switch_path).resolve())],
            stdout=log,
            stderr=subprocess.STDOUT,
            env=env,
            start_new_session=True,
        )


def is_listening(port: int) -> bool:
    """Check the kernel's socket tables for a TCP listener on the given port."""
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(table) as f:
                next(f)
                for line in f:
                    fields = line.split()
                    local_addr, state = fields[1], fields[3]
                    if state == "0A" and int(local_addr.rsplit(":", 1)[1], 16) == port:
                        return True
        except FileNotFoundError:
            continue
    return False


def wait_for_controller(proc: subprocess.Popen, port: int = OPENFLOW_PORT, timeout: float = 15):
    """
    Wait until the controller is listening, without opening a connection to it.
    Fails fast if the controller process dies.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(
                f"Controller exited with code {proc.returncode}, check {CONTROLLER_LOG}"
            )
        if is_listening(port):
            return
        time.sleep(0.25)
    raise RuntimeError(f"Controller wasn't listening within {timeout}s, check {CONTROLLER_LOG}")


def ensure_port_free(port: int = OPENFLOW_PORT):
    """
    Refuse to start if something is already listening on the OpenFlow port,
    usually an osken-manager left over from an earlier run. Otherwise the new controller
    fails to bind and the switch silently connects to (or loses) the old one.
    """
    if is_listening(port):
        raise RuntimeError(
            f"Port {port} is already in use, likely a leftover controller. "
            f"Check with `sudo ss -ltnp | grep {port}`, or clear it with "
            "`sudo pkill -f osken-manager` and `sudo mn -c`."
        )


def watch_controller(proc: subprocess.Popen, stopping: threading.Event, interval: float = 0.5):
    """
    Warn as soon as the controller exits on its own. With the switch in secure
    fail mode, every packet without an existing flow is dropped from that point on.
    """
    def watch():
        while not stopping.is_set():
            if proc.poll() is not None:
                if not stopping.is_set():
                    sys.stderr.write(
                        f"\n*** WARNING: controller exited with code {proc.returncode}, "
                        f"new flows will be dropped. Check {CONTROLLER_LOG}\n"
                    )
                    sys.stderr.flush()
                return
            stopping.wait(interval)

    thread = threading.Thread(target=watch, name="controller-watch", daemon=True)
    thread.start()
    return thread


def stop_controller(proc: subprocess.Popen, timeout: float = 5):
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DoS-responding SDN testbed")
    parser.add_argument(
        "-s", "--num-servers", type=int, required=True,
        help="The number of internal servers running applications."
    )
    parser.add_argument(
        "-e", "--num-external", type=int, required=True,
        help="The number of external hosts to send traffic to the internal hosts."
    )
    parser.add_argument(
        "-S", "--switch", type=str, required=False,
        default="switches/dumb_switch.py",
        help="Path to the switch file you want to use."
    )
    args = parser.parse_args()

    elevate_privileges()

    osken = None
    topo = None
    procs = []
    stopping = threading.Event()

    try:
        ensure_port_free()
        osken = start_controller(args.switch)
        wait_for_controller(osken)
        watch_controller(osken, stopping)

        topo = create_network(args.num_servers, args.num_external)
        topo.net.start()

        procs = start_servers(topo.servers)
        CLI(topo.net)
    finally:
        stopping.set()

        for p in procs:
            p.terminate()

        if topo is not None:
            topo.net.stop()

        if osken is not None:
            stop_controller(osken)
