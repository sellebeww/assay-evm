"""S3 to S6 and the process policy, against the real runner image.

The probes run the Python that the image carries for Slither, under the complete container
policy of `SandboxRunner` (see `run_policy_probe`). The argv allowlist, which would refuse that
program, is the only layer removed, so each limit observed here is enforced by the container.

- S3: enormous output is cut at the limit, and the runner does not keep it in memory.
- S4: an endless loop ends with `timed_out`, and the container is gone afterwards.
- S5: a fork bomb stops at the pids limit.
- S6: no network beyond loopback: no route, no DNS, no connection to the internet or to the
  Docker host; loopback works.
- S9: the container sees no variable of the host environment, runs as uid and gid 10001, holds
  no capability, and cannot gain privileges.
"""

import json
import os
import resource
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from assay.sandbox import SandboxLimits, SandboxRunner

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("runner")]

Probe = Callable[..., Any]

FLOOD = """
import os
chunk = b"x" * (1 << 20)
for _ in range(64):
    os.write(1, chunk)
    os.write(2, chunk)
"""


def _max_rss_bytes() -> int:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux reports kibibytes, macOS bytes.
    return peak if sys.platform == "darwin" else peak * 1024


def test_s3_enormous_output_is_cut_and_not_kept(tmp_path: Path, policy_probe: Probe) -> None:
    limit = 1 << 20
    runner = SandboxRunner(limits=SandboxLimits(output_limit_bytes=limit))
    before = _max_rss_bytes()

    result = policy_probe(runner, FLOOD, tmp_path)

    assert result.exit_code == 0
    assert result.truncated
    assert len(result.stdout.encode()) <= limit
    assert len(result.stderr.encode()) <= limit
    assert not result.timed_out
    # 128 MiB went through the pipes; the runner kept at most the two limits.
    assert _max_rss_bytes() - before < 48 * (1 << 20)


def test_s4_an_endless_loop_is_killed_and_the_container_removed(
    tmp_path: Path, policy_probe: Probe
) -> None:
    runner = SandboxRunner(limits=SandboxLimits(timeout_s=5))
    before = runner.list_containers()

    result = policy_probe(runner, "while True:\n    pass\n", tmp_path, timeout_s=5)

    assert result.timed_out
    assert 5 <= result.duration_s < 45
    assert result.exit_code != 0
    assert runner.list_containers() == before


FORK_BOMB = """
import errno, os, time
children, failure = 0, None
try:
    while children < 4096:
        pid = os.fork()
        if pid == 0:
            time.sleep(30)
            os._exit(0)
        children += 1
except OSError as exc:
    failure = errno.errorcode.get(exc.errno, str(exc.errno))
print(f"children={children} failure={failure}", flush=True)
"""


def test_s5_a_fork_bomb_stops_at_the_pids_limit(tmp_path: Path, policy_probe: Probe) -> None:
    limits = SandboxLimits(pids=64, timeout_s=60)
    runner = SandboxRunner(limits=limits)
    before = runner.list_containers()

    result = policy_probe(runner, FORK_BOMB, tmp_path)

    assert not result.timed_out, result.stderr
    line = result.stdout.strip().splitlines()[-1]
    fields = dict(item.split("=", 1) for item in line.split())
    assert fields["failure"] == "EAGAIN", line
    assert 0 < int(fields["children"]) < limits.pids
    # The sleeping children went with the container.
    assert runner.list_containers() == before


NETWORK_PROBE = """
import json, socket
found = {}
def attempt(name, action):
    try:
        action()
        found[name] = "ok"
    except OSError as exc:
        found[name] = type(exc).__name__ + ":" + str(exc.errno)

def tcp(host, port):
    with socket.create_connection((host, port), timeout=3):
        pass

def udp(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(b"x", (host, port))

def tcp6(host, port):
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
        sock.settimeout(3)
        sock.connect((host, port))

attempt("tcp_internet", lambda: tcp("1.1.1.1", 443))
attempt("udp_internet", lambda: udp("8.8.8.8", 53))
attempt("tcp6_internet", lambda: tcp6("2606:4700:4700::1111", 443))
attempt("docker_desktop_host", lambda: tcp("192.168.65.254", 80))
attempt("bridge_gateway", lambda: tcp("172.17.0.1", 80))
attempt("dns", lambda: socket.getaddrinfo("example.com", 443))
attempt("host_name", lambda: socket.getaddrinfo("host.docker.internal", 80))

server = socket.socket()
server.bind(("127.0.0.1", 0))
server.listen(1)
attempt("loopback", lambda: tcp("127.0.0.1", server.getsockname()[1]))

with open("/proc/net/route") as handle:
    found["routes"] = [line.split()[0] for line in handle.read().splitlines()[1:]]
up = []
for name in sorted(n for _, n in socket.if_nameindex()):
    with open(f"/sys/class/net/{name}/operstate") as handle:
        state = handle.read().strip()
    with open(f"/sys/class/net/{name}/flags") as handle:
        flags = int(handle.read().strip(), 16)
    if flags & 0x1:
        up.append(name)
found["interfaces_up"] = up
print(json.dumps(found), flush=True)
"""


def test_s6_there_is_no_network_beyond_loopback(
    tmp_path: Path, policy_probe: Probe, runner: SandboxRunner
) -> None:
    result = policy_probe(runner, NETWORK_PROBE, tmp_path)

    assert result.exit_code == 0, result.stderr
    found = json.loads(result.stdout.strip().splitlines()[-1])
    assert found["loopback"] == "ok"
    for name in (
        "tcp_internet",
        "udp_internet",
        "tcp6_internet",
        "docker_desktop_host",
        "bridge_gateway",
        "dns",
        "host_name",
    ):
        assert found[name] != "ok", (name, found)
    assert found["routes"] == []
    assert found["interfaces_up"] == ["lo"]


PROCESS_PROBE = """
import json, os
status = {}
with open("/proc/self/status") as handle:
    for line in handle:
        key, _, value = line.partition(":")
        status[key] = value.strip()
print(json.dumps({
    "env": sorted(os.environ),
    "uid": os.getuid(), "gid": os.getgid(), "groups": os.getgroups(),
    "cap_eff": status["CapEff"], "cap_prm": status["CapPrm"], "cap_bnd": status["CapBnd"],
    "no_new_privs": status["NoNewPrivs"],
}), flush=True)
"""


def test_s9_no_host_environment_no_root_no_capabilities(
    tmp_path: Path, runner: SandboxRunner, monkeypatch: pytest.MonkeyPatch, policy_probe: Probe
) -> None:
    monkeypatch.setenv("ASSAY_HOST_SENTINEL", "must-not-reach-the-container")
    monkeypatch.setenv("ASSAY_LLM_API_KEY", "must-not-reach-the-container")

    result = policy_probe(runner, PROCESS_PROBE, tmp_path)

    assert result.exit_code == 0, result.stderr
    found = json.loads(result.stdout.strip().splitlines()[-1])
    host_only = set(os.environ) - {"HOME", "PATH"}
    assert not set(found["env"]) & host_only
    assert "ASSAY_HOST_SENTINEL" not in found["env"]
    assert (found["uid"], found["gid"]) == (10001, 10001)
    assert found["groups"] in ([], [10001])
    assert int(found["cap_eff"], 16) == 0
    assert int(found["cap_prm"], 16) == 0
    assert int(found["cap_bnd"], 16) == 0
    assert found["no_new_privs"] == "1"
