import os
import subprocess
import json
import logging
from pathlib import Path
from typing import Dict, List, Tuple


# CO-RE approach, better than BCC approach:
# bcc python bindings are a nightmare to install. Besides it requires linux kernel headers.
# And the worse part is that it cannot use a CO-RE approach and needs to recompile the program everytime.
# So we choose a more recent BTF approach (compiling the program once during build, since every cgroup can use
# the same program with a different map)
# + bpfcc-tools + subprocess approach. Less pythonic but
# more perf and more robust (when will python have decent (e)bpf bindings ??)
LOG = logging.getLogger(__name__)
BPF_OBJ_FILE = Path("../device_api/bpf/device_filter.bpf.o")
PIN_LOCATION = Path("/sys/fs/bpf/mytest")

# https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_CGROUP_DEVICE/
BPF_DEVCG_ACC_MKNOD = 1
BPF_DEVCG_ACC_READ = 2
BPF_DEVCG_ACC_WRITE = 4

BPF_DEVCG_DEV_BLOCK = 1
BPF_DEVCG_DEV_CHAR  = 2


# --- Shell helper ---
def run(cmd):
    """Run a shell command and return stdout, raise on failure."""
    LOG.debug(f"CMD: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {cmd}\n{result.stderr}")
    return result.stdout.strip()


# --- Path helpers ---
def get_cgroup_map_path(cgroup_path: Path, map_name: str) -> Path:
    return PIN_LOCATION / f"{cgroup_path.name}_{map_name}"


def get_cgroup_prog_path(cgroup_path: Path, prog_name: str) -> Path:
    return PIN_LOCATION / f"{cgroup_path.name}_{prog_name}"


# --- BPF helpers using JSON output ---
def get_prog_info(prog_pin_path: Path) -> Dict:
    """Return numeric program ID of a pinned program using JSON."""
    out = run(f"bpftool -j prog show pinned {prog_pin_path}")
    data = json.loads(out)
    return data


def get_map_id_for_prog(prog_id):
    """Return the first map ID used by a given program ID using JSON."""
    out = run(f"bpftool -j prog show id {prog_id}")
    data = json.loads(out)
    return data[0]["map_ids"][0]


def list_map_keys(map_pin_path: Path) -> List[Tuple[int, int, int]]:
    """
    Return all keys in the pinned map as (major, minor) tuples.
    Works with CO-RE / BTF maps where bpftool -j returns a list of byte strings.
    """
    out = run(f"bpftool -j map dump pinned {map_pin_path}")
    data = json.loads(out)
    keys = []

    for entry in data:
        raw_key = entry["key"]
        if isinstance(raw_key, list):
            # Convert list of bytes ["0x01","0x00",...] → integer little-endian
            key_bytes = bytes(int(b, 16) for b in raw_key)
        else:
            # fallback: already a string like "0x0100000005000000"
            key_bytes = bytes.fromhex(raw_key[2:])

        major = int.from_bytes(key_bytes[:4], "little")
        minor = int.from_bytes(key_bytes[4:8], "little")
        dev_type = int.from_bytes(key_bytes[8:], "little")
        keys.append((major, minor, dev_type))

    return keys


# --- Load program + pin map per cgroup ---
def load_and_pin_bpf(cgroup_path: Path) -> Tuple[Path, Path]:
    prog_pin_path = get_cgroup_prog_path(cgroup_path, "device_filter")
    map_pin_path = get_cgroup_map_path(cgroup_path, "allowed_devices")

    # Only load program if not already pinned
    if not os.path.exists(prog_pin_path):
        LOG.info("Loading and pinning device filter program to %s", prog_pin_path)
        run(f"bpftool prog load {BPF_OBJ_FILE} {prog_pin_path} type cgroup/dev")

    prog_info = get_prog_info(prog_pin_path)
    prog_id = prog_info['id']
    map_id = prog_info['map_ids'][0]

    # Pin the map if not pinned yet
    if not os.path.exists(map_pin_path):
        LOG.info("Pinning map related to program %s at %s", prog_pin_path, map_pin_path)
        run(f"bpftool map pin id {map_id} {map_pin_path}")

    LOG.info("BPF program %s and map %s loaded and pinned to %s and %s", prog_id, map_id, prog_pin_path, map_pin_path)
    return prog_pin_path, map_pin_path


# --- Attach program to cgroup ---
def attach_to_cgroup(cgroup_path, prog_pin_path):
    # Check if program already attached
    out = run(f"bpftool -j cgroup show {cgroup_path}")
    if out:
        data = json.loads(out)
        attached_ids = [p["id"] for p in data]
    else:
        attached_ids = []
    prog_info = get_prog_info(prog_pin_path)
    prog_id = prog_info['id']
    if prog_id in attached_ids:
        LOG.debug(f"Program already attached to {cgroup_path}")
        return

    run(f"bpftool cgroup attach {cgroup_path} cgroup_device id {prog_id} multi")
    LOG.info(f"Attached device_filter to {cgroup_path}")


# --- Map manipulation helpers ---
def map_insert(map_pin_path: Path, major: int, minor: int, dev_type: int, allow_flags: int):
    """Insert or update an entry in the device map (CO-RE maps)."""
    # Convert key/value to little-endian bytes
    key_bytes = major.to_bytes(4, "little") + minor.to_bytes(4, "little") + dev_type.to_bytes(4, "little")
    val_bytes = allow_flags.to_bytes(4, "little")

    # Build bpftool command with each byte as separate hex token
    key_hex_tokens = " ".join(f"{b:02x}" for b in key_bytes)
    val_hex_tokens = " ".join(f"{b:02x}" for b in val_bytes)

    run(f"bpftool map update pinned {map_pin_path} key hex {key_hex_tokens} value hex {val_hex_tokens}")


def map_delete(map_pin_path: Path, major: int, minor: int, dev_type: int):
    """Delete an entry from the device map (CO-RE maps)."""
    key_bytes = major.to_bytes(4, "little") + minor.to_bytes(4, "little") + dev_type.to_bytes(4, "little")
    key_hex_tokens = " ".join(f"{b:02x}" for b in key_bytes)
    run(f"bpftool map delete pinned {map_pin_path} key hex {key_hex_tokens}")


def map_clear(map_pin_path: Path):
    """Remove all entries from the map."""
    keys = list_map_keys(map_pin_path)
    for (major, minor, dev_type) in keys:
        map_delete(map_pin_path, major, minor, dev_type)


# --- Example usage ---
if __name__ == "__main__":

    logging.basicConfig(level=logging.DEBUG)
    cgroups = [
        Path("/sys/fs/cgroup/mytest/"),
    ]

    for cg_path in cgroups:
        prog_path, map_path = load_and_pin_bpf(cg_path)
        attach_to_cgroup(cg_path, prog_path)

        # Insert example entries
        map_insert(map_path, 1, 5, BPF_DEVCG_DEV_CHAR, BPF_DEVCG_ACC_MKNOD | BPF_DEVCG_ACC_READ)  # device 1:5:c with allow_flags=rm
        map_insert(map_path, 1, 0xFFFFFFFF, BPF_DEVCG_DEV_CHAR, BPF_DEVCG_ACC_MKNOD)  # wildcard minor for major 1

        print(list_map_keys(map_path))

        # To delete a device:
        map_delete(map_path, 1, 5, BPF_DEVCG_DEV_CHAR)
        print(list_map_keys(map_path))

        # To clear a map:
        map_clear(map_path)
        print(list_map_keys(map_path))
