"""System metrics collector using psutil.

Collects real system metrics including CPU, Memory, Disk, and Network IO.
"""

import time
import psutil

_last_net_counters = None
_last_net_time = None


def get_system_metrics():
    """Collect current local system metrics.
    
    Returns:
        dict: Metrics containing cpu_percent, memory_percent, disk_percent,
              bytes_sent, and bytes_recv.
    """
    global _last_net_counters, _last_net_time

    # CPU usage percentage (interval=0.1 for a quick non-blocking measure)
    cpu_percent = psutil.cpu_percent(interval=0.1)

    # Virtual memory usage percentage
    memory_info = psutil.virtual_memory()
    memory_percent = memory_info.percent

    # Disk usage percentage (checks root partition)
    disk_info = psutil.disk_usage("/")
    disk_percent = disk_info.percent

    # Network IO counters - calculate interval delta bytes
    net_io = psutil.net_io_counters()
    now = time.time()

    if _last_net_counters is not None and _last_net_time is not None:
        delta_sent = max(net_io.bytes_sent - _last_net_counters.bytes_sent, 0)
        delta_recv = max(net_io.bytes_recv - _last_net_counters.bytes_recv, 0)
    else:
        delta_sent = 0
        delta_recv = 0

    _last_net_counters = net_io
    _last_net_time = now

    return {
        "cpu_percent": round(cpu_percent, 1),
        "memory_percent": round(memory_percent, 1),
        "disk_percent": round(disk_percent, 1),
        "bytes_sent": delta_sent,
        "bytes_recv": delta_recv,
    }


if __name__ == "__main__":
    metrics = get_system_metrics()
    print("Collected Local System Metrics:")
    for key, value in metrics.items():
        print(f"  {key}: {value}")
