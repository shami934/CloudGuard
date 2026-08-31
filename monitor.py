"""System metrics collector using psutil.

Collects real system metrics including CPU, Memory, Disk, and Network IO.
"""

import psutil


def get_system_metrics():
    """Collect current local system metrics.
    
    Returns:
        dict: Metrics containing cpu_percent, memory_percent, disk_percent,
              bytes_sent, and bytes_recv.
    """
    # CPU usage percentage (interval=0.1 for a quick non-blocking measure)
    cpu_percent = psutil.cpu_percent(interval=0.1)

    # Virtual memory usage percentage
    memory_info = psutil.virtual_memory()
    memory_percent = memory_info.percent

    # Disk usage percentage (checks root partition)
    disk_info = psutil.disk_usage("/")
    disk_percent = disk_info.percent

    # Network IO counters
    net_io = psutil.net_io_counters()
    bytes_sent = net_io.bytes_sent
    bytes_recv = net_io.bytes_recv

    return {
        "cpu_percent": round(cpu_percent, 1),
        "memory_percent": round(memory_percent, 1),
        "disk_percent": round(disk_percent, 1),
        "bytes_sent": bytes_sent,
        "bytes_recv": bytes_recv,
    }


if __name__ == "__main__":
    metrics = get_system_metrics()
    print("Collected Local System Metrics:")
    for key, value in metrics.items():
        print(f"  {key}: {value}")
