#!/usr/bin/env python3
"""
xytop - Combined system monitor showing process, disk I/O, and network information
"""

import os
import sys
import time
import signal
import argparse
import threading
import curses
from datetime import datetime
from collections import deque

try:
    import psutil
except ImportError:
    print("Error: python3-psutil is required. Please install it.")
    print("Run: sudo apt install python3-psutil")
    sys.exit(1)

try:
    from scapy.all import sniff, conf
except ImportError:
    print("Error: python3-scapy is required. Please install it.")
    print("Run: sudo apt install python3-scapy")
    sys.exit(1)

# Global variables
running = True
packet_counts = {'tcp': 0, 'udp': 0, 'icmp': 0, 'other': 0}
packet_sizes = {'tcp': 0, 'udp': 0, 'icmp': 0, 'other': 0}
packet_lock = threading.Lock()

# Store history for graphs
cpu_history = deque(maxlen=60)
mem_history = deque(maxlen=60)
net_history = deque(maxlen=60)
disk_history = deque(maxlen=60)

# For network traffic rate calculation
last_bytes_sent = 0
last_bytes_recv = 0
net_speed_sent = 0
net_speed_recv = 0

# For disk I/O rate calculation
last_read_bytes = 0
last_write_bytes = 0
disk_read_speed = 0
disk_write_speed = 0

# Colors
COLORS = {
    'normal': 1,
    'highlight': 2,
    'cpu': 3,
    'memory': 4,
    'swap': 5,
    'network': 6,
    'disk': 7,
    'warning': 8,
    'critical': 9,
}

def format_bytes(bytes_val):
    """Format bytes to human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1024
    return f"{bytes_val:.2f} PB"

def packet_callback(packet):
    """Callback function for packet sniffing"""
    global packet_counts, packet_sizes, packet_lock
    
    with packet_lock:
        if 'TCP' in packet:
            packet_counts['tcp'] += 1
            packet_sizes['tcp'] += len(packet)
        elif 'UDP' in packet:
            packet_counts['udp'] += 1
            packet_sizes['udp'] += len(packet)
        elif 'ICMP' in packet:
            packet_counts['icmp'] += 1
            packet_sizes['icmp'] += len(packet)
        else:
            packet_counts['other'] += 1
            packet_sizes['other'] += len(packet)

def start_packet_capture():
    """Start packet capture in a separate thread"""
    def sniffer_thread():
        sniff(prn=packet_callback, store=0, filter="ip")
    
    # Start sniffing in a separate thread
    sniffer = threading.Thread(target=sniffer_thread)
    sniffer.daemon = True
    sniffer.start()

def draw_bar(win, y, x, width, percent, color=COLORS['normal'], title=None):
    """Draw a progress bar"""
    bar_width = int(width * percent / 100)
    win.addstr(y, x, title + ": " if title else "", curses.color_pair(COLORS['normal']))
    win.addstr(y, x + (len(title) + 2 if title else 0), f"{percent:6.2f}%", curses.color_pair(color))
    x_pos = x + (len(title) + 10 if title else 8)
    win.addstr(y, x_pos, "│" + "█" * bar_width + " " * (width - bar_width) + "│", curses.color_pair(color))

def draw_graph(win, y, x, width, height, data, color, title=None):
    """Draw a simple graph using the data history"""
    if not data:
        return
    
    # Draw title
    if title:
        win.addstr(y, x, title, curses.color_pair(COLORS['normal']))
        y += 1
    
    # Draw y-axis
    for i in range(height):
        win.addstr(y + i, x, "│", curses.color_pair(COLORS['normal']))
    
    # Draw x-axis
    win.addstr(y + height - 1, x, "└" + "─" * width, curses.color_pair(COLORS['normal']))
    
    # Draw data points
    max_val = max(data) if data else 1
    if max_val == 0:
        max_val = 1
    
    data_points = list(data)[-width:] if len(data) > width else data
    for i, val in enumerate(data_points):
        if i < width:
            # Calculate height of bar (normalized to graph height)
            bar_height = int((val / max_val) * (height - 2))
            if bar_height > 0:
                for h in range(bar_height):
                    if y + height - 2 - h >= y:  # Ensure we're not drawing above the graph area
                        win.addstr(y + height - 2 - h, x + i + 1, "█", curses.color_pair(color))

def signal_handler(sig, frame):
    """Handle Ctrl+C to exit gracefully"""
    global running
    running = False

def main(stdscr):
    global running, last_bytes_sent, last_bytes_recv, net_speed_sent, net_speed_recv
    global last_read_bytes, last_write_bytes, disk_read_speed, disk_write_speed
    
    # Set up curses environment
    curses.curs_set(0)  # Hide cursor
    curses.start_color()
    curses.use_default_colors()
    
    # Initialize color pairs
    curses.init_pair(COLORS['normal'], curses.COLOR_WHITE, -1)
    curses.init_pair(COLORS['highlight'], curses.COLOR_WHITE, curses.COLOR_BLUE)
    curses.init_pair(COLORS['cpu'], curses.COLOR_GREEN, -1)
    curses.init_pair(COLORS['memory'], curses.COLOR_YELLOW, -1)
    curses.init_pair(COLORS['swap'], curses.COLOR_MAGENTA, -1)
    curses.init_pair(COLORS['network'], curses.COLOR_CYAN, -1)
    curses.init_pair(COLORS['disk'], curses.COLOR_BLUE, -1)
    curses.init_pair(COLORS['warning'], curses.COLOR_YELLOW, -1)
    curses.init_pair(COLORS['critical'], curses.COLOR_RED, -1)
    
    # Get initial network stats
    net_io = psutil.net_io_counters()
    last_bytes_sent = net_io.bytes_sent
    last_bytes_recv = net_io.bytes_recv
    
    # Get initial disk stats
    disk_io = psutil.disk_io_counters()
    if disk_io:
        last_read_bytes = disk_io.read_bytes
        last_write_bytes = disk_io.write_bytes
    
    # Start network packet capture
    try:
        start_packet_capture()
    except Exception as e:
        # Continue even if packet capture fails (might need root)
        pass
    
    # Main display loop
    while running:
        try:
            # Get terminal size - FIX: Use getmaxyx() instead of getmaxlines()
            max_y, max_x = stdscr.getmaxyx()
            
            # Clear screen
            stdscr.clear()
            
            # Display header
            header = f" xytop - Combined System Monitor | Press 'q' to quit "
            stdscr.addstr(0, (max_x - len(header)) // 2, header, curses.color_pair(COLORS['highlight']))
            
            # Get current time
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            stdscr.addstr(0, max_x - len(current_time) - 1, current_time, curses.color_pair(COLORS['normal']))
            
            # Get system statistics
            cpu_percent = psutil.cpu_percent(interval=0)
            cpu_history.append(cpu_percent)
            
            mem = psutil.virtual_memory()
            mem_percent = mem.percent
            mem_history.append(mem_percent)
            
            swap = psutil.swap_memory()
            swap_percent = swap.percent
            
            # Get network statistics
            net_io = psutil.net_io_counters()
            bytes_sent, bytes_recv = net_io.bytes_sent, net_io.bytes_recv
            
            # Calculate network speed
            net_speed_sent = bytes_sent - last_bytes_sent
            net_speed_recv = bytes_recv - last_bytes_recv
            last_bytes_sent, last_bytes_recv = bytes_sent, bytes_recv
            
            net_history.append((net_speed_sent + net_speed_recv) / 1024)  # KB/s
            
            # Get disk I/O statistics
            disk_io = psutil.disk_io_counters()
            if disk_io:
                read_bytes, write_bytes = disk_io.read_bytes, disk_io.write_bytes
                
                # Calculate disk I/O speed
                disk_read_speed = read_bytes - last_read_bytes
                disk_write_speed = write_bytes - last_write_bytes
                last_read_bytes, last_write_bytes = read_bytes, write_bytes
                
                disk_history.append((disk_read_speed + disk_write_speed) / 1024)  # KB/s
            
            # Get disk usage statistics
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            
            # Display CPU information (row 2)
            stdscr.addstr(2, 2, f"CPU Usage:", curses.color_pair(COLORS['normal']))
            cpu_color = COLORS['critical'] if cpu_percent > 90 else (COLORS['warning'] if cpu_percent > 70 else COLORS['cpu'])
            draw_bar(stdscr, 2, 13, 30, cpu_percent, cpu_color)
            
            # Display memory information (row 3-4)
            mem_color = COLORS['critical'] if mem_percent > 90 else (COLORS['warning'] if mem_percent > 70 else COLORS['memory'])
            draw_bar(stdscr, 3, 2, 30, mem_percent, mem_color, "Memory")
            stdscr.addstr(3, 50, f"Total: {format_bytes(mem.total)}", curses.color_pair(COLORS['normal']))
            stdscr.addstr(3, 70, f"Used: {format_bytes(mem.used)}", curses.color_pair(COLORS['normal']))
            
            swap_color = COLORS['critical'] if swap_percent > 90 else (COLORS['warning'] if swap_percent > 70 else COLORS['swap'])
            draw_bar(stdscr, 4, 2, 30, swap_percent, swap_color, "Swap")
            stdscr.addstr(4, 50, f"Total: {format_bytes(swap.total)}", curses.color_pair(COLORS['normal']))
            stdscr.addstr(4, 70, f"Used: {format_bytes(swap.used)}", curses.color_pair(COLORS['normal']))
            
            # Display disk information (row 5)
            disk_color = COLORS['critical'] if disk_percent > 90 else (COLORS['warning'] if disk_percent > 70 else COLORS['disk'])
            draw_bar(stdscr, 5, 2, 30, disk_percent, disk_color, "Disk")
            stdscr.addstr(5, 50, f"Total: {format_bytes(disk.total)}", curses.color_pair(COLORS['normal']))
            stdscr.addstr(5, 70, f"Used: {format_bytes(disk.used)}", curses.color_pair(COLORS['normal']))
            
            # Display network information (row 6-7)
            stdscr.addstr(6, 2, f"Network:", curses.color_pair(COLORS['normal']))
            stdscr.addstr(6, 13, f"↓ {format_bytes(net_speed_recv)}/s", curses.color_pair(COLORS['network']))
            stdscr.addstr(6, 30, f"↑ {format_bytes(net_speed_sent)}/s", curses.color_pair(COLORS['network']))
            
            # Display disk I/O information (row 7)
            if disk_io:
                stdscr.addstr(7, 2, f"Disk I/O:", curses.color_pair(COLORS['normal']))
                stdscr.addstr(7, 13, f"Read: {format_bytes(disk_read_speed)}/s", curses.color_pair(COLORS['disk']))
                stdscr.addstr(7, 35, f"Write: {format_bytes(disk_write_speed)}/s", curses.color_pair(COLORS['disk']))
            
            # Display packet statistics (row 8-9)
            with packet_lock:
                total_packets = sum(packet_counts.values())
                total_size = sum(packet_sizes.values())
            
            stdscr.addstr(8, 2, f"Packets:", curses.color_pair(COLORS['normal']))
            stdscr.addstr(8, 13, f"TCP: {packet_counts['tcp']}", curses.color_pair(COLORS['network']))
            stdscr.addstr(8, 30, f"UDP: {packet_counts['udp']}", curses.color_pair(COLORS['network']))
            stdscr.addstr(8, 45, f"ICMP: {packet_counts['icmp']}", curses.color_pair(COLORS['network']))
            stdscr.addstr(8, 60, f"Other: {packet_counts['other']}", curses.color_pair(COLORS['network']))
            
            stdscr.addstr(9, 2, f"Traffic:", curses.color_pair(COLORS['normal']))
            stdscr.addstr(9, 13, f"Total: {format_bytes(total_size)}", curses.color_pair(COLORS['network']))
            
            # Draw graphs
            graph_start_y = 11
            graph_width = min(60, (max_x - 10) // 2)
            graph_height = 8
            
            # CPU and Memory graphs
            draw_graph(stdscr, graph_start_y, 2, graph_width, graph_height, cpu_history, COLORS['cpu'], "CPU History (%)")
            draw_graph(stdscr, graph_start_y, 5 + graph_width, graph_width, graph_height, mem_history, COLORS['memory'], "Memory History (%)")
            
            # Network and Disk I/O graphs
            draw_graph(stdscr, graph_start_y + graph_height + 1, 2, graph_width, graph_height, net_history, COLORS['network'], "Network Traffic (KB/s)")
            draw_graph(stdscr, graph_start_y + graph_height + 1, 5 + graph_width, graph_width, graph_height, disk_history, COLORS['disk'], "Disk I/O (KB/s)")
            
            # Process list
            proc_start_y = graph_start_y + 2 * graph_height + 2
            stdscr.addstr(proc_start_y, 2, "Top Processes:", curses.color_pair(COLORS['highlight']))
            stdscr.addstr(proc_start_y + 1, 2, "PID    CPU%   MEM%   Name", curses.color_pair(COLORS['highlight']))
            
            try:
                processes = []
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                    try:
                        pinfo = proc.info
                        processes.append((
                            pinfo['pid'],
                            proc.cpu_percent(),
                            proc.memory_percent(),
                            pinfo['name']
                        ))
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass
                
                # Sort by CPU usage
                processes.sort(key=lambda x: x[1], reverse=True)
                
                # Display top processes
                for i, proc in enumerate(processes[:10]):  # Show top 10 processes
                    if proc_start_y + 2 + i < max_y:  # Ensure we don't draw beyond the screen
                        pid, cpu_percent, mem_percent, name = proc
                        proc_color = COLORS['critical'] if cpu_percent > 90 else (COLORS['warning'] if cpu_percent > 70 else COLORS['normal'])
                        stdscr.addstr(proc_start_y + 2 + i, 2, f"{pid:6d}", curses.color_pair(COLORS['normal']))
                        stdscr.addstr(proc_start_y + 2 + i, 9, f"{cpu_percent:5.1f}", curses.color_pair(proc_color))
                        stdscr.addstr(proc_start_y + 2 + i, 16, f"{mem_percent:5.1f}", curses.color_pair(COLORS['memory']))
                        stdscr.addstr(proc_start_y + 2 + i, 23, f"{name[:max_x-24]}", curses.color_pair(COLORS['normal']))
            except Exception as e:
                stdscr.addstr(proc_start_y + 2, 2, f"Error getting process info: {str(e)}", curses.color_pair(COLORS['critical']))
            
            # Refresh the screen
            stdscr.refresh()
            
            # Check for user input (non-blocking)
            stdscr.timeout(1000)  # Wait up to 1 second for key press
            key = stdscr.getch()
            if key == ord('q') or key == ord('Q'):
                running = False
                break
            
            # Sleep for update interval
            time.sleep(1)
            
        except curses.error:
            # Terminal size might be too small, just wait and retry
            time.sleep(1)
        except KeyboardInterrupt:
            running = False
            break
        except Exception as e:
            # Try to exit gracefully on error
            stdscr.clear()
            stdscr.addstr(0, 0, f"Error: {str(e)}")
            stdscr.refresh()
            time.sleep(3)
            running = False
            break

def run():
    # Set up signal handler for graceful exit
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = argparse.ArgumentParser(description='xytop - Combined system monitor')
    parser.add_argument('-v', '--version', action='store_true', help='Show version information')
    args = parser.parse_args()
    
    if args.version:
        print("xytop v1.0.0 - Combined system monitor")
        return
    
    # Check if running as root (needed for some network features)
    if os.geteuid() != 0:
        print("Note: Some network features require root privileges.")
        print("Consider running with 'sudo' for full functionality.")
    
    try:
        # Start the curses UI
        curses.wrapper(main)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Error: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(run())
