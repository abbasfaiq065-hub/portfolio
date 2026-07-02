import subprocess
import platform
import re
import socket

print("=" * 60)
print(" PING TOOL")
print("=" * 60)

target = input("Enter IP or Hostname: ").strip()

system = platform.system().lower()

if system == "windows":
    command = ["ping", "-n", "5", target]
else:
    command = ["ping", "-c", "5", target]

print("\nPinging...\n")

result = subprocess.run(command, capture_output=True, text=True)
output = result.stdout

try:
    hostname = socket.gethostbyaddr(target)[0]
except:
    hostname = target

try:
    resolved_ip = socket.gethostbyname(target)
except:
    resolved_ip = "Unknown"

status = "REACHABLE" if "TTL=" in output.upper() or "ttl=" in output else "UNREACHABLE"

loss = "Unknown"
minimum = average = maximum = "Unknown"

if system == "windows":
    loss_match = re.search(r"Lost = (\d+) \((\d+)% loss\)", output)
    time_match = re.search(r"Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms", output)

    if loss_match:
        loss = f"{loss_match.group(2)}%"

    if time_match:
        minimum = f"{time_match.group(1)} ms"
        maximum = f"{time_match.group(2)} ms"
        average = f"{time_match.group(3)} ms"

else:
    loss_match = re.search(r"(\d+(?:\.\d+)?)% packet loss", output)
    time_match = re.search(r"min/avg/max.* = ([\d.]+)/([\d.]+)/([\d.]+)", output)

    if loss_match:
        loss = f"{loss_match.group(1)}%"

    if time_match:
        minimum = f"{time_match.group(1)} ms"
        average = f"{time_match.group(2)} ms"
        maximum = f"{time_match.group(3)} ms"

activity = "■ " * 5 if status == "REACHABLE" else "□ " * 5

print("╔══════════════════════════════════════════════════════════════╗")
print("║ NETWORK PING REPORT ║")
print("╠══════════════════════════════════════════════════════════════╣")
print(f"║ Target : {target:<43}║")
print(f"║ Resolved IP : {resolved_ip:<43}║")
print(f"║ Hostname : {hostname:<43}║")
print(f"║ Status : {status:<43}║")
print("╠══════════════════════════════════════════════════════════════╣")
print(f"║ Packets Sent : {'5':<43}║")
print(f"║ Packet Loss : {loss:<43}║")
print(f"║ Min Latency : {minimum:<43}║")
print(f"║ Avg Latency : {average:<43}║")
print(f"║ Max Latency : {maximum:<43}║")
print("╠══════════════════════════════════════════════════════════════╣")
print(f"║ Activity : {activity:<43}║")
print("╚══════════════════════════════════════════════════════════════╝")

input("\nPress Enter to exit...")
