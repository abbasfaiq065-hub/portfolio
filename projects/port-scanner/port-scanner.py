import socket
import threading

PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP-Alt",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1433: "MSSQL",
    1521: "Oracle",
    2082: "cPanel",
    2083: "cPanel-SSL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

print("=== Port Scanner ===")
target = input("Enter IP address: ").strip()

open_ports = []

def scan(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        if s.connect_ex((target, port)) == 0:
            print(f"[OPEN] {port:<5} {PORTS[port]}")
            open_ports.append((port, PORTS[port]))
        s.close()
    except:
        pass

threads = []

for port in PORTS:
    t = threading.Thread(target=scan, args=(port,))
    t.start()
    threads.append(t)

for t in threads:
    t.join()

print("\n=== Scan Complete ===")

if open_ports:
    print("Open ports:")
    for port, service in sorted(open_ports):
        print(f"{port:<5} {service}")
else:
    print("No listed ports are open.")

input("\nPress Enter to close...")