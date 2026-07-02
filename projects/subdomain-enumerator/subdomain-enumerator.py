import asyncio
import dns.asyncresolver

SUBDOMAINS = [
    "www", "dev", "test", "admin", "staging",
    "mail", "blog", "webmail", "server",
    "ns1", "ns2", "smtp", "secure", "vpn",
    "api", "portal", "beta", "web", "ftp",
    "cpanel", "shop", "forum", "support"
]

resolver = dns.asyncresolver.Resolver()
resolver.lifetime = 1.0
resolver.timeout = 1.0

async def check(host):
    try:
        answer = await resolver.resolve(host, "A")
        print(f"[+] {host:<35} {answer[0]}")
    except Exception:
        pass

async def main():
    domain = input("Target domain: ").strip()

    print(f"\nScanning {domain}...\n")

    tasks = [
        check(f"{sub}.{domain}")
        for sub in SUBDOMAINS
    ]

    await asyncio.gather(*tasks)

    input("\nPress Enter to continue...")

if __name__ == "__main__":
    asyncio.run(main())