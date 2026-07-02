import whois

print("=" * 60)
print("                  WHOIS LOOKUP TOOL")
print("=" * 60)

domain = input("Enter a domain (example.com): ").strip()

try:
    w = whois.whois(domain)

    print("\n" + "=" * 60)
    print("                    WHOIS REPORT")
    print("=" * 60)

    print(f"Domain Name      : {w.domain_name}")
    print(f"Registrar        : {w.registrar}")
    print(f"WHOIS Server     : {getattr(w, 'whois_server', 'N/A')}")
    print(f"Creation Date    : {w.creation_date}")
    print(f"Updated Date     : {w.updated_date}")
    print(f"Expiration Date  : {w.expiration_date}")
    print(f"Status           : {w.status}")
    print(f"Name Servers     : {w.name_servers}")
    print(f"Emails           : {w.emails}")
    print(f"DNSSEC           : {getattr(w, 'dnssec', 'N/A')}")

    print("=" * 60)

except Exception as e:
    print(f"\nLookup failed: {e}")

input("\nPress Enter to exit...")