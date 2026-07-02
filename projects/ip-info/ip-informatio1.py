import socket
import requests
from colorama import Fore, Style, init

init(autoreset=True)

class IPInfoFetcher:
    def __init__(self, ip):
        self.ip = ip

    def get_hostname(self):
        """Performs a Reverse DNS Lookup to find the hostname associated with the IP."""
        try:
            hostname = socket.gethostbyaddr(self.ip)[0]
            return hostname
        except socket.herror:
            return "No reverse DNS record found"
        except Exception as e:
            return f"Error: {str(e)}"

    def get_geo_data(self):
        """Fetches detailed location and ISP data from ip-api.com."""
        try:
            # ip-api.com is free and does not require an API key for low-volume use
            url = f"http://ip-api.com/json/{self.ip}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # Check if the API returned success
                if data.get('status') == 'success':
                    return {
                        "Country": data.get('country'),
                        "Region": data.get('regionName'),
                        "City": data.get('city'),
                        "ZIP": data.get('zip'),
                        "ISP": data.get('isp'),
                        "Org": data.get('org'),
                        "AS": data.get('as'),  # Autonomous System
                        "Lat": data.get('lat'),
                        "Lon": data.get('lon'),
                        "Timezone": data.get('timezone')
                    }
                else:
                    return {"Error": f"API Error: {data.get('message', 'Unknown')}"}
            else:
                return {"Error": f"HTTP Error: {response.status_code}"}
                
        except requests.exceptions.Timeout:
            return {"Error": "Request timed out"}
        except Exception as e:
            return {"Error": str(e)}

    def display_info(self):
        print(f"{Fore.YELLOW}{'='*50}")
        print(f"{Fore.YELLOW}   IP Intelligence Report")
        print(f"{Fore.YELLOW}{'='*50}{Style.RESET_ALL}\n")

        # 1. Basic Info
        print(f"{Fore.CYAN}[+] Target IP: {self.ip}{Style.RESET_ALL}")
        
        hostname = self.get_hostname()
        print(f"{Fore.GREEN}[+] Hostname: {hostname}{Style.RESET_ALL}")

        # 2. Geolocation & ISP
        print(f"\n{Fore.CYAN}[-] Fetching Location & ISP Data...{Style.RESET_ALL}")
        geo_data = self.get_geo_data()

        if "Error" in geo_data:
            print(f"{Fore.RED}[!] {geo_data['Error']}{Style.RESET_ALL}")
        else:
            # Display data in a clean format
            print(f"{Fore.WHITE}    {'Field':<15}: {Fore.LIGHTWHITE_EX}Value{Style.RESET_ALL}")
            print(f"    {'-'*30}")
            
            for key, value in geo_data.items():
                if key != "Error":
                    # Format nicely (e.g., capitalize keys)
                    label = key.replace('_', ' ').title()
                    print(f"    {label:<15}: {value}")

        print(f"\n{Fore.BLUE}{'='*50}{Style.RESET_ALL}")
        
        # Wait for user input to close
        input(f"{Fore.CYAN}[+] Press Enter to exit...{Style.RESET_ALL}")

def main():
    target_ip = input("Enter an IP Address (e.g., 8.8.8.8): ").strip()
    
    if not target_ip:
        print(f"{Fore.RED}[-] No IP provided.{Style.RESET_ALL}")
        return

    try:
        # Basic validation to ensure it looks like an IP
        socket.inet_aton(target_ip)
        fetcher = IPInfoFetcher(target_ip)
        fetcher.display_info()
    except socket.error:
        print(f"{Fore.RED}[-] Invalid IP Address format.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()