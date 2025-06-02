import whois
from bs4 import BeautifulSoup
import requests
import dns.resolver
import socket
import nmap
import re
import os

default_domain = "papashoes-pu.com"
use_default = input(f"Do you want to use domain {default_domain}? (yes/no): ").strip().lower()


if use_default == "no":
    domain = input("Enter the domain: ").strip()
else:
    domain = default_domain

def get_links(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, "html.parser")
    links = [link.get("href") for link in soup.find_all("a") if link.get("href") and link.get("href").startswith("http")]
    return links

def crawl_site(url, depth=2):#1
    site_map = {}
    def crawl(url, current_depth):
        if current_depth > depth:
            return
        links = get_links(url)
        site_map[url] = links
        for link in links:
            if link not in site_map:
                crawl(link, current_depth + 1)
    crawl(url, 0)
    return site_map

def check_subdomains(domain):
    subdomains = [
        "www", "mail", "ftp", "api", "blog", "dev", "shop", "test", "admin", "portal",
        "support", "secure", "status", "dashboard", "login", "cpanel", "webmail", "billing",
        "cdn", "static", "news", "forum", "cloud", "data", "smtp", "vpn", "sql", "database",
        "monitoring", "tracking", "ads", "payments", "checkout", "hr", "payroll", "security",
        "uploads", "downloads", "media", "docs", "reports", "json", "xml", "docker", "kubernetes",
        "cloud-storage", "aws", "azure", "gcp", "digitalocean", "vultr", "cloudflare"
    ]

    print(f"\n🔍 Checking subdomains for {domain}...\n")
    found_subdomains = []

    for sub in subdomains:
        full_domain = f"{sub}.{domain}"


        try:
            ip_addresses = dns.resolver.resolve(full_domain, "A")
            ip_list = [ip.to_text() for ip in ip_addresses]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except Exception as e:
            print(f"❌ Error resolving {full_domain}: {e}")
            continue

        try:
            response = requests.get(f"https://{full_domain}", timeout=5)
            status_code = response.status_code
            soup = BeautifulSoup(response.content, "html.parser")
            title = soup.title.string if soup.title else "No Title Found"
        except requests.exceptions.RequestException:
            status_code, title = "N/A", "Request Failed"

        found_subdomains.append({
            "subdomain": full_domain,
            "ips": ip_list,
            "http_status": status_code,
            "title": title
        })

    if found_subdomains:
        print("✅ Discovered Subdomains:\n")
        for entry in found_subdomains:
            print(f"{entry['subdomain']} → {', '.join(entry['ips'])} | Status: {entry['http_status']} | Title: {entry['title']}")
    else:
        print("🚫 No subdomains found!")

    return found_subdomains
def get_dns_info(domain):
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        print("\nName Servers:")
        for ns in ns_records:
            print("\t", ns.to_text())
    except Exception as e:
        print("\nDNS query failed for domain:", domain)
        print("Error:", e)

def get_http_status_and_title(url):#3
    try:
        response = requests.get(url, timeout=5)
        status_code = response.status_code
        soup = BeautifulSoup(response.content, "html.parser")
        title = soup.title.string if soup.title else "No Title Found"
        print(f"\nURL: {url}")
        print(f"Status Code: {status_code}")
        print(f"Title: {title}\n")
    except requests.exceptions.RequestException as e:
        print(f"\nFailed to process {url}: {e}\n")

def get_ip_address(domain):#4
    try:
        ip_address = socket.gethostbyname(domain)
        print(f"\nIP Address of {domain}: {ip_address}")
        return ip_address
    except Exception as e:
        print(f"\nFailed to retrieve IP for {domain}: {e}")
        return None

def scan_ports(ip):#5
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments="-Pn -p 1-1000 -sV -T5")

        ports_info = []
        for host in nm.all_hosts():
            for port in nm[host]["tcp"]:
                state = nm[host]["tcp"][port]["state"]
                service = nm[host]["tcp"][port]["name"]
                version = nm[host]["tcp"][port].get("version", "Unknown")
                ports_info.append(f"Port {port} → {state} | Service: {service} | Version: {version}")

        result = "\n".join(ports_info) if ports_info else "❌ No open ports found"

        print(f"\n🔹 Port Scan Results for {ip}:\n{result}\n")

        file_path = os.path.join(os.path.expanduser("~"), "Desktop", "yaghoooti.txt")
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(f"🔹 Port Scan Results for {ip}:\n{result}\n")
            f.write("-"*60 + "\n\n")

        print(f"✅ Port scan data saved to {file_path}")

    except Exception as e:
        error_msg = f"❌ Port scanning failed: {e}"
        print(error_msg)

        file_path = os.path.join(os.path.expanduser("~"), "Desktop", "yaghoooti.txt")
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(error_msg + "\n")

        print(f"✅ Error info saved to {file_path}")


def get_server_location(ip):
    """ دریافت موقعیت جغرافیایی براساس IP """
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        data = response.json()
        location = f"{data.get('city', 'Unknown')}, {data.get('region', 'Unknown')}"
        return location
    except Exception:
        return "❌ Location not found"

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        ip_address = get_ip_address(domain)
        server_location = get_server_location(ip_address) if ip_address else "Unknown"

        whois_data = f"""
🔹 WHOIS Information for {domain}:
--------------------------------------------------
🌍 Domain Registrar: {w.registrar}
🔹 WHOIS Server: {w.whois_server}
📅 Creation Date: {w.creation_date}
⏳ Expiration Date: {w.expiration_date}
🔄 Last Updated: {w.last_updated}
🔧 Name Servers: {', '.join(w.name_servers) if w.name_servers else 'Not Available'}
👤 Registrant Name: {w.name if w.name else 'Not Available'}
🏢 Organization: {w.org if w.org else 'Not Available'}
📍 Server Location: {server_location}
--------------------------------------------------
"""
        print(whois_data)
        file_path = os.path.join(os.path.expanduser("~"), "Desktop", "yaghoooti.txt")
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(whois_data + "\n")

        print(f"✅ WHOIS data saved to {file_path}")

    except Exception as e:
        error_msg = f"❌ Failed to retrieve WHOIS data: {e}"
        print(error_msg)

        file_path = os.path.join(os.path.expanduser("~"), "Desktop", "yaghoooti.txt")
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(error_msg + "\n")

        print(f"✅ Error info saved to {file_path}")

def extract_email_and_phone_from_web(url):#6 regex
    """Extracts email and phone numbers from the given web page."""
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        text = soup.get_text()

        email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        phone_pattern = r"\b(?:\+98|0)?\d{2,4}[-.]?\d{3,4}[-.]?\d{3,4}\b"

        emails = re.findall(email_pattern, text)
        phones = re.findall(phone_pattern, text)

        return {
            "emails": list(set(emails)),
            "phones": list(set(phones))
        }

    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch the website: {e}")
        return {"emails": [], "phones": []}



def generate_report(domain):
    file_path = os.path.join(os.path.expanduser("~"), "Desktop", "yaghoooti.txt")

    with open(file_path, "w", encoding="utf-8") as f:
        f.write("="*60 + "\n")
        f.write(f"📄 REPORT FOR {domain}\n")
        f.write("="*60 + "\n\n")

        f.write("🔹 LIST OF URLS:\n")
        urls = get_links(f"https://{domain}")
        for url in urls:
            f.write(f"{url}\n")
        f.write("-"*60 + "\n\n")

        subdomains = check_subdomains(domain)
        if not subdomains:
            f.write("❌ No subdomains found!\n")
        else:
            f.write("🔹 SUBDOMAINS WITH HTTP STATUS & TITLE:\n")
            for entry in subdomains:
                f.write(f"{entry['subdomain']} | Status: {entry['http_status']} | Title: {entry['title']}\n")
        f.write("-"*60 + "\n\n")

        if subdomains:
            f.write("🔹 SUBDOMAINS WITH IPS:\n")
            for entry in subdomains:
                f.write(f"{entry['subdomain']} → {', '.join(entry['ips'])}\n")
        else:
            f.write("❌ No subdomains with IPs found!\n")
        f.write("-"*60 + "\n\n")



        f.write("🔹 EXTRACTED EMAILS & PHONE NUMBERS:\n")
        contacts = extract_email_and_phone_from_web(f"https://{domain}")
        f.write(f"Emails: {', '.join(contacts['emails'])}\n")
        f.write(f"Phones: {', '.join(contacts['phones'])}\n")
        f.write("-"*60 + "\n\n")

    print(f"✅  saved to {file_path}")


def menu():
    while True:
        print("\nChoose an operation:")
        print("1. Extract links from website")
        print("2. Crawl website pages | site map")
        print("3. Get DNS info")
        print("4. Check HTTP status and page title")
        print("5. Get IP address of the domain")
        print("6. Scan ports of the server")
        print("7. Get WHOIS info & server location")
        print("8. Exit")
        print("9. Check subdomains")
        print("10.Extract email & phone from website")
        print("11.all in txt  | (full) | ")

        while True:
            choice = input("Enter your choice (1-9): ")
            if choice.isdigit() and 1 <= int(choice) <= 11:
                break
            else:
                print("Invalid input. Please enter a number between 1 and 9.")
        if choice == "1":
            links = get_links(f"https://{domain}")
            if links:
                print("\nExtracted Links:")
                for link in links:
                    print(link)
            else:
                print("No links found.")
        elif choice == "2":
            site_map = crawl_site(f"https://{domain}", depth=1)
            print("\nSite Map:")
            for page_url, links in site_map.items():
                print(page_url)
                for link in links:
                    print("\t", link)
        elif choice == "3":
            get_dns_info(domain)
        elif choice == "4":
            get_http_status_and_title(f"https://{domain}")
        elif choice == "5":
            get_ip_address(domain)
        elif choice == "6":
            ip_address = get_ip_address(domain)
            if ip_address:
                scan_ports(ip_address)
        elif choice == "7":
            get_whois_info(domain)
        elif choice == "8":
            print("Exiting program...")
            break
        elif choice == "9":
            check_subdomains(domain)
        elif choice == "10":
            url = f"https://{domain}"
            result = extract_email_and_phone_from_web(url)
            print("\nExtracted Emails:", result["emails"])
            print("Extracted Phones:", result["phones"])
        elif choice == "11":
             generate_report(domain)
menu()
