# PY1C4B69317AE2E4
APIk = "L2M0ADYNT5NS21C289H69SH65XAYP2UBHCFS2QH3HW5FHKJ49JM65AX3VIYSZGEG"

import vulners
import nmap
def nmap_scan(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-sV')
    version_info = {}
    for host in nm.all_hosts():
        for port in nm[host]['tcp']:
            if 'product' in nm[host]['tcp'][port] and 'version' in nm[host]['tcp'][port]:
                product = nm[host]['tcp'][port]['product']
                version = nm[host]['tcp'][port]['version']
                version_info[f"{host}:{port}"] = f"{product} {version}"
    print(version_info)
    return version_info

def API_init(API_key, version_info):
    vulners_api = vulners.VulnersApi(api_key=API_key)
    exploits = []
    for info in version_info.values():
        exploits.extend(vulners_api.find_exploit_all(info))
    return exploits

def print_result(exploits_list):
    for exploit in exploits_list:
        print("Exploit ID:", exploit.get("id", ""))
        print("Title:", exploit.get("title", ""))
        print("Description:", exploit.get("description", ""))
        print("Platform:", exploit.get("platform", ""))
        print("Type:", exploit.get("type", ""))
        print("Link:", exploit.get("href", ""))
        print("-" * 30)

target = "google.com"
vs_if = nmap_scan(target)
exploits = API_init(APIk, vs_if)
print_result(exploits)









