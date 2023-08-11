import dns
import dns.resolver
import socket

def ReverseDNS(ip):
    try:
        result = socket.gethostbyaddr(ip)
        return [result[0]] + result[1]      # primary + alter hostnames
    except (socket.herror, socket.gaierror) as e:
        return None

def DNSRequest(domain):
    # ips = []
    try:
        result = dns.resolver.resolve(domain)
        if result:
            print(domain)
            for answer in result:
                print(answer)
                print("Domain Names: %s" % ReverseDNS(answer.to_text()))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return []

def SubdomainSearch(domain, dictionary, nums):
    for word in dictionary:
        subdomain = word + "." + domain
        DNSRequest(subdomain)
        if nums:
            for i in range(0,10):
                s = word + str(i) + "." + domain
                DNSRequest(s)

domain = "facebook.com"
subdomain_file = "subdomains.txt"
dictionary = []
with open(subdomain_file, "r") as f:
    dictionary = f.read().splitlines()
SubdomainSearch(domain, dictionary, False)
