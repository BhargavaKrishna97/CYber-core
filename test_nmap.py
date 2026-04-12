import nmap
scanner = nmap.PortScanner()
scanner.scan("scanme.nmap.org","22-80")

print(scanner.all_hosts())
