import nmap

# nm = nmap.PortScanner()
# base_ip = '192.168.0.'
# list_ip = []
# for i in range(1, 256):
#     list_ip.append(base_ip+str(i))

# for ip in list_ip:
#     print(f'ip: {ip}')
#     nm.scan(hosts=ip, arguments='-sn', sudo=True)
#     if ip in nm.all_hosts() and nm[ip].state() == 'up':
#         print(f"mac: {nm[ip]['addresses']['mac']}")
#     else:
#         print(f'mac: None')

scanner = nmap.PortScanner()
scanner.scan(hosts='192.168.0.1-255', arguments='-sn', sudo=True)

for host in scanner.all_hosts():
        if scanner[host].state() == 'up':
            mac = scanner[host]['addresses'].get('mac')
            ip = scanner[host]['addresses'].get('ipv4')
            print(f'ip: {ip}\nmac: {mac}')