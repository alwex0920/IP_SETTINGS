import psutil
import socket
import webbrowser
import os
from scapy.all import ARP, Ether, srp

print("IP_SETTINGS by Alwex Developer")
print("v0.0.1")
print("help - показ команд; list - просканирование и вывод айпи в сети; open - открытие айпи в браузере; change - изменение айпи; scan - сканирование подключенных устройств; exit - выйти")

def get_local_ip_addresses():
    ip_addresses = []
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                ip_addresses.append((interface, addr.address))
    return ip_addresses

def scan_network(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

local_ips = get_local_ip_addresses()

def choose_and_open_url(ip_list):
    choice = int(input("Выберите номер IP для открытия: ")) - 1

    if 0 <= choice < len(ip_list):
        webbrowser.open(f"http://{ip_list[choice][1]}")
    else:
        print("Неверный выбор. Пожалуйста, попробуйте снова.")

def change_ip(interface, old_ip, new_ip, netmask, gateway, dns_server, alternate_dns):
    if os.name == 'nt':  # Windows
        os.system(f'netsh interface ip set address name="{interface}" static {new_ip} {netmask} {gateway} 1')
        os.system(f'netsh interface ip set dns name="{interface}" static {dns_server} primary')
        os.system(f'netsh interface ip add dns name="{interface}" {alternate_dns} index=2')
    else:  # Unix-based systems
        os.system(f'sudo ifconfig {interface} {new_ip} netmask {netmask}')
        os.system(f'sudo route add default gw {gateway}')
        os.system(f'echo "nameserver {dns_server}" | sudo tee /etc/resolv.conf > /dev/null')
        os.system(f'echo "nameserver {alternate_dns}" | sudo tee -a /etc/resolv.conf > /dev/null')
    print(f'IP-адрес интерфейса {interface} изменён с {old_ip} на {new_ip} с маской подсети {netmask}, основным шлюзом {gateway}, DNS-сервером {dns_server} и альтернативным DNS-сервером {alternate_dns}')

while True:
    command = input(">>>").lower()
    if command == "list":
        for idx, (interface, ip) in enumerate(local_ips, start=1):
            print(f"{idx}. {ip} ({interface})")
    elif command == "open":
        choose_and_open_url(local_ips)
    elif command == "change":
        choice = int(input("Выберите номер IP для изменения: ")) - 1
        if 0 <= choice < len(local_ips):
            old_ip = local_ips[choice][1]
            interface = local_ips[choice][0]
            new_ip = input("Введите новый IP: ")
            netmask = input("Введите новую маску подсети: ")
            gateway = input("Введите основной шлюз: ")
            dns_server = input("Введите новый DNS сервер: ")
            alternate_dns = input("Введите альтернативный DNS сервер: ")
            change_ip(interface, old_ip, new_ip, netmask, gateway, dns_server, alternate_dns)
            local_ips = get_local_ip_addresses()
        else:
            print("Неверный выбор. Пожалуйста, попробуйте снова.")
    elif command == "scan":
        ip_range = input("Введите диапазон IP для сканирования (например, 192.168.1.0/24): ")
        devices = scan_network(ip_range)
        if devices:
            print("Найденные устройства в сети:")
            for device in devices:
                print(f"IP: {device['ip']}, MAC: {device['mac']}")
        else:
            print("Устройства не найдены.")
    elif command == "help":
        print("help - показ команд; list - просканирование и вывод айпи в сети; open - открытие айпи в браузере; change - изменение айпи; scan - сканирование подключенных устройств; exit - выйти")
    elif command == "exit":
        break
    else:
        print("Неизвестная команда. Попробуйте снова.")
