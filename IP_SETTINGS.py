import psutil
import socket
import webbrowser
import os
from scapy.all import ARP, Ether, srp
from PySide6.QtCore import (QCoreApplication, QDate, QDateTime, QLocale,
    QMetaObject, QObject, QPoint, QRect,
    QSize, QTime, QUrl, Qt)
from PySide6.QtGui import (QBrush, QColor, QConicalGradient, QCursor,
    QFont, QFontDatabase, QGradient, QIcon,
    QImage, QKeySequence, QLinearGradient, QPainter,
    QPalette, QPixmap, QRadialGradient, QTransform)
from PySide6.QtWidgets import (QApplication, QGridLayout, QLabel, QLineEdit,
    QListWidget, QListWidgetItem, QMainWindow, QPushButton,
    QSizePolicy, QStatusBar, QWidget)

if os.name == "posix":
    os.system("sudo apt update && sudo apt install libpcap0.8 -y && sudo apt install python3-psutil -y && sudo apt install python3-scapy -y && sudo pip install pyside6 && sudo apt install libxcb-cursor0 -y")

class Ui_IP_SETTINGS(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.local_ips = self.get_local_ip_addresses()
        self.populate_ip_list()
        self.DoneButton.clicked.connect(self.apply_changes)
        self.scanButton.clicked.connect(self.scan_network_ips)
        self.list_ip.itemDoubleClicked.connect(self.open_ip_in_browser)

    def setupUi(self, IP_SETTINGS):
        # Здесь должен быть код генерации интерфейса из вашего UI файла.
        if not IP_SETTINGS.objectName():
            IP_SETTINGS.setObjectName(u"IP_SETTINGS")
        IP_SETTINGS.resize(1025, 375)
        icon = QIcon()
        icon.addFile(u"IP_SETTINGS.ico", QSize(), QIcon.Mode.Normal, QIcon.State.Off)
        IP_SETTINGS.setWindowIcon(icon)
        IP_SETTINGS.setStyleSheet(u"")
        self.centralwidget = QWidget(IP_SETTINGS)
        self.centralwidget.setObjectName(u"centralwidget")
        self.gridLayoutWidget = QWidget(self.centralwidget)
        self.gridLayoutWidget.setObjectName(u"gridLayoutWidget")
        self.gridLayoutWidget.setGeometry(QRect(-2, -1, 321, 351))
        self.gridLayout = QGridLayout(self.gridLayoutWidget)
        self.gridLayout.setObjectName(u"gridLayout")
        self.gridLayout.setContentsMargins(0, 0, 0, 0)
        self.lineEdit = QLineEdit(self.gridLayoutWidget)
        self.lineEdit.setObjectName(u"lineEdit")

        self.gridLayout.addWidget(self.lineEdit, 11, 0, 1, 1)

        self.osnShluseLabel = QLabel(self.gridLayoutWidget)
        self.osnShluseLabel.setObjectName(u"osnShluseLabel")
        self.osnShluseLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.gridLayout.addWidget(self.osnShluseLabel, 12, 0, 1, 1)

        self.IPedit = QLineEdit(self.gridLayoutWidget)
        self.IPedit.setObjectName(u"IPedit")

        self.gridLayout.addWidget(self.IPedit, 4, 0, 1, 1)

        self.aternativeDnsLabel = QLabel(self.gridLayoutWidget)
        self.aternativeDnsLabel.setObjectName(u"aternativeDnsLabel")

        self.gridLayout.addWidget(self.aternativeDnsLabel, 10, 0, 1, 1)

        self.DoneButton = QPushButton(self.gridLayoutWidget)
        self.DoneButton.setObjectName(u"DoneButton")

        self.gridLayout.addWidget(self.DoneButton, 14, 0, 1, 1)

        self.osnShluseEdit = QLineEdit(self.gridLayoutWidget)
        self.osnShluseEdit.setObjectName(u"osnShluseEdit")

        self.gridLayout.addWidget(self.osnShluseEdit, 13, 0, 1, 1)

        self.maskLabel = QLabel(self.gridLayoutWidget)
        self.maskLabel.setObjectName(u"maskLabel")
        self.maskLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.gridLayout.addWidget(self.maskLabel, 6, 0, 1, 1)

        self.osnDnsLabel = QLabel(self.gridLayoutWidget)
        self.osnDnsLabel.setObjectName(u"osnDnsLabel")

        self.gridLayout.addWidget(self.osnDnsLabel, 8, 0, 1, 1)

        self.gatewayEdit = QLineEdit(self.gridLayoutWidget)
        self.gatewayEdit.setObjectName(u"gatewayEdit")

        self.gridLayout.addWidget(self.gatewayEdit, 7, 0, 1, 1)

        self.osnDnsEdit = QLineEdit(self.gridLayoutWidget)
        self.osnDnsEdit.setObjectName(u"osnDnsEdit")

        self.gridLayout.addWidget(self.osnDnsEdit, 9, 0, 1, 1)

        self.changeLabel = QLabel(self.gridLayoutWidget)
        self.changeLabel.setObjectName(u"changeLabel")
        self.changeLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.gridLayout.addWidget(self.changeLabel, 0, 0, 1, 1)

        self.IPlabel = QLabel(self.gridLayoutWidget)
        self.IPlabel.setObjectName(u"IPlabel")

        self.gridLayout.addWidget(self.IPlabel, 3, 0, 1, 1)

        self.list_local_ip = QListWidget(self.centralwidget)
        self.list_local_ip.setObjectName(u"list_local_ip")
        self.list_local_ip.setGeometry(QRect(320, 0, 331, 351))
        self.list_ip = QListWidget(self.centralwidget)
        self.list_ip.setObjectName(u"list_ip")
        self.list_ip.setGeometry(QRect(660, 1, 351, 321))
        self.scanButton = QPushButton(self.centralwidget)
        self.scanButton.setObjectName(u"scanButton")
        self.scanButton.setGeometry(QRect(670, 330, 101, 24))
        self.ip_rangeEdit = QLineEdit(self.centralwidget)
        self.ip_rangeEdit.setObjectName(u"ip_rangeEdit")
        self.ip_rangeEdit.setGeometry(QRect(782, 330, 231, 21))
        IP_SETTINGS.setCentralWidget(self.centralwidget)
        self.statusbar = QStatusBar(IP_SETTINGS)
        self.statusbar.setObjectName(u"statusbar")
        IP_SETTINGS.setStatusBar(self.statusbar)

        self.retranslateUi(IP_SETTINGS)

        QMetaObject.connectSlotsByName(IP_SETTINGS)

    def retranslateUi(self, IP_SETTINGS):
        IP_SETTINGS.setWindowTitle(QCoreApplication.translate("IP_SETTINGS", u"IP_SETTINGS", None))
        self.osnShluseLabel.setText(QCoreApplication.translate("IP_SETTINGS", u"\u0412\u0432\u0435\u0434\u0438\u0442\u0435 \u043e\u0441\u043d\u043e\u0432\u043d\u043e\u0439 \u0448\u043b\u044e\u0437(IP-\u0430\u0434\u0440\u0435\u0441 \u0440\u043e\u0443\u0442\u0435\u0440\u0430)", None))
        self.IPedit.setInputMask("")
        self.aternativeDnsLabel.setText(QCoreApplication.translate("IP_SETTINGS", u"\u0412\u0432\u0435\u0434\u0438\u0442\u0435 \u0430\u043b\u044c\u0442\u0435\u0440\u043d\u0430\u0442\u0438\u0432\u043d\u044b\u0439 \u0434\u043d\u0441 \u0441\u0435\u0440\u0432\u0435\u0440", None))
        self.DoneButton.setText(QCoreApplication.translate("IP_SETTINGS", u"\u0413\u043e\u0442\u043e\u0432\u043e", None))
        self.maskLabel.setText(QCoreApplication.translate("IP_SETTINGS", u"\u0412\u0432\u0435\u0434\u0438\u0442\u0435 \u043d\u043e\u0432\u0443\u044e \u043c\u0430\u0441\u043a\u0443 \u043f\u043e\u0434\u0441\u0435\u0442\u0438 \u0441\u0435\u0442\u0438", None))
        self.osnDnsLabel.setText(QCoreApplication.translate("IP_SETTINGS", u"\u0412\u0432\u0435\u0434\u0438\u0442\u0435 \u043d\u043e\u0432\u044b\u0439 \u0434\u043d\u0441 \u0441\u0435\u0440\u0432\u0435\u0440", None))
        self.changeLabel.setText(QCoreApplication.translate("IP_SETTINGS", u"\u0418\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435 \u0441\u0435\u0442\u0435\u0432\u044b\u0445 \u043d\u0430\u0441\u0442\u0440\u043e\u0435\u043a \u043a\u043e\u043c\u043f\u044c\u044e\u0442\u0435\u0440\u0430", None))
        self.IPlabel.setText(QCoreApplication.translate("IP_SETTINGS", u"\u0412\u0432\u0435\u0434\u0438\u0442\u0435 \u043d\u043e\u0432\u044b\u0439 IP-\u0430\u0434\u0440\u0435\u0441", None))
        self.scanButton.setText(QCoreApplication.translate("IP_SETTINGS", u"\u0421\u043a\u0430\u043d\u0438\u0440\u043e\u0432\u0430\u0442\u044c", None))

    def get_local_ip_addresses(self):
        ip_addresses = []
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    ip_addresses.append((interface, addr.address))
        return ip_addresses

    def populate_ip_list(self):
        for idx, (interface, ip) in enumerate(self.local_ips, start=1):
            list_item = QListWidgetItem(f"{ip} ({interface})")
            self.list_local_ip.addItem(list_item)

    def open_ip_in_browser(self, item):
        ip_index = self.list_ip.row(item)
        devices = self.scan_network_ips()  # Получаем обновленный список устройств
        if 0 <= ip_index < len(devices):
            ip_address = devices[ip_index][0]
            webbrowser.open(f"http://{ip_address}")

    def apply_changes(self):
        selected_item = self.list_local_ip.currentItem()
        if selected_item:
            ip_index = self.list_local_ip.row(selected_item)
            interface, old_ip = self.local_ips[ip_index]
            new_ip = self.IPedit.text()
            netmask = self.gatewayEdit.text()
            gateway = self.osnShluseEdit.text()
            dns_server = self.osnDnsEdit.text()
            alternate_dns = self.lineEdit.text()
            self.change_ip(interface, old_ip, new_ip, netmask, gateway, dns_server, alternate_dns)
            self.local_ips = self.get_local_ip_addresses()
            self.list_local_ip.clear()
            self.populate_ip_list()

    def change_ip(self, interface, old_ip, new_ip, netmask, gateway, dns_server, alternate_dns):
        if os.name == 'nt':  # Windows
            os.system(f'netsh interface ip set address name="{interface}" static {new_ip} {netmask} {gateway} 1')
            os.system(f'netsh interface ip set dns name="{interface}" static {dns_server} primary')
            os.system(f'netsh interface ip add dns name="{interface}" {alternate_dns} index=2')
        else:  # Unix-based systems
            os.system(f'sudo ifconfig {interface} {new_ip} netmask {netmask}')
            os.system(f'sudo route add default gw {gateway}')
            os.system(f'echo "nameserver {dns_server}" | sudo tee /etc/resolv.conf > /dev/null')
            os.system(f'echo "nameserver {alternate_dns}" | sudo tee -a /etc/resolv.conf > /dev/null')
        print(f'IP-адрес интерфейса {interface} изменён с {old_ip} на {new_ip}')

    def scan_network_ips(self):
        ip_range = self.ip_rangeEdit.text()
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=3, verbose=0)[0]
        self.list_ip.clear()  # Очистить список перед добавлением новых элементов
        devices = []
        for sent, received in result:
            # Создание строки с информацией об устройстве
            device_info = f"IP: {received.psrc} - MAC: {received.hwsrc}"
            # Добавление устройства в список
            devices.append((received.psrc, received.hwsrc))
            # Добавление информации об устройстве в QListWidget
            list_item_scan = QListWidgetItem(device_info)
            self.list_ip.addItem(list_item_scan)
        return devices

if __name__ == "__main__":
    app = QApplication([])
    window = Ui_IP_SETTINGS()
    window.show()
    app.exec()
