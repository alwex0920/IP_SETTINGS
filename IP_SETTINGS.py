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
from PySide6.QtWidgets import (QApplication, QComboBox, QGridLayout, QLabel,
    QLineEdit, QListWidget, QListWidgetItem, QMainWindow,
    QPushButton, QSizePolicy, QStatusBar, QWidget)

class Ui_IP_SETTINGS(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.local_ips = self.get_local_ip_addresses()
        self.populate_ip_list()
        self.DoneButton.clicked.connect(self.apply_changes)
        self.list_local_ip.itemDoubleClicked.connect(self.open_ip_in_browser)

    def setupUi(self, IP_SETTINGS):
        # Здесь должен быть код генерации интерфейса из вашего UI файла.
        if not IP_SETTINGS.objectName():
            IP_SETTINGS.setObjectName(u"IP_SETTINGS")
        IP_SETTINGS.resize(442, 374)
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
        self.DoneButton = QPushButton(self.gridLayoutWidget)
        self.DoneButton.setObjectName(u"DoneButton")

        self.gridLayout.addWidget(self.DoneButton, 15, 0, 1, 1)

        self.netmaskEdit = QLineEdit(self.gridLayoutWidget)
        self.netmaskEdit.setObjectName(u"netmaskEdit")

        self.gridLayout.addWidget(self.netmaskEdit, 8, 0, 1, 1)

        self.osnShluseEdit = QLineEdit(self.gridLayoutWidget)
        self.osnShluseEdit.setObjectName(u"osnShluseEdit")

        self.gridLayout.addWidget(self.osnShluseEdit, 14, 0, 1, 1)

        self.IPedit = QLineEdit(self.gridLayoutWidget)
        self.IPedit.setObjectName(u"IPedit")

        self.gridLayout.addWidget(self.IPedit, 5, 0, 1, 1)

        self.comboBox = QComboBox(self.gridLayoutWidget)
        self.comboBox.setObjectName(u"comboBox")

        self.gridLayout.addWidget(self.comboBox, 3, 0, 1, 1)

        self.osnDnsLabel = QLabel(self.gridLayoutWidget)
        self.osnDnsLabel.setObjectName(u"osnDnsLabel")

        self.gridLayout.addWidget(self.osnDnsLabel, 9, 0, 1, 1)

        self.IPlabel = QLabel(self.gridLayoutWidget)
        self.IPlabel.setObjectName(u"IPlabel")

        self.gridLayout.addWidget(self.IPlabel, 4, 0, 1, 1)

        self.osnShluseLabel = QLabel(self.gridLayoutWidget)
        self.osnShluseLabel.setObjectName(u"osnShluseLabel")
        self.osnShluseLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.gridLayout.addWidget(self.osnShluseLabel, 13, 0, 1, 1)

        self.osnDnsEdit = QLineEdit(self.gridLayoutWidget)
        self.osnDnsEdit.setObjectName(u"osnDnsEdit")

        self.gridLayout.addWidget(self.osnDnsEdit, 10, 0, 1, 1)

        self.maskLabel = QLabel(self.gridLayoutWidget)
        self.maskLabel.setObjectName(u"maskLabel")
        self.maskLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.gridLayout.addWidget(self.maskLabel, 7, 0, 1, 1)

        self.lineEdit = QLineEdit(self.gridLayoutWidget)
        self.lineEdit.setObjectName(u"lineEdit")

        self.gridLayout.addWidget(self.lineEdit, 12, 0, 1, 1)

        self.alternateDnsLabel = QLabel(self.gridLayoutWidget)
        self.alternateDnsLabel.setObjectName(u"'alternateDnsLabel")

        self.gridLayout.addWidget(self.alternateDnsLabel, 11, 0, 1, 1)

        self.changeLabel = QLabel(self.gridLayoutWidget)
        self.changeLabel.setObjectName(u"changeLabel")
        self.changeLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.gridLayout.addWidget(self.changeLabel, 0, 0, 1, 1)

        self.list_local_ip = QListWidget(self.centralwidget)
        self.list_local_ip.setObjectName(u"list_local_ip")
        self.list_local_ip.setGeometry(QRect(320, 0, 121, 351))
        IP_SETTINGS.setCentralWidget(self.centralwidget)
        self.statusbar = QStatusBar(IP_SETTINGS)
        self.statusbar.setObjectName(u"statusbar")
        IP_SETTINGS.setStatusBar(self.statusbar)

        self.retranslateUi(IP_SETTINGS)

        QMetaObject.connectSlotsByName(IP_SETTINGS)

    def retranslateUi(self, IP_SETTINGS):
        IP_SETTINGS.setWindowTitle(QCoreApplication.translate("IP_SETTINGS", u"IP_SETTINGS", None))
        self.DoneButton.setText(QCoreApplication.translate("IP_SETTINGS", u"\u0413\u043e\u0442\u043e\u0432\u043e", None))
        self.IPedit.setInputMask("")
        self.osnDnsLabel.setText(QCoreApplication.translate("IP_SETTINGS", u"\u0412\u0432\u0435\u0434\u0438\u0442\u0435 \u043d\u043e\u0432\u044b\u0439 \u0434\u043d\u0441 \u0441\u0435\u0440\u0432\u0435\u0440", None))
        self.osnShluseLabel.setText(QCoreApplication.translate("IP_SETTINGS", u"\u0412\u0432\u0435\u0434\u0438\u0442\u0435 \u043e\u0441\u043d\u043e\u0432\u043d\u043e\u0439 \u0448\u043b\u044e\u0437(IP-\u0430\u0434\u0440\u0435\u0441 \u0440\u043e\u0443\u0442\u0435\u0440\u0430)", None))
        self.maskLabel.setText(QCoreApplication.translate("IP_SETTINGS", u"\u0412\u0432\u0435\u0434\u0438\u0442\u0435 \u043d\u043e\u0432\u0443\u044e \u043c\u0430\u0441\u043a\u0443 \u043f\u043e\u0434\u0441\u0435\u0442\u0438 \u0441\u0435\u0442\u0438", None))
        self.alternateDnsLabel.setText(QCoreApplication.translate("IP_SETTINGS", u"\u0412\u0432\u0435\u0434\u0438\u0442\u0435 \u0430\u043b\u044c\u0442\u0435\u0440\u043d\u0430\u0442\u0438\u0432\u043d\u044b\u0439 \u0434\u043d\u0441 \u0441\u0435\u0440\u0432\u0435\u0440", None))
        self.changeLabel.setText(QCoreApplication.translate("IP_SETTINGS", u"\u0418\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435 \u0441\u0435\u0442\u0435\u0432\u044b\u0445 \u043d\u0430\u0441\u0442\u0440\u043e\u0435\u043a \u043a\u043e\u043c\u043f\u044c\u044e\u0442\u0435\u0440\u0430", None))
        self.IPlabel.setText(QCoreApplication.translate("IP_SETTINGS", u"\u0412\u0432\u0435\u0434\u0438\u0442\u0435 \u043d\u043e\u0432\u044b\u0439 IP-\u0430\u0434\u0440\u0435\u0441", None))

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
        ip_index = self.list_local_ip.row(item)
        if 0 <= ip_index < len(self.local_ips):
            webbrowser.open(f"http://{self.local_ips[ip_index][1]}")

    def apply_changes(self):
        selected_item = self.list_local_ip.currentItem()
        if selected_item:
            ip_index = self.list_local_ip.row(selected_item)
            interface, old_ip = self.local_ips[ip_index]
            new_ip = self.IPedit.text()
            netmask = self.netmaskEdit.text()
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

    def scan_network(self, ip_range):
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=3, verbose=0)[0]
        devices = []
        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
        return devices

if __name__ == "__main__":
    app = QApplication([])
    window = Ui_IP_SETTINGS()
    window.show()
    app.exec()
