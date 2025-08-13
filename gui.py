import subprocess
from PyQt5.QtWidgets import (
    QMainWindow, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget, QTextEdit, QDialog, QLabel,
    QPushButton, QSizePolicy, QHBoxLayout
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QPixmap, QPainter, QBrush, QIcon, QTextCursor, QFont

class MainWindow(QMainWindow):
    def __init__(self, scanner_thread):
        super().__init__()
        self.setWindowTitle("NET PORTNITES")

        # 아스키 아트
        ascii_art = """
    _   __     __     ____             __        _ __     
   / | / /__  / /_   / __ \____  _____/ /_____  (_) /____ 
  /  |/ / _ \/ __/  / /_/ / __ \/ ___/ __/ __ \/ / __/ _ \\
 / /|  /  __/ /_   / ____/ /_/ / /  / /_/ / / / / /_/  __/
_/ |_/\___/\__/  /_/    \____/_/   \__/_/ /_/_/\\__/\\___/ 
        """
        self.banner_label = QLabel(ascii_art)
        self.banner_label.setFont(QFont("Courier New", 10))
        self.banner_label.setAlignment(Qt.AlignCenter)
        self.banner_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.banner_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        # 로그 영역
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setFixedHeight(200)

        # 트리뷰
        self.tree = QTreeWidget()
        self.tree.setColumnCount(7)
        self.tree.setHeaderLabels([
            "CVE Count", "Port", "Service",
            "CVE ID", "Description", "Published Date",
            "CVSS Mark"
        ])
        widths = [80, 60, 120, 150, 500, 120, 60]
        for i, w in enumerate(widths):
            self.tree.setColumnWidth(i, w)
        for i in range(self.tree.columnCount()):
            self.tree.headerItem().setTextAlignment(i, Qt.AlignCenter)

        # 정렬 버튼
        self.sort_buttons_layout = QHBoxLayout()
        self.btn_sort_pub = QPushButton("Sort by Published")
        self.btn_sort_cvss = QPushButton("Sort by CVSS")
        self.sort_buttons_layout.addWidget(self.btn_sort_pub)
        self.sort_buttons_layout.addWidget(self.btn_sort_cvss)
        self.btn_sort_pub.clicked.connect(self.sort_by_published)
        self.btn_sort_cvss.clicked.connect(self.sort_by_cvss)

        # 하단 새로고침 버튼
        self.btn_refresh = QPushButton("새로고침")
        self.btn_refresh.setFixedHeight(40)
        self.btn_refresh.clicked.connect(self.start_scan)

        # 메인 레이아웃
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.banner_label)
        main_layout.addLayout(self.sort_buttons_layout)
        main_layout.addWidget(self.tree)
        main_layout.addWidget(self.log_area)
        main_layout.addWidget(self.btn_refresh)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        # CVSS 점 컬러
        self.dot_red = self.create_color_dot("red")
        self.dot_orange = self.create_color_dot("orange")
        self.dot_green = self.create_color_dot("green")
        self.dot_none = QPixmap(12, 12)
        self.dot_none.fill(Qt.transparent)

        # 스캐너 쓰레드
        self.scanner_thread = scanner_thread
        self.scanner_thread.log_signal.connect(self.append_log)
        self.scanner_thread.result_signal.connect(self.add_result)
        self.scanner_thread.finished.connect(lambda: self.append_log("✅ [스캔 완료]"))

        # 트리뷰 이벤트
        self.tree.itemActivated.connect(self.on_item_activated)
        self.tree.itemDoubleClicked.connect(self.on_item_activated)
        self.tree.keyPressEvent = self.tree_key_press

        self.start_scan()
        self.showMaximized()

    def create_color_dot(self, color_name, size=12):
        pix = QPixmap(size, size)
        pix.fill(Qt.transparent)
        painter = QPainter(pix)
        painter.setRenderHint(QPainter.Antialiasing)
        brush = QBrush(QColor(color_name))
        painter.setBrush(brush)
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(0, 0, size - 1, size - 1)
        painter.end()
        return pix

    def start_scan(self):
        self.tree.clear()
        self.log_area.clear()
        self.append_log("▶ 스캔 시작")
        self.scanner_thread.start()

    def append_log(self, text):
        cursor = self.log_area.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.log_area.setTextCursor(cursor)
        self.log_area.append(text)
        print(text)

    def add_result(self, data):
        port = str(data["port"])
        service = data["service"]
        cves = data["cves"]  # [(cve_id, info_dict), ...]

        parent = QTreeWidgetItem(self.tree)
        parent.setText(0, f"{len(cves)}개")
        parent.setText(1, port)
        parent.setText(2, service)
        for i in range(3, 7):
            parent.setText(i, "")
        parent.setExpanded(True)

        for cve_id, cve_info in cves:
            child = QTreeWidgetItem(parent)
            child.setText(3, cve_id)
            desc_full = cve_info.get("desc", "").replace('\n', ' ').replace('\r', ' ')
            child.setText(4, desc_full)
            child.setText(5, cve_info.get("pubdatestr", "?"))
            cvss_text = cve_info.get("cvss", "-")
            try:
                score = float(cvss_text)
            except:
                score = -1
            child.setText(6, f"{score:.1f}" if score >= 0 else "-")
            if score >= 7.0:
                dot = self.dot_red
            elif score >= 4.0:
                dot = self.dot_orange
            elif score >= 0:
                dot = self.dot_green
            else:
                dot = self.dot_none
            child.setIcon(6, QIcon(dot))

    # =================== 정렬 기능 ===================
    def sort_by_published(self):
        expanded_ports = self.get_expanded_ports()
        data_list = self.collect_tree_data()
        for d in data_list:
            d["cves"].sort(key=lambda x: x[1].get("pubdatestr", "") or "", reverse=True)
        self.reload_tree(data_list, expanded_ports)

    def sort_by_cvss(self):
        expanded_ports = self.get_expanded_ports()
        data_list = self.collect_tree_data()
        for d in data_list:
            d["cves"].sort(key=lambda x: float(x[1].get("cvss", -1)) if x[1].get("cvss", "-") != "-" else -1, reverse=True)
        self.reload_tree(data_list, expanded_ports)

    def collect_tree_data(self):
        data_list = []
        for i in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(i)
            children_data = []
            for j in range(item.childCount()):
                child = item.child(j)
                children_data.append((
                    child.text(3),  # cve_id
                    {
                        "desc": child.text(4),
                        "pubdatestr": child.text(5),
                        "cvss": child.text(6)
                    }
                ))
            data_list.append({
                "port": item.text(1),
                "service": item.text(2),
                "cves": children_data
            })
        return data_list

    def get_expanded_ports(self):
        expanded = set()
        for i in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(i)
            if item.isExpanded():
                expanded.add(item.text(1))
        return expanded

    def reload_tree(self, data_list, expanded_ports=None):
        self.tree.clear()
        for data in data_list:
            self.add_result(data)
        if expanded_ports:
            for i in range(self.tree.topLevelItemCount()):
                item = self.tree.topLevelItem(i)
                item.setExpanded(item.text(1) in expanded_ports)

    # =================== 트리뷰 이벤트 ===================
    def on_item_activated(self, item, column):
        if item.parent() is not None:
            parent = item.parent()
            port = parent.text(1)
            service = parent.text(2)
            cve_id = item.text(3)
            desc = item.text(4)
            pubdate = item.text(5)
            cvss = item.text(6)
            self.show_cve_detail(service, port, cve_id, desc, pubdate, cvss)

    def tree_key_press(self, event):
        key = event.key()
        selected_items = self.tree.selectedItems()
        if key in (Qt.Key_Return, Qt.Key_Enter):
            for item in selected_items:
                if item.childCount() > 0:
                    item.setExpanded(not item.isExpanded())
                else:
                    self.on_item_activated(item, 0)
        else:
            QTreeWidget.keyPressEvent(self.tree, event)

    # =================== CVE 상세 ===================
    def show_cve_detail(self, service, port, cve_id, desc, pubdate, cvss):
        dialog = QDialog(self)
        dialog.setWindowTitle(f"{service} - CVE 상세 정보")
        layout = QVBoxLayout()
        layout.addWidget(QLabel(f"<b>서비스:</b> {service}"))
        layout.addWidget(QLabel(f"<b>포트:</b> {port}"))
        layout.addWidget(QLabel(f"<b>CVE ID:</b> {cve_id}"))
        layout.addWidget(QLabel(f"<b>Published:</b> {pubdate}"))
        layout.addWidget(QLabel(f"<b>CVSS:</b> {cvss}"))

        desc_text = QTextEdit()
        desc_text.setReadOnly(True)
        desc_text.setPlainText(desc)
        layout.addWidget(desc_text)

        btn_close = QPushButton("닫기")
        btn_close.clicked.connect(dialog.close)
        layout.addWidget(btn_close)

        dialog.setLayout(layout)
        dialog.resize(700, 500)
        dialog.exec_()
