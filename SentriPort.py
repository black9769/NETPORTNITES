# SentriPort.py
import sys
from PyQt5.QtWidgets import QApplication
from scanner import ScannerThread
from gui import MainWindow

def main():
    app = QApplication(sys.argv)

    scanner_thread = ScannerThread()
    window = MainWindow(scanner_thread)
    window.resize(1200, 700)
    window.show()

    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
