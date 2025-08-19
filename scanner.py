# scanner.py
import socket
import json
import requests
from datetime import datetime
from PyQt5.QtCore import QThread, pyqtSignal

# well_known.json 파일 로드 (같은 경로에 위치시킬 것)
with open("well_known.json", "r", encoding="utf-8") as f:
    WELLKNOWN_PORTS = json.load(f)

NVD_API_KEY = "f12241dd-84c8-4490-818c-11d5c2d55fa9"  # 필요 시 API키 입력


class ScannerThread(QThread):
    log_signal = pyqtSignal(str)
    result_signal = pyqtSignal(dict)

    def run(self):
        open_ports = self.scan_ports()
        for entry in open_ports:
            port = entry["port"]
            service = entry["service"]
            if service.lower() == "unknown":
                self.log_signal.emit(f"[SKIP] 포트 {port} 서비스명이 unknown이므로 NVD 검색 제외")
                cves = []
            else:
                cves = self.search_nvd(port, service)
            result = {
                "port": port,
                "service": service,
                "cves": cves
            }
            self.result_signal.emit(result)

        self.log_signal.emit("[완료] 스캔 및 NVD 조회 완료.")

    def scan_ports(self):
        open_ports = []
        self.log_signal.emit("🔍 포트 스캔 시작 (1~65535)...")
        for port in range(1, 65536):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    if s.connect_ex(("127.0.0.1", port)) == 0:
                        service = WELLKNOWN_PORTS.get(str(port), "unknown")
                        open_ports.append({"port": port, "service": service})
                        self.log_signal.emit(f"✅ 열린 포트 발견: {port} ({service})")
            except Exception as e:
                self.log_signal.emit(f"⚠ 포트 스캔 에러: {port} - {e}")
        self.log_signal.emit(f"🔎 총 열린 포트 수: {len(open_ports)}")
        return open_ports

    def search_nvd(self, port, service):
        keywords = [
            f"{port} {service}",
            service
        ]

        found_cves = {}
        headers = {}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY

        for query in keywords:
            query = query.strip()
            if not query:
                continue
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}"
            self.log_signal.emit(f"[INFO] NVD 검색 요청: {query}")
            try:
                res = requests.get(url, headers=headers, timeout=10)
                if res.status_code == 200:
                    data = res.json()
                    cve_items = data.get("vulnerabilities", [])
                    for item in cve_items:
                        cve_data = item.get("cve", {})
                        cve_id = cve_data.get("id")
                        if not cve_id or cve_id in found_cves:
                            continue

                        desc = ""
                        for d in cve_data.get("descriptions", []):
                            if d.get("value"):
                                desc = d["value"]
                                break

                        pub_date = cve_data.get("published", "") or cve_data.get("publishedDate", "")
                        try:
                            pub_dt = datetime.fromisoformat(pub_date.replace("Z", "+00:00"))
                        except Exception:
                            pub_dt = None

                        cvss_score = "-"
                        metrics = cve_data.get("metrics", {})
                        for key in ["cvssMetricV30", "cvssMetricV31"]:
                            if key in metrics:
                                metric_list = metrics[key]
                                if isinstance(metric_list, list) and metric_list:
                                    base_score = metric_list[0].get("cvssData", {}).get("baseScore")
                                    if base_score is not None:
                                        cvss_score = f"{base_score:.1f}"
                                        break

                        found_cves[cve_id] = {
                            "desc": desc,
                            "pubdate": pub_dt,
                            "pubdatestr": pub_date,
                            "cvss": cvss_score
                        }
                    if cve_items:
                        self.log_signal.emit(f"[FOUND] {query} → {len(cve_items)}건")
                    else:
                        self.log_signal.emit(f"[INFO] {query} → CVE 없음")
                else:
                    self.log_signal.emit(f"[ERROR] NVD 요청 실패 ({res.status_code}) for query '{query}'")
            except Exception as e:
                self.log_signal.emit(f"[ERROR] 요청 중 오류: {e} for query '{query}'")

        cve_list = list(found_cves.items())
        cve_list.sort(key=lambda x: (x[1]["pubdate"] or datetime.min), reverse=True)
        return cve_list
