import os
import sys
import pandas as pd
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QTableWidget, QTableWidgetItem, QLabel, QHBoxLayout, QMessageBox, QProgressBar
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QPushButton
from PyQt5.QtWidgets import QInputDialog,QSplitter
from PyQt5.QtCore import QTimer,Qt
from PyQt5.QtChart import QPieSeries, QChart, QChartView
from PyQt5.QtCore import pyqtSignal, QObject
import threading
from datetime import datetime, timedelta
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import matplotlib.pyplot as plt
import subprocess
import socket
import numpy as np
import time


def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
        
    return os.path.join(base_path, relative_path)

        ##############
        ## 차단 리스트 ##
        ##############

class IPListDialog(QDialog):
    def __init__(self, ip_list, parent=None):
        super().__init__(parent)
        self.setWindowTitle('차단된 IP 목록')
        
        # 창 크기 설정
        self.setGeometry(1000, 100, 400, 400) # x, y, width, height
        
        # IP 목록을 표시할 QTextEdit 위젯 생성 및 설정
        self.ip_text_edit = QTextEdit()
        self.ip_text_edit.setPlainText(ip_list)
        self.ip_text_edit.setReadOnly(True)
        
        # 레이아웃 설정
        layout = QVBoxLayout()
        
        # IP 추가 버튼 생성 및 이벤트 연결 위치 설정
        self.btn_add = QPushButton('IP 추가', self)
        self.btn_add.clicked.connect(self.add_ip)
        layout.addWidget(self.btn_add)
        
        self.btn_remove = QPushButton('IP 해제', self)
        self.btn_remove.clicked.connect(self.remove_ip)
        layout.addWidget(self.btn_remove)
        
        self.btn_remove_all = QPushButton('모두 해제', self)
        self.btn_remove_all.clicked.connect(self.remove_all)
        layout.addWidget(self.btn_remove_all)

        # QTextEdit 위젯을 레이아웃에 추가
        layout.addWidget(self.ip_text_edit)

        # 설정된 레이아웃을 대화 상자에 설정
        self.setLayout(layout)

    def add_ip(self):
        # 입력 다이얼로그 생성
        ip, ok = QInputDialog.getText(self, 'IP 추가', '차단할 IP 주소를 입력하세요.')
        # 확인 버튼을 누르면 IP 주소를 추가
        if ok and ip:  # ip가 비어있지 않은지도 확인
            self.ip_text_edit.append(ip)
            # 차단 규칙 추가
            block_ip(ip)
            self.update_ip_list()

    def remove_ip(self):
        # 입력 다이얼로그 생성
        ip, ok = QInputDialog.getText(self, 'IP 해제', '해제할 IP 주소를 입력하세요.')
        # 확인 버튼을 누르면 IP 주소를 제거
        if ok and ip:  # ip가 비어있지 않은지도 확인
            with open(resource_path('black_list.txt'), 'r') as f:
                ips = f.readlines()
            with open(resource_path('black_list.txt'), 'w') as f:
                # /t로 구분된 IP 주소와 시간을 분리
                ips = [line for line in ips if line.split('\t')[0] != ip]
                f.writelines(ips)
                
            self.update_ip_list()
            # 차단 규칙 제거
            unblock_ip(ip)

    def remove_all(self):
        # 모든 IP 주소를 제거
        with open(resource_path('black_list.txt'), 'w') as f:
            pass  # 파일 내용을 비움
        self.update_ip_list()
        # 모든 차단 규칙 제거
        remove_pf_rule()

    def update_ip_list(self):
        # black_list.txt 파일에서 IP 목록을 읽어와 QTextEdit 위젯에 표시합니다.
        try:
            with open(resource_path('black_list.txt'), 'r') as f:
                ips = f.read().strip()  # 파일 끝의 개행 문자 제거
            self.ip_text_edit.setPlainText(ips)  # IP 목록을 텍스트 에디트에 설정
        except Exception as e:
            QMessageBox.critical(self, '오류', 'IP 목록을 불러오는 동안 오류가 발생했습니다:\n' + str(e))
            
            
        
        ############
        ## 메인 UI ##
        ############
class AlarmSignal(QObject):
    alarm = pyqtSignal(str, str, str)

class PacketCaptureGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.capture_thread = None
        self.is_auto_mode = False  # 초기 모드를 수동으로 설정
        # self.graph_timer = QTimer(self)
        # self.graph_timer.timeout.connect(self.update_graph)
        # self.graph_timer.start(1)
    
        
    def show_popup(self, title, text, ip):
        reply = QMessageBox.question(self, title, text, QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            block_ip(ip)
    

    def init_ui(self):
        # 위젯 설정
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

         # 메인 레이아웃
        self.main_layout = QVBoxLayout(central_widget)

        # 상태 및 정보 레이블 레이아웃
        info_layout = QVBoxLayout()
        self.main_layout.addLayout(info_layout)
        
        # 캡처 상태 레이블
        self.capture_status_label = QLabel('캡처 준비...', self)
        info_layout.addWidget(self.capture_status_label)

        # 전체 패킷 수 레이블
        self.total_packets_label = QLabel('전체 패킷 수: 계산 중...\n', self)
        info_layout.addWidget(self.total_packets_label)
        
        # 공격 유형별 패킷 수 레이블
        self.attack_counts_label = QLabel('공격 유형별 패킷 수: 계산 중... \n', self)
        info_layout.addWidget(self.attack_counts_label)
        
        # 캡처 진행률 표시
        self.capture_progress = QProgressBar(self)
        self.capture_progress.setRange(0, 0)  # 무한 진행률
        self.capture_progress.setVisible(False)  # 초기에 숨김
        self.main_layout.addWidget(self.capture_progress)

        # 버튼 레이아웃
        button_layout = QHBoxLayout()
        info_layout.addLayout(button_layout)
        # 자동 수동 토글 버튼 생성 및 설정
        self.toggle_button = QPushButton("수동", self)
        self.toggle_button.setCheckable(True)
        self.toggle_button.setChecked(False)
        self.toggle_button.toggled.connect(self.toggle_mode)
        button_layout.addWidget(self.toggle_button)
        
        # 우측 상단에 IP리스트 버튼 추가
        self.btn_ip_list = QPushButton('차단 IP 리스트', self)
        self.btn_ip_list.clicked.connect(self.show_ip_list)
        button_layout.addWidget(self.btn_ip_list)

        # 시작 버튼
        self.btn_start = QPushButton('패킷 캡처 시작', self)
        self.btn_start.clicked.connect(self.start_capture_thread)
        button_layout.addWidget(self.btn_start)

        # 중지 버튼
        self.btn_stop = QPushButton('패킷 캡처 중지', self)
        self.btn_stop.clicked.connect(self.stop_capture)
        self.btn_stop.setEnabled(False)  # 초기에 비활성화
        button_layout.addWidget(self.btn_stop)
        
        # # 그래프 초기화
        # self.figure, self.ax = plt.subplots()
        # self.canvas = FigureCanvas(self.figure)
        # self.line, = self.ax.plot([], [], 'r-')
        # self.ax.set_title('Real-time Network Traffic Volume')
        # self.ax.set_xlabel('Time')
        # self.ax.set_ylabel('Source Bytes')
        # self.main_layout.addWidget(self.canvas)

        # 테이블 및 차트
        self.table_widget = QTableWidget(self)
        self.main_layout.addWidget(self.table_widget)
        
        # 수평 스플리터 설정
        splitter = QSplitter(Qt.Horizontal)

        # 차트 뷰 설정
        self.chart_view = QChartView(self)
        self.chart_view.setMinimumSize(400, 300)  # 차트 뷰의 최소 크기 설정
        splitter.addWidget(self.chart_view)  # 차트 뷰를 스플리터에 추가

        # 실시간 패킷 정보 테이블 설정
        # self.packet_table = QTableWidget(self)
        # self.packet_table.setColumnCount(3)
        # self.packet_table.horizontalHeader().setStretchLastSection(True)
        # splitter.addWidget(self.packet_table)  # 패킷 테이블을 스플리터에 추가

        # 스플리터를 메인 레이아웃에 추가
        self.main_layout.addWidget(splitter)
        
        # 팝업창에 알람 띄우기
        self.alarm_timer = QTimer(self)
        self.alarm_timer.timeout.connect(self.update_alarm)
        self.alarm_timer.start(1000)  # 1초마다 알람 업데이트
        
        
        # 타이머 설정
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_table)
        self.timer.start(1000)  # 1초마다 테이블 업데이트

        # 차트 업데이트 타이머
        self.chart_timer = QTimer(self)
        self.chart_timer.timeout.connect(self.update_chart)
        self.chart_timer.start(1000)  # 1초마다 차트 업데이트
        
        # # 실시간 패킷 정보 테이블 업데이트 타이머
        # self.packet_table_timer = QTimer(self)
        # self.packet_table_timer.timeout.connect(self.update_packet_table)
        # self.packet_table_timer.start(100)  # 0.1초마다 패킷 테이블 업데이트
    

        # 윈도우 설정
        self.setGeometry(500, 500, 870, 800) # x, y, width, height
        self.setWindowTitle('패킷 캡처')

        self.show()

    def stop_capture(self):
        from main import stop_packet_capture

        # 패킷 캡처 중지
        stop_packet_capture()
        self.capture_status_label.setText('캡처 정지')
        self.capture_status_label.setStyleSheet("")
        self.capture_progress.setVisible(False)
        self.btn_start.setEnabled(True)
        self.btn_stop.setDisabled(True)

    def start_capture_thread(self):
        from main import start_packet_capture

        # 쓰레드에서 패킷 캡처 시작
        self.capture_status_label.setText('캡처 중...')
        self.capture_status_label.setStyleSheet("background-color: green; color: white;")
        self.capture_progress.setVisible(True)
        self.btn_start.setDisabled(True)
        self.btn_stop.setEnabled(True)
        self.capture_thread = threading.Thread(target=start_packet_capture)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
    # def update_graph(self):
    #     # 파일이 없을 경우 처리
    #     if not os.path.exists('packet_info.csv'):
    #         return
    #     # CSV 파일 로드 및 그래프 데이터 업데이트
    #     data = pd.read_csv('packet_info.csv')
    #     x = np.arange(len(data))
    #     # 10초 동안 들어온 패킷의 소스 바이트 합을 계산합니다.
    #     y = data['src_bytes'].rolling(window=1).sum()

    #     # 그래프 데이터 설정
    #     self.line.set_data(x, y)
    #     self.ax.set_xlim(len(data)-50, len(data))  # X축 범위 조정
    #     self.ax.set_ylim(0, y.max() + 500)  # Y축 범위 조정
    #     self.canvas.draw()
        
    def update_chart(self):
        # 파일이 없을 경우 처리
        if not os.path.exists(resource_path('all_packets_with_predictions.csv')):
            return
        try:
            data = pd.read_csv(resource_path('all_packets_with_predictions.csv'))
            attack_counts = data['predicted_label'].value_counts()

            # 전체 패킷 수를 업데이트합니다.
            self.total_packets_label.setText(f"전체 패킷 수: {len(data)}")
            
            # 공격 유형별 패킷 수를 업데이트합니다.
            attack_details = '\n'.join([f"{attack}: {count}" for attack, count in attack_counts.items()])
            self.attack_counts_label.setText(f"공격 유형별 패킷 수 \n{attack_details}")

            series = QPieSeries()
            total = sum(attack_counts)
            for attack, count in attack_counts.items():
                slice = series.append(f"{attack} ({count})", count)
                # 비율을 계산하고 레이블에 표시합니다.
                percent = 100 * count / total
                slice.setLabel(f"{attack} {percent:.2f}%")
                slice.setLabelVisible(True)

            chart = QChart()
            chart.addSeries(series)
            chart.setTitle('공격 유형별 비율')
            self.chart_view.setChart(chart)
        except Exception as e:
            QMessageBox.critical(self, "오류", "차트를 업데이트하는 동안 오류가 발생했습니다.")
            print(f"Error updating chart: {e}")


    def update_table(self):
        # 파일이 없을 경우 처리
        if not os.path.exists(resource_path('all_packets_with_predictions.csv')):
            return
        try:
            # CSV 파일을 역순으로 읽어옵니다.
            data = pd.read_csv(resource_path('all_packets_with_predictions.csv'))
            data = data.iloc[::-1]  # 데이터를 역순으로 정렬합니다.

            # 테이블에 데이터를 설정합니다.
            self.table_widget.setRowCount(len(data.index))
            self.table_widget.setColumnCount(len(data.columns))
            self.table_widget.setHorizontalHeaderLabels(data.columns)
            
            # 데이터를 테이블에 설정한 후, 첫 번째 열의 넓이를 조정합니다.
            self.table_widget.setColumnWidth(0, 160)
            
            for row in range(len(data.index)):
                for col in range(len(data.columns)):
                    item = QTableWidgetItem(str(data.iloc[row, col]))
                    item.setTextAlignment(Qt.AlignCenter)  # 텍스트를 가운데 정렬합니다.
                    self.table_widget.setItem(row, col, item)
                    
        except Exception as e:
            # 에러가 발생했을 때 처리
            self.text_area.setText(f"파일을 읽는 중 오류가 발생했습니다: {e}")
            
            
    # toggle_mode 함수에 수정 사항을 추가
    def toggle_mode(self, checked):
        if checked:
            self.toggle_button.setText("자동")
            self.is_auto_mode = True
            # "자동 모드로 변경되었습니다." 팝업창을 띄웁니다.
            QMessageBox.information(self, '알람', '자동 모드로 변경되었습니다.')
        else:
            self.toggle_button.setText("수동")
            self.is_auto_mode = False
            # "수동 모드로 변경되었습니다." 팝업창을 띄웁니다.
            QMessageBox.information(self, '알람', '수동 모드로 변경되었습니다.')
            
            
    def update_alarm(self):
        if not os.path.exists(resource_path('all_packets_with_predictions.csv')):
            return
        try:
            data = pd.read_csv(resource_path('all_packets_with_predictions.csv'))
            data['timestamp'] = pd.to_datetime(data['timestamp'])
            time_threshold = datetime.now() - timedelta(seconds=5) 
            recent_data = data[data['timestamp'] >= time_threshold]
            attack_counts = recent_data['predicted_label'].value_counts()
            
            count = 10 # 임계값
            for attack_type in ['DOS', 'PROBE', 'R2L', 'U2R']:
                if attack_counts.get(attack_type, 0) >= count:
                    attacker_ip = recent_data[recent_data['predicted_label'] == attack_type]['src_ip'].values[0]
                    my_ip = get_internal_ip()
                    # my_ip = '192.168.219.155'
                    if attacker_ip == my_ip:
                        attacker_ip = recent_data[recent_data['predicted_label'] == attack_type]['dst_ip'].values[0]
                    
                    # 수동 모드일 때만 팝업창을 띄웁니다.
                    if not self.is_auto_mode:
                        # 블랙리스트와 하이트리스트에 없는 IP 주소만 팝업창을 띄웁니다.
                        if attacker_ip not in open(resource_path('black_list.txt')).read() and attacker_ip not in open(resource_path('white_list.txt')).read():
                            reply = QMessageBox.question(self, '알람', f"{attack_type} 공격이 감지되었습니다. {attacker_ip} IP를 차단하시겠습니까?", QMessageBox.Yes | QMessageBox.No)
                            if reply == QMessageBox.Yes:
                                block_ip(attacker_ip)
                            if reply == QMessageBox.No:
                                # 화이트리스트 오픈
                                with open(resource_path('white_list.txt'), 'r') as f:
                                    current_ips = f.readlines()
                                
                                # 중복된 IP인지 확인하고 중복이 아니면 파일에 IP를 추가합니다.
                                if attacker_ip.strip() not in [ip.strip() for ip in current_ips]:
                                    with open(resource_path('white_list.txt'), 'a') as f:
                                        f.write(f"{attacker_ip}\n")
                                    
                    # 자동 모드일 때는 자동으로 차단합니다.
                    if self.is_auto_mode:
                        if attacker_ip not in open(resource_path('black_list.txt')).read():
                            block_ip(attacker_ip)
                            with open(resource_path('black_list.txt'), 'a') as f:
                                if attacker_ip not in f.read():
                                    f.write(f"{attacker_ip}\n")

        except Exception as e:
            print(f"Error updating alarm: {e}")
            
    def update_packet_table(self):
        # 파일이 없을 경우 처리
        if not os.path.exists(resource_path('packet_info.csv')):
            return
        try:
            data = pd.read_csv(resource_path('packet_info.csv'))
            data = data.iloc[::-1]  # 데이터를 역순으로 정렬합니다.
            data = data[['protocol_type', 'service','flag','src_bytes','dst_bytes']]
            data = data.head(10)  # 최근 10개의 패킷만 표시합니다.

            self.packet_table.setRowCount(len(data.index))
            self.packet_table.setColumnCount(len(data.columns))
            self.packet_table.setHorizontalHeaderLabels(data.columns)
            
            # 컬럼 너비 조정
            self.packet_table.setColumnWidth(0, 80)
            self.packet_table.setColumnWidth(1, 80)
            self.packet_table.setColumnWidth(2, 80)
            self.packet_table.setColumnWidth(3, 80)
            self.packet_table.setColumnWidth(4, 80)

            for row in range(len(data.index)):
                for col in range(len(data.columns)):
                    item = QTableWidgetItem(str(data.iloc[row, col]))
                    item.setTextAlignment(Qt.AlignCenter)  # 텍스트를 가운데 정렬합니다.
                    self.packet_table.setItem(row, col, item)
                    
        except Exception as e:
            print(f"Error updating packet table: {e}")
            
    def show_ip_list(self):
        try:
            with open(resource_path('black_list.txt'), 'r') as f:
                ips = f.readlines()
                ips = [ip.strip() for ip in ips]
                ip_list = '\n'.join(ips)
                
                # IPListDialog 인스턴스 생성
                dialog = IPListDialog(ip_list, parent=self)
                
                # IPListDialog를 모달로 표시
                dialog.exec_()
                
        except Exception as e:
            QMessageBox.critical(self, '오류', 'IP 목록을 불러오는 동안 오류가 발생했습니다.')
            print(f"Error loading IP list: {e}")


def get_internal_ip():
    # socket을 생성합니다. AF_INET는 IPv4 주소 체계를 사용하고, SOCK_DGRAM은 UDP 프로토콜을 사용합니다.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        # 임의의 비접근 가능한 IP 주소와 포트에 UDP 패킷을 보내려고 합니다. 
        # 이 명령은 실제로 데이터를 보내지 않습니다만, OS에 IP 스택을 초기화하도록 요청합니다.
        s.connect(('10.255.255.255', 1))
        
        # connect() 후 getsockname()을 호출하면 소켓에 할당된 로컬 주소를 얻을 수 있습니다.
        # 이 주소는 시스템이 네트워크에 대해 '가장 자신 있는' 내부 IP 주소입니다.
        IP = s.getsockname()[0]
    except Exception:
        # 예외가 발생하면, 로컬호스트 주소를 기본값으로 사용합니다.
        IP = '127.0.0.1'
    finally:
        # 모든 작업이 끝나면 소켓을 닫습니다. 이는 리소스를 해제하고 다른 네트워크 작업에 영향을 주지 않도록 합니다.
        s.close()
    
    # 얻어진 IP 주소를 반환합니다.
    return IP


# IP 차단 함수
def block_ip(ip_address):
    """지정된 IP 주소에 대해 방화벽 규칙을 추가하여 연결을 차단함"""
    try:
        rule1 = f"echo 'block drop in quick from {ip_address} to any' | sudo tee -a /etc/pf.conf"
        rule2 = f"echo 'block drop out quick from any to {ip_address}' | sudo tee -a /etc/pf.conf"

        # shell=True 사용 시 보안 위험이 있으므로, 이 방법을 사용할 때는 주의가 필요
        subprocess.run(rule1, shell=True, check=True, text=True)
        subprocess.run(rule2, shell=True, check=True, text=True)
        
        # 연결 세션 종료
        subprocess.run(["sudo", "pfctl", "-k", ip_address], check=True)  # 타겟 IP와의 모든 연결 종료
        subprocess.run(["sudo", "pfctl", "-k", "0/0", "-k", ip_address], check=True)  # 소스 IP로부터 타겟 IP로의 모든 연결 종료
        
        reload_pf_configuration()

        print(f"IP {ip_address} has been successfully blocked.")

        # 차단된 IP와 시간을 black_list.txt에 기록
        with open(resource_path('black_list.txt'), 'a') as f:
            f.write(f"{ip_address}\t")
            current_time = datetime.now().strftime("%H:%M:%S")
            f.write(f"{current_time}\n")

        # 차단 성공 메시지 1초 띄우기
        app = QApplication.instance()
        if app is None:
            app = QApplication(sys.argv)

        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Information)
        msg_box.setText(f"{ip_address} IP가 차단되었습니다.")
        msg_box.setWindowTitle("알람")
        msg_box.setStandardButtons(QMessageBox.NoButton)
        
        QTimer.singleShot(1000, msg_box.accept)
        msg_box.exec_()        

    except subprocess.CalledProcessError as e:
        print(f"Failed to block IP {ip_address}: {e}")


            
# IP 차단 해제 함수
def unblock_ip(ip_address):
    """지정된 IP 주소에 대한 방화벽 규칙을 제거"""
    try:
        # /etc/pf.conf 파일에서 해당 IP 주소의 규칙을 찾아 제거
        sed_command_in = f"sudo sed -i '' '/block drop in quick from {ip_address} to any/d' /etc/pf.conf"
        sed_command_out = f"sudo sed -i '' '/block drop out quick from any to {ip_address}/d' /etc/pf.conf"
        subprocess.run(sed_command_in, shell=True, check=True)
        subprocess.run(sed_command_out, shell=True, check=True)
        print(f"Rules removed for IP {ip_address} successfully.")
        
        reload_pf_configuration()
        
        # 차단 해제 후 black_list.txt에서 해당 IP 주소 제거
        with open(resource_path('black_list.txt'), 'r') as f:
            ips = f.readlines()
        with open(resource_path('black_list.txt'), 'w') as f:
            ips = [line for line in ips if line.strip() not in ip_address]
            f.writelines(ips)
            
        QMessageBox.information(None, '알람', f"{ip_address} IP 차단이 해제되었습니다.")
            
    except subprocess.CalledProcessError as e:
        print(f"Failed to remove block rules for IPs: {e}")

# IP 차단 초기화 함수
def remove_pf_rule():
    """모든 block 규칙을 /etc/pf.conf 파일에서 제거하고 방화벽 설정을 재로드함"""
    try:
        # /etc/pf.conf에서 'block'으로 시작하는 모든 줄 제거
        sed_command = "sudo sed -i '' '/^block/d' /etc/pf.conf"
        subprocess.run(sed_command, shell=True, check=True)

        # 방화벽 구성 재로드
        reload_pf_configuration()        
        # 모든 규칙 제거 성공 메시지 출력
        print(f"All IP block rules have been successfully removed.")
        # 모든 차단 규칙 제거 성공 메시지 팝업창
        QMessageBox.information(None, '알람', f"모든 IP 차단 규칙이 해제되었습니다.")
    except subprocess.CalledProcessError as e:
        # 규칙 제거 실패 시 오류 메시지 출력
        print(f"Failed to remove block rules: {e}")
        
        
def reload_pf_configuration():
    """방화벽 설정을 재로드하여 변경사항을 적용함"""
    try:
        subprocess.run(['sudo', 'pfctl', '-f', '/etc/pf.conf'], check=True)
        print("PF configuration reloaded successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to reload PF configuration: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = PacketCaptureGUI()
    sys.exit(app.exec_())
