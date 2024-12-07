from scapy.all import sniff
from packet_processing import process_packet
import subprocess
import sys

# 재귀 한도를 증가시킵니다.
sys.setrecursionlimit(2000)

def reload_pf_configuration():
    try:
        # sudo 명령을 실행하기 위해 사용자에게 비밀번호 입력을 요구할 수 있습니다.
        # subprocess.run은 Python 3.5 이상에서 사용 가능합니다.
        subprocess.run(['sudo', 'pfctl', '-f', '/etc/pf.conf'], check=True)
        print("PF configuration reloaded successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to reload PF configuration: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")


packet_info = {  
    
    'duration': [],
    'protocol_type': [],
    'service': [],
    'flag': [],
    'src_bytes': [],
    'dst_bytes': [],
    'land': [],
    'wrong_fragment': [],
    'urgent': [],
    'hot': [],
    'num_failed_logins': [],
    'logged_in': [],
    'num_compromised': [],
    'root_shell': [],
    'su_attempted' : [],
    'num_root': [],
    'num_file_creations': [],
    'num_shells': [],
    "num_access_files": [],
    "num_outbound_cmds": [],
    "is_host_login" : [],
    "is_guest_login": [],
    "count": [],
    "srv_count": [],
    "serror_rate": [],
    "srv_serror_rate" : [],
    "rerror_rate" : [],
    "srv_rerror_rate": [],
    "same_srv_rate" : [],
    "diff_srv_rate": [],
    "srv_diff_host_rate": [],
    "dst_host_count": [],
    "dst_host_srv_count": [],
    "dst_host_same_srv_rate": [],
    "dst_host_diff_srv_rate": [],
    "dst_host_same_src_port_rate": [],
    "dst_host_srv_diff_host_rate": [],
    "dst_host_serror_rate": [],
    "dst_host_srv_serror_rate": [],
    "dst_host_rerror_rate": [],
    "dst_host_srv_rerror_rate": [],
}


# 패킷 캡처를 제어하기 위한 전역 변수
capturing = True

def packet_capture_filter(packet):
    # 패킷 캡처를 멈출 조건을 체크
    if not capturing:
        return True  # True를 반환하면 sniff가 패킷 캡처를 멈춤
    return False


# 전체 패킷 캡처 ##
def start_packet_capture():
    try:
        global capturing
        capturing = True

        # 방화벽 설정을 새로 고침합니다.
        reload_pf_configuration()
        # en0 인터페이스로 들어오는 모든 패킷을 캡처합니다.
        sniff(prn=lambda packet: process_packet(packet, packet_info), stop_filter=packet_capture_filter, filter="ip")
        # sniff(prn=lambda packet: process_packet(packet, packet_info), stop_filter=packet_capture_filter, filter="ip")
    except Exception as e:
        print(e)
        
        
#####################      
## 특정 ip 주소만 캡처 ##
#####################

# def start_packet_capture():
#     try:
#         global capturing
#         capturing = True
#         target_ip = "172.30.1.27"
#         filter_condition = f"ip and (src {target_ip} or dst {target_ip})"
        
#         # 방화벽 설정을 새로 고침합니다.
#         reload_pf_configuration()
        
#         sniff(prn=lambda packet: process_packet(packet, packet_info), stop_filter=packet_capture_filter, filter=filter_condition)
#     except Exception as e:
#         print(e)

def stop_packet_capture():
    global capturing
    # 캡처 상태를 False로 변경하여 패킷 캡처를 중지
    capturing = False


