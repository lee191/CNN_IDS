import csv
from scapy.all import IP, TCP, UDP
from intrusion_detection import *
from model_predictor import predict_model
import pandas as pd
from GUI import resource_path

TCP_FLAGS = {
   0: 'OTH',  # 기타
    1: 'REJ',  # 연결 거부됨
    2: 'RSTO',  # 연결 종료, 리셋됨
    3: 'RSTOS0',  # 연결 종료, 리셋됨
    4: 'RSTR',  # 연결 종료, 리셋됨
    5: 'S0',  # 연결 시도 실패
    6: 'S1',  # 연결 설정됨, 종료되지 않음
    7: 'S2',  # 연결 설정됨, 종료되지 않음
    8: 'S3',  # 연결 설정됨, 종료되지 않음
    9: 'SF',  # 연결 설정되고 완료됨
    10: 'SH'  # 연결 설정되고 종료됨
}

SERVICE_MAP = {
    80: 'http',
    5190: 'aol',
    113: 'auth',
    179: 'bgp',
    530: 'courier',
    105: 'csnet_ns',
    103: 'ctf',
    13: 'daytime',
    9: 'discard',
    53: 'domain',  # 'domain_u'도 동일한 포트이므로 중복됩니다.
    7: 'echo',
    119: 'eco_i',  # 'nnsp', 'nntp'와 포트가 동일합니다.
    121: 'ecr_i',
    520: 'efs',
    512: 'exec',  # 'remote_job'과 동일한 포트입니다.
    79: 'finger',
    21: 'ftp',
    20: 'ftp_data',
    70: 'gopher',
    666: 'harvest',  # 'IRC'와 포트가 동일합니다.
    101: 'hostnames',
    2784: 'http_2784',
    443: 'http_443',
    8001: 'http_8001',
    143: 'imap4',
    6667: 'IRC',
    102: 'iso_tsap',
    543: 'klogin',
    544: 'kshell',
    389: 'ldap',
    87: 'link',
    513: 'login',
    57: 'mtp',
    42: 'name',
    138: 'netbios_dgm',
    137: 'netbios_ns',
    139: 'netbios_ssn',
    15: 'netstat',
    123: 'ntp_u',
    8080: 'other',
    1001: 'pm_dump',
    109: 'pop_2',
    110: 'pop_3',
    515: 'printer',
    49152: 'private',
    1024: 'red_i',
    5: 'rje',
    514: 'shell',
    25: 'smtp',
    118: 'sql_net',
    22: 'ssh',  
    111: 'sunrpc',
    95: 'supdup',
    11: 'systat',
    23: 'telnet',
    69: 'tftp_u',
    37: 'tim_i',  # 'time'과 동일한 포트입니다.
    19: 'urh_i',  # 'urp_i'와 동일한 포트입니다.
    540: 'uucp',
    117: 'uucp_path',
    607: 'vmnet',
    43: 'whois',
    6000: 'X11',
    210: 'Z39_50'
}


def get_protocol_name(proto):
    protocol_names = {
        1: 'icmp',  # 인터넷 제어 메시지 프로토콜, 네트워크 장치 간의 오류 메시지와 운영 정보를 전송
        6: 'tcp',  # 전송 제어 프로토콜, 신뢰할 수 있는 연결 지향 데이터 전송을 제공
        17: 'udp',  # 사용자 데이터그램 프로토콜, 신뢰성보다는 속도를 중시하는 데이터 전송에 사용
        2: 'igmp',  # 인터넷 그룹 관리 프로토콜, 멀티캐스트 그룹 멤버십을 관리
        3: 'ggp',  # 게이트웨이 간 프로토콜, 네트워크 게이트웨이 간 라우팅 정보 교환
        4: 'ip',  # 인터넷 프로토콜, 패킷 스위칭 네트워크에서 데이터를 전송
        5: 'st',  # 인터넷 스트림 프로토콜, 실시간 음성과 비디오 전송 등에 사용되었던 실험적 프로토콜
        8: 'egp',  # 외부 게이트웨이 프로토콜, 서로 다른 인터넷 시스템 간의 라우팅 정보 교환
        9: 'igp',  # 내부 게이트웨이 프로토콜, 동일한 자율 시스템 내 라우팅 정보 교환
        41: 'ipv6',  # 인터넷 프로토콜 버전 6, 더 많은 주소 공간과 보안 기능을 제공
        43: 'ipv6-route',  # IPv6 라우팅 헤더, 경로 선택을 위한 정보 제공
        44: 'ipv6-frag',  # IPv6 단편화 헤더, 대형 패킷을 처리하기 위해 사용
        47: 'gre',  # 일반 라우팅 캡슐화, 다양한 네트워크 프로토콜을 IP 네트워크 내에서 캡슐화
        50: 'esp',  # IPsec 암호화 페이로드, IP 패킷의 페이로드 부분을 암호화하여 보안 통신 제공
        51: 'ah',  # IPsec 인증 헤더, 패킷의 무결성과 출처 인증 제공
        58: 'ipv6-icmp',  # IPv6용 ICMP, IPv6 네트워크에서의 진단 메시지와 오류 보고
        59: 'ipv6-nonxt',  # IPv6 다음 헤더 없음, 다음 헤더 필드가 더 이상 없음을 나타냄
        60: 'ipv6-opts',  # IPv6 옵션 헤더, 선택적 정보 전송
        88: 'eigrp',  # 개선된 내부 게이트웨이 라우팅 프로토콜, Cisco에서 개발한 고급 라우팅 프로토콜
        89: 'ospf',  # 오픈 최단 경로 우선, 내부 게이트웨이 프로토콜 중 하나로 널리 사용됨
        115: 'l2tp',  # 계층 2 터널링 프로토콜, VPN 연결 설정에 사용
        132: 'sctp',  # 스트림 제어 전송 프로토콜, 신뢰성 있고 순서대로 메시지를 전송하는 프로토콜
        # 필요에 따라 추가 프로토콜 번호와 이름
    }
    return protocol_names.get(proto, 'Unknown')

# 저장할 CSV 파일 이름
csv_filename = resource_path("packet_info.csv")
intruded_hosts_filename = resource_path("intruded_hosts.txt") # 침해당한 호스트 정보를 저장할 파일

# 컬럼 이름
COLUMN_NAMES = [
    'duration', 'protocol_type', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot', 'flag',
    'service', 'num_failed_logins', 'login_successful', 'root_shell', 'num_intrusions', 'su_attempted',
    'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'is_host_login', 'is_guest_login',
    'count', 'srv_count', 'num_compromised', 'num_outbound_cmds', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
    'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
]
# 패킷을 저장할 리스트
packets = []
ip_packets = []

#'REJ', 'RSTO', 'RSTOS0', 'RSTR', 'S0', 'S1', 'S2', 'S3', 'SF', 'SH' 구하는 함수
def get_tcp_flags(packet):
   # TCP 레이어가 없는 경우는 분석 대상에서 제외
    if not packet.haslayer(TCP):
        return 'OTH'
    
    tcp_layer = packet[TCP]    
    # 각 상태별 조건 분석
    if tcp_layer.flags & 0x02 and not tcp_layer.flags & 0x10:
        # SYN 패킷만 있고 ACK 응답이 없는 경우
        return 'S0'
    elif tcp_layer.flags & 0x12 == 0x12:
        # SYN-ACK 패킷을 보낸 경우
        return 'S1'
    elif tcp_layer.flags & 0x04 and not tcp_layer.flags & 0x10:
        # RST 패킷만 있는 경우
        return 'RSTR'
    elif tcp_layer.flags & 0x01 and not tcp_layer.flags & 0x10:
        # FIN 패킷만 있는 경우
        return 'SF'
    elif tcp_layer.flags & 0x11 == 0x11:
        # FIN-ACK 패킷을 받은 경우
        return 'SH'
    elif tcp_layer.flags & 0x10 and not tcp_layer.flags & 0x02:
        # ACK 패킷만 있는 경우
        return 'S2'
    elif tcp_layer.flags & 0x11 == 0x11:
        # ACK 패킷과 FIN 패킷이 있는 경우
        return 'S3'
    elif tcp_layer.flags & 0x14 == 0x14:
        # 연결이 거부된 경우 (RST와 ACK 모두 설정)
        return 'REJ'
    elif tcp_layer.flags & 0x04 and tcp_layer.flags & 0x02:
        # RST와 SYN 패킷이 모두 있는 경우
        return 'RSTO'
    elif tcp_layer.flags & 0x04 and not (tcp_layer.flags & 0x02 or tcp_layer.flags & 0x10):
        # RST 패킷을 보내고 SYN 또는 ACK 패킷을 받지 않은 경우
        return 'RSTOS0'
    else:
        return 'OTH'
# 연결 정보를 저장할 딕셔너리 초기화
connections = {}

def process_packet(packet, packet_info):
    try:
        # 캡처된 패킷을 리스트에 추가
        packets.append(packet)
        
        
        # 블랙리스트와 비교하여 같은 IP 주소가 있는지 확인
        if IP in packet:
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
        
        # 패킷에서 추출 가능한 정보를 변수에 저장합니다.
        if IP in packet:
            # 패킷 정보 처리 (예: IP 주소 추출)
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            print(f"IP 패킷 - 출발지: {src_ip}, 목적지: {dst_ip}")
            # 처리된 패킷 정보를 리스트에 추가
            ip_packets.append((src_ip, dst_ip))
            
            
            # 연결 식별자 생성 (소스 IP, 목적지 IP, 소스 포트, 목적지 포트)
            #conn_id = (packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport)
            # if IP in packet and TCP in packet:
            #     # 연결의 시작과 종료 시간 기록
            #     if conn_id not in connections:
            #         connections[conn_id] = {'start': packet.time, 'end': packet.time}
            #     else:
            #         connections[conn_id]['end'] = packet.time
            #     # 연결시간을 계산
            #     for conn_id, times in connections.items():
            #         duration = int(times['end'] - times['start']) 
            # else:
            #     duration = 0
                
            duration = 0
            protocol_type = get_protocol_name(packet[IP].proto)  # 프로토콜 유형을 해당 숫자에 해당하는 영어로 저장
            src_bytes = len(packet[IP])  # 송신 바이트
            dst_bytes = len(packet[IP]) if IP in packet and packet.haslayer(IP) else 0  # 수신 바이트는 모니터링 중인 호스트의 경우 0
            land = 1 if packet[IP].src == packet[IP].dst else 0  # 출발지와 목적지 IP가 같은지 여부
            wrong_fragment = packet[IP].frag  # 잘못된 조각
            urgent = packet[TCP].urgptr if TCP in packet and packet.haslayer(TCP) else 0  # 긴급 플래그
            flag = get_tcp_flags(packet)  # TCP 플래그
            service = SERVICE_MAP.get(packet.dport, 'other')  # 패킷의 목적지 포트에 대한 서비스 매핑
            print("Service:", packet.dport, service)
            # 패킷의 길이를 기준으로 이상 행위를 감지하는 경우
            hot_value = 1 if len(packet) > 1500 else 0  # 패킷 길이가 1500을 초과하면 이상 행위로 간주

            # 데이터를 packet_info에 추가
            packet_info['duration'] = duration
            packet_info['protocol_type'] = protocol_type
            packet_info['src_bytes'] = src_bytes
            packet_info['dst_bytes'] = dst_bytes
            packet_info['land'] = land
            packet_info['wrong_fragment'] = wrong_fragment
            packet_info['urgent'] = urgent
            packet_info['hot'] = hot_value  # 핫 플래그에 이상 행위 여부 추가
            packet_info['flag'] = flag
            packet_info['service'] = service

            # 실패한 로그인 시도를 감지하고 저장합니다.
            packet_info['num_failed_logins'] = detect_failed_logins(packet)  # 로그인 실패 횟수를 가져옴
            # 패킷에서 로그인 성공 여부를 감지하고 저장합니다.
            packet_info['logged_in'] = detect_login_success(packet)
            # 루트 쉘 획득 여부를 추출하고 저장합니다.
            packet_info['root_shell'] = extract_root_shell(packet)
            # su명령어 시도 여부를 감지하고 저장합니다.
            packet_info['su_attempted'] = detect_su_attempt(packet)
            # root 엑세스 시도 수를 저장합니다.
            packet_info['num_root'] = count_root_access_attempts(packet)
            # 파일 생성 시도 수를 저장합니다.
            packet_info['num_file_creations'] = count_file_creation_attempts(packet)
            # 쉘 실행 시도 수를 저장합니다.
            packet_info['num_shells'] = count_shell_execution_attempts(packet)
            # 엑세스 파일 시도 수를 저장합니다.
            packet_info['num_access_files'] = count_file_access_attempts(packet)
            # 호스트 로그인 여부를 저장합니다.
            packet_info['is_host_login'] = detect_host_login(packet)
            # 게스트 로그인 여부를 저장합니다.
            packet_info['is_guest_login'] = detect_guest_login(packet)
            # 이 시점에서 관찰된 패킷 수를 저장합니다.
            packet_info['count'] = packet_callback(packet)
            # 서비스 카운트를 저장합니다.
            packet_info['srv_count'] = count_services(packet)
            # num_compromised 카운트를 저장합니다.
            packet_info['num_compromised'] = count_compromised(packet)
            # 아웃바운드 명령의 수(이 필드는 NSL-KDD 데이터셋에서는 항상 0입니다)
            packet_info['num_outbound_cmds'] = 0
            # SYN 패킷의 오류율을 계산하여 저장합니다.
            packet_info['serror_rate'] = calculate_syn_error_rate(packets)
            # 서비스의 SYN 에러 비율을 계산하여 저장합니다.
            service = packet[IP].dport # 서비스 포트를 가져옴
            packet_info['srv_serror_rate'] = calculate_service_syn_error_rate(packets, service)
            # RST 패킷의 오류율을 계산하여 저장합니다.
            packet_info['rerror_rate'] = calculate_reject_error_rate(packets)
            # 서비스의 REJ 에러 비율을 계산하여 저장합니다.
            packet_info['srv_rerror_rate'] = calculate_service_reject_error_rate(packets, service)
            # 같은 서비스 비율을 계산하여 저장합니다.
            packet_info['same_srv_rate'] = calculate_same_srv_rate(packets, service)
            # 다른 서비스 비율을 계산하여 저장합니다.
            packet_info['diff_srv_rate'] = calculate_diff_srv_rate(packets,service)
            # 다른 호스트 비율을 계산하여 저장합니다.
            packet_info['srv_diff_host_rate'] = calculate_srv_diff_host_rate(packets, service)
            # 목적지 호스트의 카운트를 저장합니다.
            packet_info['dst_host_count'] = calculate_dst_host_count(packets)
            # 목적지 호스트의 서비스 카운트를 저장합니다.
            packet_info['dst_host_srv_count'] = count_dst_host_service_connections(packets, service, packet[IP].dst)
            # 목적지 호스트의 같은 서비스 비율을 저장합니다.
            packet_info['dst_host_same_srv_rate'] = calculate_dst_host_srv_rate(packets, service, packet[IP].dst)
            # 목적지 호스트의 다른 서비스 비율을 저장합니다.
            packet_info['dst_host_diff_srv_rate'] = calculate_dst_host_diff_srv_rate(packets, service, packet[IP].dst)
            # 목적지 호스트의 같은 소스 포트 비율을 저장합니다.
            packet_info['dst_host_same_src_port_rate'] = calculate_dst_host_src_port_rate(packets, service, packet[IP].dst)
            # 목적지 호스트의 다른 서비스 비율을 저장합니다.
            packet_info['dst_host_srv_diff_host_rate'] = calculate_service_diff_host_rate(packets, service)
            # 목적지 호스트의 서비스 에러 비율을 저장합니다.
            packet_info['dst_host_serror_rate'] = calculate_dst_host_syn_error_rate(packets, packet[IP].dst)
            # 목적지 호스트의 서비스 SYN 에러 비율
            packet_info['dst_host_srv_serror_rate'] = calculate_dst_host_service_syn_error_rate(packets, service, packet[IP].dst)
            # 목적지 호스트의 서비스 REJ 에러 비율
            packet_info['dst_host_rerror_rate'] = calculate_dst_host_reject_error_rate(packets, packet[IP].dst)
            # 목적지 호스트의 서비스 REJ 에러 비율
            packet_info['dst_host_srv_rerror_rate'] = calculate_dst_host_service_reject_error_rate(packets, service, packet[IP].dst)
            
            # 패킷 정보를 CSV 파일에 저장
            save_to_csv(csv_filename, packet_info)
                        
    except Exception as e:
        print("Error:", e)
        
    # 모든 패킷과 예측 결과를 저장하는 함수
    def save_all_packet_info_with_prediction(packets, predictions):
        assert len(packets) == len(predictions), "Packets and predictions count must match."
        
        filename = resource_path("all_packets_with_predictions.csv")
        with open(filename, 'a', newline='') as file:
            writer = csv.writer(file)
            
            # 파일이 비어있다면, 헤더를 추가합니다.
            if file.tell() == 0:
                writer.writerow(['timestamp', 'src_ip', 'dst_ip', 'predicted_label', 'probability'])
            
            for packet, prediction in zip(packets, predictions):
                # 패킷에서 시간, 출발지 IP, 목적지 IP 정보를 추출합니다.
                timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # 예측된 레이블과 확률을 추출합니다.
                predicted_label, probability = prediction
                
                # 추출된 정보를 CSV 파일에 기록합니다.
                writer.writerow([timestamp, src_ip, dst_ip, predicted_label, probability])
                    
                    
    # 그룹화할 패킷 수
    count = 100
    # 패킷 정보와 모델의 예측 결과를 기반으로 모든 패킷 정보와 예측 결과를 파일에 저장하는 부분
    if len(packets) >= count:
        # 패킷 정보를 DataFrame으로 변환하는 코드 필요
        packet_info_df = pd.read_csv(csv_filename)
        latest_packets_df = packet_info_df.tail(count)  # 마지막 50개의 패킷 정보 선택
        predictions = predict_model(latest_packets_df)  # 패킷 정보를 모델에 전달하여 예측
        print("Predictions:", predictions)
        save_all_packet_info_with_prediction(packets[-count:], predictions)  # 모든 패킷 정보와 예측 결과 저장
        packets.clear()  # 다음 분석을 위해 패킷 리스트 초기화


# CSV 파일에 데이터를 추가하는 함수
def save_to_csv(filename, data):
    try:
        with open(filename, 'a', newline='') as csvfile:  # 'a' 모드로 열기 (append 모드)
            fieldnames = data.keys() 
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            # 파일이 비어있는 경우 헤더를 쓰기
            if csvfile.tell() == 0:
                writer.writeheader()

            # 데이터를 쓰기
            row = {key: data[key] for key in fieldnames}
            writer.writerow(row)
    except Exception as e:
        print("Error in save_to_csv:", e)
        


