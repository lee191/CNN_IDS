from scapy.all import TCP, UDP, IP
from scapy.all import *

packet_info = {
    # 'num_failed_logins': 0,
    # 'login_successful': [],
    'num_intrusions': 0,
    'intruded_hosts': set(),
    # 'root_shell': [],
    'service': {}
    
}

# 로그인 실패를 감지하는 함수
def detect_failed_logins(packet):
    """
    이 함수는 네트워크 패킷에서 로그인 실패를 감지합니다.
    패킷의 Raw 레이어 데이터를 분석하여 특정 로그인 실패 메시지 패턴을 찾습니다.
    발견된 패턴의 수를 반환합니다.
    """
    try:
        # 패킷이 Raw 데이터를 포함하는지 확인
        if packet.haslayer(Raw):
            # Raw 데이터를 문자열로 디코딩
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            
            # 로그인 실패를 나타내는 메시지 패턴 목록
            failed_login_patterns = ["permission denied", "authentication failed", "incorrect password"]
            num_failed_logins = 0  # 로그인 실패 횟수를 저장할 변수 초기화
            
            # 패턴 목록을 순회하며 Raw 데이터 내에 각 패턴이 있는지 검사
            for pattern in failed_login_patterns:
                if pattern in payload.lower():
                    num_failed_logins += 1  # 패턴이 존재하면 로그인 실패 횟수 증가
            
            return num_failed_logins  # 로그인 실패 횟수 반환
    except Exception as e:
        print("Error in detect_failed_logins:", e)  # 오류 발생 시 콘솔에 오류 메시지 출력
    
    return 0  # 예외 발생 또는 로그인 실패가 감지되지 않을 경우 0을 반환

# 패킷에서 로그인 성공 여부를 확인하는 함수
def detect_login_success(packet):
    """
    이 함수는 네트워크 패킷에서 로그인 성공 여부를 확인합니다.
    패킷의 Raw 데이터를 분석하여 특정 로그인 성공 메시지 패턴을 찾습니다.
    발견된 패턴이 있으면 1을 반환하고, 그렇지 않으면 0을 반환합니다.
    """
    try:
        # 패킷의 Raw 데이터를 문자열로 디코딩하여 로그 메시지를 가져옴
        log_message = packet[Raw].load.decode('utf-8', errors='ignore') if packet.haslayer(Raw) else ''
        
        # 로그인 성공을 나타내는 패턴 목록
        success_patterns = ["login successful", "login success", "user logged in", "authentication successful"]
        
        # 각 패턴을 순회하며 로그 메시지에 패턴이 있는지 확인
        for pattern in success_patterns:
            if pattern in log_message.lower():
                return 1  # 로그인 성공 패턴이 발견되면 1을 반환합니다.
        
        return 0  # 모든 패턴에 일치하지 않으면 0을 반환합니다.
        
    except Exception as e:
        print("Error in detect_login_success:", e)
        return False  # 오류가 발생하면 False를 반환합니다.

# 루트 쉘 획득 여부를 추출하는 함수
def extract_root_shell(packet):
    """
    이 함수는 네트워크 패킷에서 루트 쉘 획득 여부를 추출합니다.
    패킷의 Raw 데이터를 분석하여 특정 루트 쉘 획득 메시지 패턴을 찾습니다.
    발견된 패턴이 있으면 1을 반환하고, 그렇지 않으면 0을 반환합니다.
    """
    try:
        # 패킷의 Raw 데이터를 문자열로 디코딩하여 로그 메시지를 가져옴
        if packet.haslayer(Raw):
            # Raw 데이터를 문자열로 디코딩
            log_message = packet[Raw].load.decode('utf-8', errors='ignore')

            # 루트 쉘 획득 패턴
            root_shell_patterns = ["root shell", "uid=0", "euid=0", "suid=0"]
            
            # 각 패턴을 순회하며 로그 메시지에 패턴이 있는지 확인
            for pattern in root_shell_patterns:
                if pattern in log_message:
                    return 1  # 루트 쉘 획득 패턴이 발견되면 1을 반환합니다.

        return 0  # 모든 패턴에 일치하지 않으면 0을 반환합니다.

    except Exception as e:
        print("Error in extract_root_shell:", e)
        return 0  # 오류가 발생하면 0을 반환합니다.

# 'su' 명령어 시도 여부를 감지하는 함수
def detect_su_attempt(packet):
    """
    이 함수는 네트워크 패킷에서 'su' 명령어 시도를 감지합니다.
    패킷의 Raw 데이터를 분석하여 'su' 명령어 시도 패턴을 찾습니다.
    발견된 패턴이 있으면 1을 반환하고, 그렇지 않으면 0을 반환합니다.
    """
    try:
        # 패킷의 Raw 데이터를 문자열로 디코딩하여 로그 메시지를 가져옴
        if packet.haslayer(Raw):
            # Raw 데이터를 문자열로 디코딩
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            
            # 'su' 명령어 시도 패턴
            if " su " in payload:  # 공백으로 둘러싸인 'su'를 검색합니다.
                return 1  # 'su' 명령어 시도가 발견되면 1을 반환합니다.
        
        return 0  # 'su' 명령어 시도가 감지되지 않으면 0을 반환합니다.
    
    # 예외가 발생하면 0을 반환합니다.
    except Exception as e:
        print("Error in detect_su_attempt:", e)
        return 0  # 오류가 발생하면 0을 반환합니다.


# 루트 액세스 시도 횟수를 세는 함수
def count_root_access_attempts(packet):
    """
    이 함수는 네트워크 패킷에서 루트 액세스 시도 횟수를 세어 반환합니다.
    패킷의 Raw 데이터를 분석하여 루트 액세스 시도 패턴을 찾습니다.
    발견된 패턴의 수를 반환합니다.
    """
    try:
        # 루트 액세스 시도 횟수를 저장할 변수 초기화
        root_access_attempts = 0
        # 패킷의 Raw 데이터를 문자열로 디코딩하여 로그 메시지를 가져옴
        if packet.haslayer(Raw):
            # Raw 데이터를 문자열로 디코딩
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            # root 액세스 시도를 나타내는 패턴
            root_access_patterns = ["su root", "su - root", "login: root", "username: root"]
            
            # 대소문자 구분 없이 패턴의 발생 횟수를 카운트
            for pattern in root_access_patterns:
                # 페이로드 안에서 패턴의 발생 횟수를 찾는다
                root_access_attempts += payload.lower().count(pattern.lower())
        return root_access_attempts
    
    # 예외가 발생하면 0을 반환합니다.
    except Exception as e:
        print("Error in count_root_access_attempts:", e)
        return 0  # 오류가 발생하면 0을 반환합니다.

# 파일 생성 시도 횟수를 세는 함수
def count_file_creation_attempts(packet):
    """
    이 함수는 네트워크 패킷에서 파일 생성 시도 횟수를 세어 반환합니다.
    패킷의 Raw 데이터를 분석하여 파일 생성 시도 패턴을 찾습니다.
    발견된 패턴의 수를 반환합니다.
    """
    try:
        # 파일 생성 시도 횟수를 저장할 변수 초기화
        file_creation_attempts = 0
        # 패킷의 Raw 데이터를 문자열로 디코딩하여 로그 메시지를 가져옴
        if packet.haslayer(Raw):
            # Raw 데이터를 문자열로 디코딩
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            # 파일 생성 시도를 나타내는 패턴
            file_creation_patterns = [
                "touch ", "> ", "mkdir ",  # 유닉스/리눅스 명령어
                "echo ", "copy ", "type nul >", "md "  # 윈도우 명령어
            ]
            
            # 대소문자 구분 없이 패턴의 발생 횟수를 카운트
            for pattern in file_creation_patterns:
                # 페이로드 안에서 패턴의 발생 횟수를 찾는다
                file_creation_attempts += payload.lower().count(pattern.lower())
        return file_creation_attempts
    
    # 예외가 발생하면 0을 반환합니다.
    except Exception as e:
        print("Error in count_file_creation_attempts:", e)
        return 0  # 오류가 발생하면 0을 반환합니다.


# 쉘 실행 시도 횟수를 세는 함수
def count_shell_execution_attempts(packet):
    """
    이 함수는 네트워크 패킷에서 쉘 실행 시도 횟수를 세어 반환합니다.
    패킷의 Raw 데이터를 분석하여 쉘 실행 시도 패턴을 찾습니다.
    발견된 패턴의 수를 반환합니다.
    """
    try:
        # 쉘 실행 시도 횟수를 저장할 변수 초기화
        shell_execution_atts = 0
        # 패킷의 Raw 데이터를 문자열로 디코딩하여 로그 메시지를 가져옴
        if packet.haslayer(Raw):
            # Raw 데이터를 문자열로 디코딩
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            # 쉘 실행 시도를 나타내는 패턴
            shell_execution_patterns = [
                "sh ", "bash ", "zsh ", "ksh ", "csh ", "tcsh ", "dash ",  # 유닉스/리눅스 쉘
                "cmd ", "powershell ", "wscript ", "cscript ", "cmd.exe"  # 윈도우 쉘
            ]
            
            # 대소문자 구분 없이 패턴의 발생 횟수를 카운트
            for pattern in shell_execution_patterns:
                # 페이로드 안에서 패턴의 발생 횟수를 찾는다
                shell_execution_atts += payload.lower().count(pattern.lower())
        return shell_execution_atts
    
    # 예외가 발생하면 0을 반환합니다.
    except Exception as e:
        print("Error in count_shell_execution_attempts:", e)
        return 0  # 오류가 발생하면 0을 반환합니다.
    
# 엑세스 파일 시도 수를 세는 함수
def count_file_access_attempts(packet):
    """
    이 함수는 네트워크 패킷에서 파일 엑세스 시도 횟수를 세어 반환합니다.
    패킷의 Raw 데이터를 분석하여 파일 엑세스 시도 패턴을 찾습니다.
    발견된 패턴의 수를 반환합니다.
    """
    try:
        # 파일 엑세스 시도 횟수를 저장할 변수 초기화
        file_access_atts = 0
        # 패킷의 Raw 데이터를 문자열로 디코딩하여 로그 메시지를 가져옴
        if packet.haslayer(Raw):
            # Raw 데이터를 문자열로 디코딩
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            # 파일 엑세스 시도를 나타내는 패턴
            file_access_patterns = [
                "cat ", "more ", "less ", "head ", "tail ", "vi ", "vim ", "nano ", "gedit ", "nano",  # 유닉스/리눅스 명령어
                "cp ", "mv ", "rm ",  # 유닉스/리눅스 파일 조작 명령어
                "notepad ", "wordpad ", "explorer ", "explorer.exe", "notepad.exe", "wordpad.exe", "type", "copy", "move",
                "notepad", "del"  # 윈도우 명령어
            ]
            
            # 대소문자 구분 없이 패턴의 발생 횟수를 카운트
            for pattern in file_access_patterns:
                # 페이로드 안에서 패턴의 발생 횟수를 찾는다
                file_access_atts += payload.lower().count(pattern.lower())
        return file_access_atts
    
    # 예외가 발생하면 0을 반환합니다.
    except Exception as e:
        print("Error in count_file_access_atts:", e)
        return 0  # 오류가 발생하면 0을 반환합니다.


# 외부 명령어 실행 시도 횟수를 세는 함수
def count_command_execution_attempts(packet):
    """
    이 함수는 네트워크 패킷에서 외부 명령어 실행 시도 횟수를 세어 반환합니다.
    패킷의 Raw 데이터를 분석하여 외부 명령어 실행 시도 패턴을 찾습니다.
    발견된 패턴의 수를 반환합니다.
    """
    try:
        # 외부 명령어 실행 시도 횟수를 저장할 변수 초기화
        command_execution_attempts = 0
        # 패킷의 Raw 데이터를 문자열로 디코딩하여 로그 메시지를 가져옴
        if packet.haslayer(Raw):
            # Raw 데이터를 문자열로 디코딩
            payload = packet[Raw].load.decode('utf-8', errors='ignore').lower()  # 대소문자 구분 없이 한 번에 처리
            # 외부 명령어 실행 시도를 나타내는 패턴, 공백을 고려하여 수정
            command_execution_patterns = [
                "system(", "system (", "exec(", "exec (", "popen(", "popen (", "shell(", "shell (",
                "sh(", "sh (", "bash(", "bash (", "zsh(", "zsh (", "ksh(", "ksh (", "csh(", "csh (", "tcsh(", "tcsh (", "dash(", "dash (",
                "cmd(", "cmd (", "powershell(", "powershell (", "wscript(", "wscript (", "cscript(", "cscript (", "cmd.exe(", "cmd.exe (", "powershell.exe(", "powershell.exe (",
                "wscript.exe(", "wscript.exe (", "cscript.exe(", "cscript.exe (",
                "os.system(", "os.system (", "os.popen(", "os.popen (", "subprocess.Popen(", "subprocess.Popen (", "subprocess.run(", "subprocess.run (",
                "subprocess.call(", "subprocess.call (", "subprocess.check_output(", "subprocess.check_output ("
            ]
            
            # 대소문자 구분 없이 패턴의 발생 횟수를 카운트
            for pattern in command_execution_patterns:
                # 페이로드 안에서 패턴의 발생 횟수를 찾는다
                command_execution_attempts += payload.count(pattern)
        return command_execution_attempts
    
    # 예외가 발생하면 0을 반환합니다.
    except Exception as e:
        print("Error in count_command_execution_attempts:", e)
        return 0

def detect_host_login(packet):
    """
    이 함수는 네트워크 패킷에서 호스트 로그인 시도를 감지합니다.
    패킷의 Raw 데이터를 분석하여 특정 호스트 로그인 시도 패턴을 찾습니다.
    발견된 패턴이 있으면 1을 반환하고, 그렇지 않으면 0을 반환합니다.
    """
    try:
        # 패킷의 Raw 데이터를 문자열로 디코딩하여 로그 메시지를 가져옴
        if packet.haslayer(Raw):
            # Raw 데이터를 문자열로 디코딩
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            # 호스트 로그인에 특화된 확장된 패턴 목록
            host_login_keywords = [
                'host login', 'host access', 'host user', 'system login', 'system access', 'local login', 'local access',
                'root access', 'root login', 'administrator login', 'admin access', 'ssh access', 'terminal login',
                'console login', 'server access', 'server login', 'direct access', 'secure host', 'login shell',
                'system authentication', 'privileged access', 'elevated access', 'sudo login', 'su login',
                'system admin login', 'machine access', 'machine login'
            ]
            # 대소문자 구분 없이 패턴의 발생 횟수를 카운트
            for keyword in host_login_keywords:
                # 페이로드 안에서 패턴의 발생 횟수를 찾는다
                if keyword in payload.lower():
                    return 1  # 호스트 로그인 시도가 감지되면 1을 반환합니다.
        return 0  # 호스트 로그인 시도가 감지되지 않으면 0을 반환합니다.
    
    # 예외가 발생하면 0을 반환합니다.
    except Exception as e:
        print("Error in detect_host_login:", e)
        return 0  # 오류가 발생하면 0을 반환합니다.
    

    
# 게스트 로그인 여부를 감지하는 함수
def detect_guest_login(packet):
    """
    이 함수는 네트워크 패킷에서 게스트 로그인 여부를 감지합니다.
    패킷의 Raw 데이터를 분석하여 특정 게스트 로그인 패턴을 찾습니다.
    발견된 패턴이 있으면 1을 반환하고, 그렇지 않으면 0을 반환합니다.
    """
    try:
        # 패킷의 Raw 데이터를 문자열로 디코딩하여 로그 메시지를 가져옴
        if packet.haslayer(Raw):
            # Raw 데이터를 문자열로 디코딩
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            # 게스트 로그인 패턴
            guest_login_patterns = ["guest", "anonymous"]
            
            # 대소문자 구분 없이 패턴의 발생 횟수를 카운트
            for pattern in guest_login_patterns:
                if pattern in payload.lower():
                    return 1  # 게스트 로그인 패턴이 발견되면 1을 반환합니다.
        return 0  # 모든 패턴에 일치하지 않으면 0을 반환합니다.
    
    # 예외가 발생하면 0을 반환합니다.
    except Exception as e:
        print("Error in detect_guest_login:", e)
        return 0  # 오류가 발생하면 0을 반환합니다.

# 네트워크 패킷에서 'count' 정보를 추적하기 위한 딕셔너리
def packet_callback(packet):
    """
    이 함수는 네트워크 패킷을 처리하여 'count' 정보를 추적합니다.
    """
    # 패킷의 IP 레이어를 포함하는지 확인
    connection_counts = {}
    # 소스 IP와 대상 IP 쌍을 키로 사용
    if IP in packet:
        src_ip = packet[IP].src # 소스 IP
        dst_ip = packet[IP].dst # 대상 IP
        # 소스 IP와 대상 IP 쌍을 키로 사용
        connection_key = (src_ip, dst_ip)
        
        # 연결 횟수 업데이트
        if connection_key in connection_counts:
            # 이미 존재하는 연결인 경우 연결 횟수를 1 증가
            connection_counts[connection_key] += 1
        else:
            # 새로운 연결인 경우 연결 횟수를 1로 초기화
            connection_counts[connection_key] = 1
            
    return connection_counts[connection_key]  # 연결 횟수 반환

# srv_count: 동일한 서비스로의 연결 수 추출하는 함수
def count_services(packet):
    """
    이 함수는 네트워크 패킷에서 동일한 서비스로의 연결 수를 세어 반환합니다.
    패킷의 IP 레이어를 분석하여 동일한 서비스로의 연결 수를 세어 반환합니다.
    """
    try:
        # 패킷의 IP 레이어를 포함하는지 확인
        service = packet[IP].dport
        # 연결 횟수 업데이트
        if service in packet_info['service']:
            packet_info['service'][service] += 1 # 이미 존재하는 서비스인 경우 연결 횟수를 1 증가
        else:
            packet_info['service'][service] = 1 # 새로운 서비스인 경우 연결 횟수를 1로 초기화
        return packet_info['service'][service]
    
    # 예외가 발생하면 0을 반환합니다.
    except Exception as e:
        print("Error in count_service_connections:", e)
        return 0  # 오류가 발생하면 0을 반환합니다.
    
#compromised 조건을 충족하는 횟수를 세는 함수
def count_compromised(packet):
    """
    이 함수는 네트워크 패킷에서 compromised 조건을 충족하는 횟수를 세어 반환합니다.
    패킷의 Raw 레이어 데이터를 분석하여 compromised 패턴을 찾습니다.
    발견된 패턴의 수를 반환합니다.
    """
    try:
        # compromised 패턴을 찾아서 카운트
        compromised = 0
        # 패킷이 Raw 데이터를 포함하는지 확인
        if packet.haslayer(Raw):
            # Raw 데이터를 문자열로 디코딩
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            # compromised 패턴
            compromised_patterns = [
                "compromised", "hacked", "breached", "exploited", "vulnerable", "infected", "malware", "ransomware",
                "trojan", "backdoor", "spyware", "rootkit", "keylogger", "ddos", "botnet", "phishing", "spoofing",
                "scam", "fraud", "identity theft", "data breach", "cyber attack", "cyber warfare", "cyber, security"
            ]   
            # 대소문자 구분 없이 패턴의 발생 횟수를 카운트
            for pattern in compromised_patterns:
                if pattern in payload.lower():
                    compromised += 1
        return compromised
    
    # 예외가 발생하면 0을 반환합니다.
    except Exception as e:
        print("Error in count_compromised:", e)
        return 0

# SYN 패킷의 에러 비율을 계산하는 함수
def calculate_syn_error_rate(packets):
    """
    이 함수는 SYN 패킷의 에러 비율을 계산합니다.
    SYN 패킷의 에러 비율은 SYN-ACK 패킷이 수신되지 않은 SYN 패킷의 비율로 계산됩니다.
    """
    try:
        syn_count = 0 # SYN 패킷 수를 저장할 변수 초기화
        syn_ack_count = 0 # SYN-ACK 패킷 수를 저장할 변수 초기화
        for packet in packets:
            # 패킷에 TCP 레이어가 포함되어 있는지 확인
            if TCP in packet:
                # SYN 패킷인지 확인
                if packet[TCP].flags & 0x02 and not packet[TCP].flags & 0x10:  # SYN
                    # SYN 패킷 수를 1 증가
                    syn_count += 1
                # SYN-ACK 패킷인지 확인
                elif packet[TCP].flags & 0x02 and packet[TCP].flags & 0x10:  # SYN-ACK
                    # SYN-ACK 패킷 수를 1 증가
                    syn_ack_count += 1
        # SYN 패킷이 존재하는 경우에만 에러 비율을 계산
        if syn_count > 0:
            # 에러 비율을 계산하여 반환
            error_rate = (syn_count - syn_ack_count) / syn_count
            # 음수일경우
            if error_rate < 0:
                error_rate = 0
            # 결과를 소수점 둘째자리까지 포맷하여 반환 (문자열로 반환됨)
            return format(error_rate, '.2f')
        else:
            # 0을 소수점 둘째자리 포맷의 문자열로 반환
            return '0.00'
        
    # 예외가 발생하면 0을 반환합니다.
    except Exception as e:
        print("Error in calculate_syn_error_rate:", e)
        return '0.00'
    
# 서비스의 SYN 에러 비율을 계산하는 함수
def calculate_service_syn_error_rate(packets, service):
    """
    이 함수는 특정 서비스의 SYN 패킷의 에러 비율을 계산합니다.
    SYN 패킷의 에러 비율은 SYN-ACK 패킷이 수신되지 않은 SYN 패킷의 비율로 계산됩니다.
    """
    try:
        syn_count = 0 # SYN 패킷 수를 저장할 변수 초기화
        syn_ack_count = 0 # SYN-ACK 패킷 수를 저장할 변수 초기화
        # 패킷을 순회하며 SYN 패킷과 SYN-ACK 패킷을 카운트
        for packet in packets:
            # 패킷에 TCP 레이어가 포함되어 있는지 확인
            if TCP in packet and packet[IP].dport == service:
                # SYN 패킷인지 확인
                if packet[TCP].flags & 0x02 and not packet[TCP].flags & 0x10:  # SYN
                    syn_count += 1
                # SYN-ACK 패킷인지 확인
                elif packet[TCP].flags & 0x02 and packet[TCP].flags & 0x10:  # SYN-ACK
                    syn_ack_count += 1
                    
        # SYN 패킷이 존재하는 경우에만 에러 비율을 계산
        if syn_count > 0:
            error_rate = (syn_count - syn_ack_count) / syn_count
            # 결과를 소수점 둘째자리까지 포맷하여 반환 (문자열로 반환됨)
            return format(error_rate, '.2f')
        else:
            # 0을 소수점 둘째자리 포맷의 문자열로 반환
            return '0.00'
        
    # 예외가 발생하면 0을 반환합니다.
    except Exception as e:
        print("Error in calculate_service_syn_error_rate:", e)
        return '0.00'
    
# 연결의 REJ 에러 비율을 계산하는 함수
def calculate_reject_error_rate(packets):
    """
    이 함수는 연결의 REJ 에러 비율을 계산합니다.
    REJ 에러 비율은 RST 패킷의 비율로 계산됩니다.
    """
    try:
        # RST 패킷 수를 저장할 변수 초기화
        reject_count = 0
        # 패킷을 순회하며 RST 패킷을 카운트
        for packet in packets:
            # 패킷에 TCP 레이어가 포함되어 있는지 확인
            if TCP in packet and packet[TCP].flags & 0x04:  # RST
                reject_count += 1
        # RST 패킷이 존재하는 경우에만 에러 비율을 계산
        if len(packets) > 0:
            # 에러 비율을 계산하여 반환
            error_rate = reject_count / len(packets)
            # 결과를 소수점 둘째자리까지 포맷하여 반환 (문자열로 반환됨)
            return format(error_rate, '.2f')
        else:
            # 0을 소수점 둘째자리 포맷의 문자열로 반환
            return '0.00'
    
    # 예외가 발생하면 0을 반환합니다.
    except Exception as e:
        print("Error in calculate_reject_error_rate:", e)
        return '0.00'
        
# 서비스의 REJ 에러 비율을 계산하는 함수
def calculate_service_reject_error_rate(packets, service):
    """
    이 함수는 특정 서비스의 REJ 에러 비율을 계산합니다.
    REJ 에러 비율은 RST 패킷의 비율로 계산됩니다.
    """
    try:
        # RST 패킷 수를 저장할 변수 초기화
        reject_count = 0
        # 패킷을 순회하며 RST 패킷을 카운트
        for packet in packets:
            # 패킷에 TCP 레이어가 포함되어 있는지 확인
            if TCP in packet and packet[IP].dport == service and packet[TCP].flags & 0x04:  # RST
                reject_count += 1
        # RST 패킷이 존재하는 경우에만 에러 비율을 계산
        if len(packets) > 0:
            error_rate = reject_count / len(packets)
            # 결과를 소수점 둘째자리까지 포맷하여 반환 (문자열로 반환됨)
            return format(error_rate, '.2f')
        else:
            # 0을 소수점 둘째자리 포맷의 문자열로 반환
            return '0.00'
        
    # 예외가 발생하면 0을 반환합니다.
    except Exception as e:
        print("Error in calculate_service_reject_error_rate:", e)
        return '0.00'

# 서비스의 에러 비율을 계산하는 함수
def calculate_same_srv_rate(packets, target_service_port):
    """
    이 함수는 특정 서비스의 에러 비율을 계산합니다.
    에러 비율은 RST 패킷의 비율로 계산됩니다.
    """
    try:
        # 패킷이 없는 경우 0.00을 반환
        if not packets:
            return "0.00"
        # 동일 서비스 카운트
        same_service_count = sum(1 for packet in packets if TCP in packet and packet[TCP].dport == target_service_port)
        # 전체 카운트
        total_count = len(packets)
        
        # 에러 비율을 계산하여 반환
        same_srv_rate = same_service_count / total_count if total_count > 0 else 0
        return "{:.2f}".format(same_srv_rate)
    
    # 예외가 발생하면 0을 반환합니다.
    except Exception as e:
        print("Error in calculate_same_srv_rate:", e)
        return "0.00"

# 다른 서비스 비율을 계산하는 함수
def calculate_diff_srv_rate(packets, target_service_port):
    """
    이 함수는 특정 서비스의 에러 비율을 계산합니다.
    에러 비율은 RST 패킷의 비율로 계산됩니다.
    """
    try:
        # 패킷이 없는 경우 0.00을 반환
        if not packets:
            return "0.00"
        
        # 다른 서비스 카운트
        diff_service_count = sum(1 for packet in packets if TCP in packet and packet[TCP].dport != target_service_port)
        # 전체 카운트
        total_count = len(packets)
        
        # 에러 비율을 계산하여 반환
        diff_srv_rate = diff_service_count / total_count if total_count > 0 else 0
        return "{:.2f}".format(diff_srv_rate)
    
    # 예외가 발생하면 0을 반환합니다.
    except Exception as e:
        print("Error in calculate_diff_srv_rate:", e)
        return "0.00"

# 다른 호스트 비율을 계산하는 함수
def calculate_srv_diff_host_rate(packets, target_service_port):
    """
    이 함수는 특정 서비스의 에러 비율을 계산합니다.
    에러 비율은 RST 패킷의 비율로 계산됩니다.
    """
    try:
        # 패킷이 없는 경우 0.00을 반환
        if not packets:
            return "0.00"
        # 서비스 패킷을 추출
        service_packets = [packet for packet in packets if TCP in packet and packet[TCP].dport == target_service_port]
        # 서비스 패킷이 없는 경우 0.00을 반환
        if not service_packets:
            return "0.00"
        
        # 대상 호스트 IP별로 패킷 수를 계산
        host_counts = {} # 호스트 IP별 패킷 수를 저장할 딕셔너리 초기화
        # 패킷을 순회하며 대상 호스트 IP별로 패킷 수를 카운트
        for packet in service_packets:
            dst_ip = packet[IP].dst # 대상 호스트 IP
            # 대상 호스트 IP별로 패킷 수를 카운트
            if dst_ip in host_counts:
                host_counts[dst_ip] += 1 # 이미 존재하는 호스트인 경우 패킷 수를 1 증가
            else:
                host_counts[dst_ip] = 1 # 새로운 호스트인 경우 패킷 수를 1로 초기화
        
        # 호스트가 1번만 나타난 경우의 수를 세어 다른 호스트 비율을 계산
        single_occurrences = sum(1 for count in host_counts.values() if count == 1) # 1번만 나타난 경우의 수를 세어 저장
        total_service_packets = len(service_packets) # 서비스 패킷의 총 수를 저장
        
        # 에러 비율을 계산하여 반환
        srv_diff_host_rate = single_occurrences / total_service_packets if total_service_packets > 0 else 0
        return "{:.2f}".format(srv_diff_host_rate)
    
    # 예외가 발생하면 0을 반환합니다.
    except Exception as e:
        print("Error in calculate_srv_diff_host_rate:", e)
        return "0.00"

# 목적지 호스트의 연결 수 구하는 함수
def calculate_dst_host_count(packets):
    """
    이 함수는 목적지 호스트의 연결 수를 계산합니다.
    """
    try:
        # 목적지 호스트 IP별로 패킷 수를 계산
        dst_host_counts = {} # 목적지 호스트 IP별 패킷 수를 저장할 딕셔너리 초기화
        # 패킷을 순회하며 목적지 호스트 IP별로 패킷 수를 카운트
        for packet in packets:
            # 패킷에 IP 레이어가 포함되어 있는지 확인
            if IP in packet:
                dst_ip = packet[IP].dst # 목적지 호스트 IP
                # 목적지 호스트 IP별로 패킷 수를 카운트
                if dst_ip in dst_host_counts:
                    dst_host_counts[dst_ip] += 1 # 이미 존재하는 목적지 호스트인 경우 패킷 수를 1 증가
                else:
                    dst_host_counts[dst_ip] = 1 # 새로운 목적지 호스트인 경우 패킷 수를 1로 초기화
        # 모든 목적지 IP 주소의 연결 수를 반환
        return dst_host_counts[dst_ip]
    
    # 예외가 발생하면 0을 반환합니다.
    except Exception as e:
        print("Error in calculate_dst_host_count:", e)
        return 0

# 목적지 호스트의 서비스 연결 수를 구하는 함수
def count_dst_host_service_connections(packets, target_service_port, target_dst_ip):
    """
    이 함수는 목적지 호스트의 특정 서비스 연결 수를 세어 반환합니다.
    """
    try:
        # 목적지 호스트의 특정 서비스 연결 수를 저장할 변수 초기화
        connection_count = 0
        # 패킷을 순회하며 목적지 호스트의 특정 서비스 연결 수를 카운트
        for packet in packets:
            # 패킷에 IP 레이어가 포함되어 있는지 확인
            if IP in packet and packet[IP].dst == target_dst_ip:
                # 목적지 호스트의 특정 서비스 연결 수를 카운트
                if TCP in packet and packet[TCP].dport == target_service_port:
                    connection_count += 1
        # 목적지 호스트의 특정 서비스 연결 수를 반환
        return connection_count
    
    # 예외가 발생하면 0을 반환합니다.
    except Exception as e:
        print("Error in count_dst_host_service_connections:", e)
        return 0


# 목적지 호스트로의 같은 서비스 연결 비율을 계산하는 함수
def calculate_dst_host_srv_rate(packets, target_service_port, target_dst_ip):
    """
    이 함수는 목적지 호스트로의 같은 서비스 연결 비율을 계산합니다.
    """
    try:
        # 패킷이 없는 경우 0.00을 반환
        if not packets:
            return "0.00"
        
        # 목적지 호스트의 특정 서비스 연결 수를 구함
        same_service_count = count_dst_host_service_connections(packets, target_service_port, target_dst_ip)
        # 전체 연결 수를 구함
        total_count = len(packets)
        
        # 에러 비율을 계산하여 반환
        same_srv_rate = same_service_count / total_count if total_count > 0 else 0
        return "{:.2f}".format(same_srv_rate)
    
    # 예외가 발생하면 0.00을 반환합니다.
    except Exception as e:
        print("Error in calculate_dst_host_srv_rate:", e)
        return "0.00"

# 목적지 호스트로의 다른 서비스 연결 비율을 계산 하는 함수
def calculate_dst_host_diff_srv_rate(packets, target_service_port, target_dst_ip):
    """
    이 함수는 목적지 호스트로의 다른 서비스 연결 비율을 계산합니다.
    """
    try:
        # 패킷이 없는 경우 0.00을 반환
        if not packets:
            return "0.00"
        
        # 목적지 호스트의 특정 서비스 연결 수를 구함
        diff_service_count = sum(1 for packet in packets if IP in packet and packet[IP].dst == target_dst_ip and TCP in packet and packet[TCP].dport != target_service_port)
        # 전체 연결 수를 구함
        total_count = len(packets)
        
        # 에러 비율을 계산하여 반환
        diff_srv_rate = diff_service_count / total_count if total_count > 0 else 0
        return "{:.2f}".format(diff_srv_rate)
    
    # 예외가 발생하면 0.00을 반환합니다.
    except Exception as e:
        print("Error in calculate_dst_host_diff_srv_rate:", e)
        return "0.00"

# 목적지 호스트로의 같은 소스 포트 연결 비율을 계산하는 함수
def calculate_dst_host_src_port_rate(packets, target_src_port, target_dst_ip):
    """
    이 함수는 목적지 호스트로의 같은 소스 포트 연결 비율을 계산합니다.
    """
    try:
        # 패킷이 없는 경우 0.00을 반환
        if not packets:
            return "0.00"
        # 목적지 호스트로의 같은 소스 포트 연결 수를 구함
        same_src_port_count = sum(1 for packet in packets if IP in packet and packet[IP].dst == target_dst_ip and TCP in packet and packet[TCP].sport == target_src_port)
        # 전체 연결 수를 구함
        total_count = len(packets)
        
        # 에러 비율을 계산하여 반환
        same_src_port_rate = same_src_port_count / total_count if total_count > 0 else 0
        return "{:.2f}".format(same_src_port_rate)
    
    # 예외가 발생하면 0.00을 반환합니다.
    except Exception as e:
        print("Error in calculate_dst_host_src_port_rate:", e)
        return "0.00"

# 서비스 연결에서 다른 호스트 비율을 계산하는 함수
def calculate_service_diff_host_rate(packets, target_service_port):
    """
    이 함수는 서비스 연결에서 다른 호스트 비율을 계산합니다.
    """
    try:
        # 패킷이 없는 경우 0.00을 반환
        if not packets:
            return "0.00"
        
        # 서비스 패킷을 추출
        service_packets = [packet for packet in packets if TCP in packet and packet[TCP].dport == target_service_port]
        # 서비스 패킷이 없는 경우 0.00을 반환
        if not service_packets:
            return "0.00"
        
        # 대상 호스트 IP별로 패킷 수를 계산
        host_counts = {} # 호스트 IP별 패킷 수를 저장할 딕셔너리 초기화
        # 패킷을 순회하며 대상 호스트 IP별로 패킷 수를 카운트
        for packet in service_packets:
            dst_ip = packet[IP].dst  # 대상 호스트 IP
            # 대상 호스트 IP별로 패킷 수를 카운트
            if dst_ip in host_counts:
                host_counts[dst_ip] += 1 # 이미 존재하는 호스트인 경우 패킷 수를 1 증가
            else:
                host_counts[dst_ip] = 1 # 새로운 호스트인 경우 패킷 수를 1로 초기화
        
        # 호스트가 1번만 나타난 경우의 수를 세어 다른 호스트 비율을 계산
        single_occurrences = sum(1 for count in host_counts.values() if count == 1)
        # 서비스 패킷의 총 수를 저장
        total_service_packets = len(service_packets)
        
        # 에러 비율을 계산하여 반환
        srv_diff_host_rate = single_occurrences / total_service_packets if total_service_packets > 0 else 0
        return "{:.2f}".format(srv_diff_host_rate)
    
    # 예외가 발생하면 0.00을 반환합니다.
    except Exception as e:
        print("Error in calculate_service_diff_host_rate:", e)
        return "0.00"

# 목적지 호스트의 SYN 에러 비율을 계산하는 함수
def calculate_dst_host_syn_error_rate(packets, target_dst_ip):
    """
    이 함수는 목적지 호스트의 SYN 에러 비율을 계산합니다.
    """
    try:
        syn_count = 0 # SYN 패킷 수를 저장할 변수 초기화
        syn_ack_count = 0 # SYN-ACK 패킷 수를 저장할 변수 초기화
        
        # 패킷을 순회하며 목적지 호스트의 SYN 패킷과 SYN-ACK 패킷을 카운트
        for packet in packets:
            # 패킷에 IP 레이어가 포함되어 있는지 확인
            if IP in packet and packet[IP].dst == target_dst_ip and TCP in packet:
                # SYN 패킷인지 확인
                if packet[TCP].flags & 0x02 and not packet[TCP].flags & 0x10:  # SYN
                    syn_count += 1
                # SYN-ACK 패킷인지 확인
                elif packet[TCP].flags & 0x02 and packet[TCP].flags & 0x10:  # SYN-ACK
                    syn_ack_count += 1
                    
        # SYN 패킷이 존재하는 경우에만 에러 비율을 계산
        if syn_count > 0:
            error_rate = (syn_count - syn_ack_count) / syn_count # 에러 비율을 계산
            # 음수인 경우 0으로 처리
            if error_rate < 0:
                error_rate = 0
            # 결과를 소수점 둘째자리까지 포맷하여 반환 (문자열로 반환됨)
            return format(error_rate, '.2f')
        else:
            # 0을 소수점 둘째자리 포맷의 문자열로 반환
            return '0.00'
        
    # 예외가 발생하면 0.00을 반환합니다.
    except Exception as e:
        print("Error in calculate_dst_host_syn_error_rate:", e)
        return '0.00'


# 목적지 호스트의 서비스 SYN 에러 비율을 계산하는 함수
def calculate_dst_host_service_syn_error_rate(packets, target_service_port, target_dst_ip):
    """
    이 함수는 목적지 호스트의 서비스 SYN 에러 비율을 계산합니다.
    """
    try:
        syn_count = 0 # SYN 패킷 수를 저장할 변수 초기화
        syn_ack_count = 0 # SYN-ACK 패킷 수를 저장할 변수 초기화
        
        # 패킷을 순회하며 목적지 호스트의 서비스 SYN 패킷과 SYN-ACK 패킷을 카운트
        for packet in packets:
            # 패킷에 IP 레이어가 포함되어 있는지 확인
            if IP in packet and packet[IP].dst == target_dst_ip and TCP in packet and packet[TCP].dport == target_service_port:
                # SYN 패킷인지 확인
                if packet[TCP].flags & 0x02 and not packet[TCP].flags & 0x10:  # SYN
                    syn_count += 1
                # SYN-ACK 패킷인지 확인
                elif packet[TCP].flags & 0x02 and packet[TCP].flags & 0x10:  # SYN-ACK
                    syn_ack_count += 1
        # SYN 패킷이 존재하는 경우에만 에러 비율을 계산
        if syn_count > 0:
            error_rate = (syn_count - syn_ack_count) / syn_count
            # 결과를 소수점 둘째자리까지 포맷하여 반환 (문자열로 반환됨)
            return format(error_rate, '.2f')
        else:
            # 0을 소수점 둘째자리 포맷의 문자열로 반환
            return '0.00'
        
    # 예외가 발생하면 0.00을 반환합니다.
    except Exception as e:
        print("Error in calculate_dst_host_service_syn_error_rate:", e)
        return '0.00'

# 목적지 호스트의 REJ 에러 비율을 계산하는 함수
def calculate_dst_host_reject_error_rate(packets, target_dst_ip):
    """
    이 함수는 목적지 호스트의 REJ 에러 비율을 계산합니다.
    """
    try:
        # RST 패킷 수를 저장할 변수 초기화
        reject_count = 0
        
        # 패킷을 순회하며 목적지 호스트의 RST 패킷을 카운트
        for packet in packets:
            # 패킷에 IP 레이어가 포함되어 있는지 확인
            if IP in packet and packet[IP].dst == target_dst_ip and TCP in packet and packet[TCP].flags & 0x04:  # RST
                reject_count += 1
        # RST 패킷이 존재하는 경우에만 에러 비율을 계산
        if len(packets) > 0:
            error_rate = reject_count / len(packets)
            # 결과를 소수점 둘째자리까지 포맷하여 반환 (문자열로 반환됨)
            return format(error_rate, '.2f')
        else:
            # 0을 소수점 둘째자리 포맷의 문자열로 반환
            return '0.00'
    
    # 예외가 발생하면 0.00을 반환합니다.
    except Exception as e:
        print("Error in calculate_dst_host_reject_error_rate:", e)
        return '0.00'

# 목적지 호스트의 서비스 REJ 에러 비율을 계산하는 함수
def calculate_dst_host_service_reject_error_rate(packets, target_service_port, target_dst_ip):
    """
    이 함수는 목적지 호스트의 서비스 REJ 에러 비율을 계산합니다.
    """
    try:
        # RST 패킷 수를 저장할 변수 초기화
        reject_count = 0
        
        # 패킷을 순회하며 목적지 호스트의 서비스 RST 패킷을 카운트
        for packet in packets:
            # 패킷에 IP 레이어가 포함되어 있는지 확인
            if IP in packet and packet[IP].dst == target_dst_ip and TCP in packet and packet[TCP].dport == target_service_port and packet[TCP].flags & 0x04:  # RST
                reject_count += 1
        # RST 패킷이 존재하는 경우에만 에러 비율을 계산
        if len(packets) > 0:
            error_rate = reject_count / len(packets)
            # 결과를 소수점 둘째자리까지 포맷하여 반환 (문자열로 반환됨)
            return format(error_rate, '.2f')
        else:
            # 0을 소수점 둘째자리 포맷의 문자열로 반환
            return '0.00'
    
    # 예외가 발생하면 0.00을 반환합니다.
    except Exception as e:
        print("Error in calculate_dst_host_service_reject_error_rate:", e)
        return '0.00'