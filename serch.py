import pandas as pd

# 공격 유형별로 레이블 지정
attack_types = {
    'normal': 'NORMAL',
    'neptune': 'DOS', 'back': 'DOS', 'land': 'DOS', 'pod': 'DOS', 'smurf': 'DOS', 'teardrop': 'DOS',
    'ipsweep': 'PROBE', 'nmap': 'PROBE', 'portsweep': 'PROBE', 'satan': 'PROBE',
    'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'imap': 'R2L', 'multihop': 'R2L', 'phf': 'R2L', 'spy': 'R2L', 'warezclient': 'R2L', 'warezmaster': 'R2L',
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 'rootkit': 'U2R',
    'apache2': 'DOS', 'mailbomb': 'DOS', 'processtable': 'DOS', 'udpstorm': 'DOS', 'worm': 'DOS', 'mscan': 'PROBE', 'saint': 'PROBE', 'httptunnel': 'R2L', 'named': 'R2L', 'sendmail': 'R2L', 'snmpgetattack': 'R2L', 'snmpguess': 'R2L', 'xlock': 'R2L', 'xsnoop': 'R2L', 'httptunnel': 'R2L', 'ps': 'U2R', 'sqlattack': 'U2R', 'xterm': 'U2R'
}

# 테스트 데이터 준비
columns = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
           'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 
           'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 
           'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate', 
           'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 
           'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 
           'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 
           'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 
           'dst_host_srv_rerror_rate', 'label', 'difficulty_level']
data = pd.read_csv('NSL-KDD/KDDTest+.txt', names=columns, header=None)
# 불필요한 컬럼 삭제
data.drop(['difficulty_level'], axis=1, inplace=True)
# 라벨 치환
data['label'] = data['label'].map(lambda x: attack_types.get(x, x.upper()))

# 데이터별 공격 유형 개수 확인
attack_counts = data['label'].value_counts()
print(attack_counts)
total = data.shape[0]
print(total)