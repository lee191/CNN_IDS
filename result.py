import pandas as pd
import joblib

le_protocol = joblib.load('model_artifacts/le_protocol_type.pkl')
le_service = joblib.load('model_artifacts/le_service_updated.pkl')
le_flag = joblib.load('model_artifacts/le_flag.pkl')
# 컬럼 이름 설정
columns = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
           'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 
           'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 
           'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate', 
           'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 
           'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 
           'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 
           'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 
           'dst_host_srv_rerror_rate', 'label', 'difficulty_level']

# 공격 유형별로 레이블 지정
attack_types = {
    'normal': 'NORMAL',
    'neptune': 'DOS', 'back': 'DOS', 'land': 'DOS', 'pod': 'DOS', 'smurf': 'DOS', 'teardrop': 'DOS',
    'ipsweep': 'PROBE', 'nmap': 'PROBE', 'portsweep': 'PROBE', 'satan': 'PROBE',
    'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'imap': 'R2L', 'multihop': 'R2L', 'phf': 'R2L', 'spy': 'R2L', 'warezclient': 'R2L', 'warezmaster': 'R2L',
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 'rootkit': 'U2R',
    'apache2': 'DOS', 'mailbomb': 'DOS', 'processtable': 'DOS', 'udpstorm': 'DOS', 'worm': 'DOS', 'mscan': 'PROBE', 'saint': 'PROBE', 'httptunnel': 'R2L', 'named': 'R2L', 'sendmail': 'R2L', 'snmpgetattack': 'R2L', 'snmpguess': 'R2L', 'xlock': 'R2L', 'xsnoop': 'R2L', 'httptunnel': 'R2L', 'ps': 'U2R', 'sqlattack': 'U2R', 'xterm': 'U2R'
}

# csv 파일을 읽어옵니다.
data = pd.read_csv('CNN_results.csv', names=columns, header=None)
data2 = pd.read_csv('NSL-KDD/KDDTest+.txt', names=columns, header=None)

# 불필요한 컬럼 삭제
data = data.drop(['difficulty_level'], axis=1)
data2 = data2.drop(['difficulty_level'], axis=1)

# data 첫번쨰 행 삭제
data = data.drop(data.index[0])

# data2 인코딩
data2['protocol_type'] = le_protocol.transform(data2['protocol_type'])
data2['service'] = le_service.transform(data2['service'])
data2['flag'] = le_flag.transform(data2['flag'])

# 라벨 치환
data2['label'] = data2['label'].map(lambda x: attack_types.get(x, x.upper()))


print(data.head())
print(data2.head())

# data의 인덱스를 0부터 시작
data.index = range(len(data))

print(data.head())

# 공격유형 별로 data와 data2의 일치하는 데이터 개수를 세어줍니다.
matching_counts = {}

# 공격 유형 리스트
attack_types_list = ['NORMAL', 'DOS', 'PROBE', 'R2L', 'U2R']

for attack_type in attack_types_list:
    # data와 data2에서 해당 공격 유형의 데이터 필터링
    data_attack = data[data['label'] == attack_type]
    data2_attack = data2[data2['label'] == attack_type]
    
    # 공통 인덱스를 사용하여 일치하는 행의 수를 셈
    common_index = data_attack.index.intersection(data2_attack.index)
    match_count = sum((data_attack.loc[idx] == data2_attack.loc[idx]).all() for idx in common_index)
    
    matching_counts[attack_type] = match_count

# 결과 출력
for attack_type, count in matching_counts.items():
    print(f"공격 유형: {attack_type}, 일치하는 데이터 개수: {count}")