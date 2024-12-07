import pandas as pd
import numpy as np
from keras.models import load_model
from sklearn.preprocessing import MinMaxScaler
import joblib
from keras.optimizers import Adam
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score
from keras.utils import to_categorical



###########################################
# NSL-KDD Test 데이터셋을 사용하여 CNN 모델 테스트#
###########################################

# 모델 및 인코더, 스케일러 불러오기
model = load_model('model_artifacts/CNN_model.h5')
model.compile(optimizer=Adam(), loss='categorical_crossentropy', metrics=['accuracy'])

le_protocol = joblib.load('model_artifacts/le_protocol_type.pkl')
le_service = joblib.load('model_artifacts/le_service_updated.pkl')
le_flag = joblib.load('model_artifacts/le_flag.pkl')
scaler = joblib.load('model_artifacts/scaler.pkl')
le_label = joblib.load('model_artifacts/le_label.pkl')

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

# 공격 유형별로 레이블 지정
attack_types = {
    'normal': 'NORMAL',
    'neptune': 'DOS', 'back': 'DOS', 'land': 'DOS', 'pod': 'DOS', 'smurf': 'DOS', 'teardrop': 'DOS',
    'ipsweep': 'PROBE', 'nmap': 'PROBE', 'portsweep': 'PROBE', 'satan': 'PROBE',
    'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'imap': 'R2L', 'multihop': 'R2L', 'phf': 'R2L', 'spy': 'R2L', 'warezclient': 'R2L', 'warezmaster': 'R2L',
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 'rootkit': 'U2R',
    'apache2': 'DOS', 'mailbomb': 'DOS', 'processtable': 'DOS', 'udpstorm': 'DOS', 'worm': 'DOS', 'mscan': 'PROBE', 'saint': 'PROBE', 'httptunnel': 'R2L', 'named': 'R2L', 'sendmail': 'R2L', 'snmpgetattack': 'R2L', 'snmpguess': 'R2L', 'xlock': 'R2L', 'xsnoop': 'R2L', 'httptunnel': 'R2L', 'ps': 'U2R', 'sqlattack': 'U2R', 'xterm': 'U2R'
}

# common_features = ['dst_host_diff_srv_rate', 'count', 'logged_in', 'srv_count', 'service', 'serror_rate', 'dst_host_srv_serror_rate', 'same_srv_rate', 'flag', 'dst_host_same_srv_rate', 'diff_srv_rate', 'dst_host_rerror_rate', 'dst_host_srv_count', 'srv_serror_rate']

data_test = pd.read_csv('NSL-KDD/KDDTest+.txt', names=columns, header=None)

data_test['label'] = data_test['label'].map(lambda x: attack_types.get(x, x.upper()))
data_test = data_test[(data_test['label'] == 'DOS') | (data_test['label'] == 'PROBE') | (data_test['label'] == 'NORMAL')]


data_test = data_test.drop(['label'], axis=1)
data_test = data_test.drop(['difficulty_level'], axis=1)


# 데이터 인코딩 및 스케일링
data_test['protocol_type'] = le_protocol.transform(data_test['protocol_type'])
data_test['service'] = le_service.transform(data_test['service'])
data_test['flag'] = le_flag.transform(data_test['flag'])

# data_test = data_test[common_features]
X_test_scaled = scaler.transform(data_test)
X_test_scaled = X_test_scaled.reshape(X_test_scaled.shape[0], X_test_scaled.shape[1], 1)

# 모델 예측
predictions = model.predict(X_test_scaled)
predictions = np.argmax(predictions, axis=1)  # 가장 높은 확률을 가진 클래스의 인덱스를 가져옵니다.

# 예측 결과 분석
attack_types = le_label.classes_
attack_counts = pd.value_counts(predictions)
attack_counts.index = [attack_types[i] for i in attack_counts.index]

# 결과 저장
data_test['label'] = le_label.inverse_transform(predictions)
data_test.to_csv('CNN_results.csv', index=False)

# 정확도 출력
print("CNN 공격 유형별 탐지 개수:")
print(attack_counts)



############################################################################################################



########################
# packet_info 테스트 CNN #
########################

# 모델 및 인코더, 스케일러 불러오기
model = load_model('model_artifacts/CNN_model.h5')
le_protocol = joblib.load('model_artifacts/le_protocol_type.pkl')
le_service = joblib.load('model_artifacts/le_service.pkl')
le_flag = joblib.load('model_artifacts/le_flag.pkl')
scaler = joblib.load('model_artifacts/scaler.pkl')
le_label = joblib.load('model_artifacts/le_label.pkl')

# 테스트 데이터 준비
columns = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
           'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 
           'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 
           'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate', 
           'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 
           'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 
           'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 
           'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 
           'dst_host_srv_rerror_rate']
data_test = pd.read_csv('packet_info.csv', names=columns, header=None)
# 라벨 열을 제거합니다.
# data_test = data_test.drop(['label'], axis=1)

# 데이터 인코딩 및 스케일링을 위한 예외 처리
dropped_rows_count = 0

# 'protocol_type' 처리
valid_indices = data_test['protocol_type'].isin(le_protocol.classes_)
dropped_rows_count += (~valid_indices).sum()  # 제거되는 행 수를 카운트
data_test = data_test[valid_indices]

# 'service' 처리
valid_indices = data_test['service'].isin(le_service.classes_)
dropped_rows_count += (~valid_indices).sum()  # 제거되는 행 수를 카운트
data_test = data_test[valid_indices]

# 'flag' 처리
valid_indices = data_test['flag'].isin(le_flag.classes_)
dropped_rows_count += (~valid_indices).sum()  # 제거되는 행 수를 카운트
data_test = data_test[valid_indices]

# 데이터 인코딩
data_test['protocol_type'] = le_protocol.transform(data_test['protocol_type'])
data_test['service'] = le_service.transform(data_test['service'])
data_test['flag'] = le_flag.transform(data_test['flag'])

# data_test = data_test[common_features]

# 스케일링 전에 데이터셋에 샘플이 존재하는지 확인
if data_test.shape[0] > 0:
    X_test_scaled = scaler.transform(data_test)
    X_test_scaled = X_test_scaled.reshape(X_test_scaled.shape[0], X_test_scaled.shape[1], 1)

    # 모델 예측
    predictions = model.predict(X_test_scaled)
    predictions = np.argmax(predictions, axis=1)  # 가장 높은 확률을 가진 클래스의 인덱스를 가져옵니다.

    # 예측 결과 출력
    attack_types = le_label.classes_
    attack_counts = pd.value_counts(predictions)
    attack_counts.index = [attack_types[i] for i in attack_counts.index]
    # packt_info에 라벨을 추가해서 저장a
    data_test['label'] = le_label.inverse_transform(predictions)
    # normal빼고 저장
    data_test = data_test[data_test['label'] != 'normal']
    
    data_test.to_csv('packet_info_label.csv', index=False)
    
    
    print("CNN 공격 유형별 탐지 개수(개인수집):")
    print(attack_counts)
else:
    print("전처리 과정에서 모든 데이터가 제거되었습니다. 스케일링과 예측을 진행할 수 없습니다.")

    
############################################################################################



import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix

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

# 레이블 치환
attack_types = {
    'normal': 'NORMAL',
    'neptune': 'DOS', 'back': 'DOS', 'land': 'DOS', 'pod': 'DOS', 'smurf': 'DOS', 'teardrop': 'DOS',
    'ipsweep': 'PROBE', 'nmap': 'PROBE', 'portsweep': 'PROBE', 'satan': 'PROBE',
    'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'imap': 'R2L', 'multihop': 'R2L', 'phf': 'R2L', 'spy': 'R2L', 'warezclient': 'R2L', 'warezmaster': 'R2L',
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 'rootkit': 'U2R',
    'apache2': 'DOS', 'mailbomb': 'DOS', 'processtable': 'DOS', 'udpstorm': 'DOS', 'worm': 'DOS', 'mscan': 'PROBE', 'saint': 'PROBE', 'httptunnel': 'R2L', 'named': 'R2L', 'sendmail': 'R2L', 'snmpgetattack': 'R2L', 'snmpguess': 'R2L', 'xlock': 'R2L', 'xsnoop': 'R2L', 'httptunnel': 'R2L', 'ps': 'U2R', 'sqlattack': 'U2R', 'xterm': 'U2R'
}

# 실제 레이블 데이터 로드 (예제에서는 NSL-KDD 테스트 데이터셋을 재사용합니다)
true_data = pd.read_csv('NSL-KDD/KDDTest+.txt', names=columns, header=None)

print(true_data.info())

true_data['label'] = true_data['label'].map(lambda x: attack_types.get(x, x.upper()))
true_data = true_data[(true_data['label'] == 'DOS') | (true_data['label'] == 'PROBE') | (true_data['label'] == 'NORMAL')]

# 불필요한 칼럼 제거
true_data.drop(['difficulty_level'], axis=1, inplace=True)
true_labels = true_data['label']


# 예측된 레이블 로드 (이미 data_test에 'label'이라는 이름으로 저장했다고 가정)
predicted_data = pd.read_csv('CNN_results.csv')
predicted_labels = predicted_data.iloc[:, -1]  # 마지막 열 선택
# 레이블 인코딩
le = joblib.load('model_artifacts/le_label.pkl')
true_labels_encoded = le.transform(true_labels)
predicted_labels_encoded = le.transform(predicted_labels)

# 혼동 행렬 계산
cm = confusion_matrix(true_labels_encoded, predicted_labels_encoded)

# 정확도 계산
accuracy = accuracy_score(true_labels_encoded, predicted_labels_encoded)
print(f'Accuracy: {accuracy:.4f}')

# 혼동 행렬을 이용한 히트맵 생성
plt.figure(figsize=(10, 7))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=le.classes_, yticklabels=le.classes_)
plt.title('Confusion Matrix Heatmap')
plt.xlabel('Predicted Labels')
plt.ylabel('True Labels')
plt.show()
