from keras.models import Sequential
from keras.layers import Conv1D, MaxPooling1D, Flatten, Dense, Dropout, BatchNormalization, GRU
from keras.optimizers import Adam
from keras.callbacks import EarlyStopping
from keras.utils import to_categorical
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from sklearn.model_selection import train_test_split
import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
import tensorflow as tf
from keras.layers import LSTM, PReLU
import seaborn as sns


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

# common_features = ['dst_host_diff_srv_rate', 'count', 'logged_in', 'srv_count', 'service', 'serror_rate', 'dst_host_srv_serror_rate', 'same_srv_rate', 'flag', 'dst_host_same_srv_rate', 'diff_srv_rate', 'dst_host_rerror_rate', 'dst_host_srv_count', 'srv_serror_rate']

# 데이터 불러오기 및 전처리
data = pd.read_csv('NSL-KDD/KDDTrain+.txt', names=columns, header=None)
data.drop(['difficulty_level'], axis=1, inplace=True)

# 결측치 확인
print(data.isnull().sum())

data['label'] = data['label'].map(lambda x: attack_types.get(x, x.upper()))
data = data[(data['label'] == 'DOS') | (data['label'] == 'PROBE') | (data['label'] == 'NORMAL')]

# 레이블 종류 확인
print(data['label'].value_counts())


le = LabelEncoder()
data['label'] = le.fit_transform(data['label'])
data_labels_one_hot = to_categorical(data['label'])
joblib.dump(le, 'model_artifacts/le_label.pkl')

print(data.head())

# 인코딩 및 스케일링
for column in ['protocol_type', 'service', 'flag']:
    le = LabelEncoder()
    data[column] = le.fit_transform(data[column])
    joblib.dump(le, f'model_artifacts/le_{column}.pkl')

scaler = MinMaxScaler()
X = data.drop(['label'], axis=1)
# X = data[common_features]
X = scaler.fit_transform(X)
joblib.dump(scaler, 'model_artifacts/scaler.pkl')

# dos = data[data['label'] == 0]
# normal = data[data['label'] == 1]
# probe = data[data['label'] == 2]
# u2r = data[data['label'] == 3]
# r2l = data[data['label'] == 4]

# data = pd.concat([dos, normal, probe, u2r, r2l])

# #오버 샘플링
# from imblearn.over_sampling import SMOTE
# smote = SMOTE(random_state=42)
# X_resampled, y_resampled = smote.fit_resample(X, data_labels_one_hot)


# 데이터 분할
X_train, X_test, y_train, y_test = train_test_split(X, data_labels_one_hot, test_size=0.3, random_state=42)

# 모델 입력 형상 변경 (CNN은 3차원 입력을 필요로 함)
X_train = X_train.reshape(X_train.shape[0], X_train.shape[1], 1)
X_test = X_test.reshape(X_test.shape[0], X_test.shape[1], 1)

# CNN-LSTM 하이브리드 모델 구성
# 모델 구성
model = Sequential([
    Conv1D(64, kernel_size=3, padding='same', input_shape=(X_train.shape[1], 1)),
    PReLU(),
    BatchNormalization(),
    Dropout(0.5),

    Conv1D(64, kernel_size=3, padding='same'),
    PReLU(),
    BatchNormalization(),
    Dropout(0.5),

    # LSTM 레이어 추가
    # LSTM(64, return_sequences=True),
    # LSTM(64, return_sequences=False),

    Flatten(),
    Dense(64),
    PReLU(),
    Dropout(0.5),
    Dense(y_train.shape[1], activation='softmax')
])
# 옵티마이저 및 컴파일
# optimizer = Adam(learning_rate=0.0001)
model.compile(optimizer=Adam(), loss='categorical_crossentropy', metrics=['accuracy'])

# 조기 종료 설정
early_stopping = EarlyStopping(monitor='val_accuracy', patience=100, restore_best_weights=True)

# 모델 훈련
history = model.fit(X_train, y_train, epochs=300, validation_split=0.2, batch_size=64, callbacks=[early_stopping])

# 모델 저장
model.save('model_artifacts/CNN_model.h5')

# 정확도 그래프
plt.plot(history.history['accuracy'])
plt.plot(history.history['val_accuracy'])
plt.title('Model Accuracy')
plt.ylabel('Accuracy')
plt.xlabel('Epoch')
plt.legend(['Train', 'Test'], loc='upper left')
plt.savefig('accuracy_graph.png')
plt.show()

# 손실 그래프
plt.plot(history.history['loss'])
plt.plot(history.history['val_loss'])
plt.title('Model Loss')
plt.ylabel('Loss')
plt.xlabel('Epoch')
plt.legend(['Train', 'Test'], loc='upper left')
plt.savefig('loss_graph.png')
plt.show()

# 모델 평가
loss, accuracy = model.evaluate(X_test, y_test)
print(f'Test Loss: {loss}, Test Accuracy: {accuracy}')

# 히트맵 시각화
y_pred = model.predict(X_test)
y_pred = np.argmax(y_pred, axis=1)
y_true = np.argmax(y_test, axis=1)

confusion_matrix = tf.math.confusion_matrix(labels=y_true, predictions=y_pred).numpy()
plt.figure(figsize=(8, 6))
sns.heatmap(confusion_matrix, annot=True, fmt='d', cmap='Blues')
plt.xlabel('Predicted labels')
plt.ylabel('True labels')
plt.show()

