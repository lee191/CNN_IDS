import numpy as np
from keras.models import load_model
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
import joblib
import pandas as pd
from GUI import resource_path

#######################
### CNN 모델 예측 함수 ###
#######################


def predict_model(data):
    print(f"데이터 개수: {len(data)}")
    # 모델 및 인코더, 스케일러 불러오기
    model = load_model(resource_path('model_artifacts/CNN_model.h5'))
    le_protocol = joblib.load(resource_path('model_artifacts/le_protocol_type.pkl'))
    le_service = joblib.load(resource_path('model_artifacts/le_service.pkl'))
    le_flag = joblib.load(resource_path('model_artifacts/le_flag.pkl'))
    scaler = joblib.load(resource_path('model_artifacts/scaler.pkl'))
    le_label = joblib.load(resource_path('model_artifacts/le_label.pkl'))

    # DataFrame으로 변환
    if not isinstance(data, pd.DataFrame):
        data = pd.DataFrame([data])
    
    # LabelEncoder를 사용해 인코딩
    data['protocol_type'] = le_protocol.transform(data['protocol_type'].values.reshape(-1))
    data['service'] = le_service.transform(data['service'].values.reshape(-1))
    data['flag'] = le_flag.transform(data['flag'].values.reshape(-1))
    
    # MinMaxScaler를 사용해 스케일링
    X_test_scaled = scaler.transform(data)
    X_test_scaled = X_test_scaled.reshape(X_test_scaled.shape[0], X_test_scaled.shape[1], 1)

    # 모델 예측 및 확률 계산
    predictions = model.predict(X_test_scaled)
    predicted_indices = np.argmax(predictions, axis=1)  # 가장 높은 확률을 가진 클래스의 인덱스
    predicted_probs = np.max(predictions, axis=1)  # 각 예측에 대한 최대 확률
    
    # 확률을 소수점 2자리까지 반올림
    predicted_probs = np.round(predicted_probs, 2)
    predicted_probs = [f"{prob * 100:.2f}%" for prob in predicted_probs]
    
    # 레이블이 NORMAL이 아닌경우 확률이 90% 미만인 경우 NORMAL로 변경
    # for i in range(len(predicted_indices)):
    #     if predicted_indices[i] != 0 and float(predicted_probs[i][:-1]) < 90:
    #         predicted_indices[i] = 1
    #         predicted_probs[i] = '90% 이하'
    
    

    # 예측된 레이블 디코딩
    predicted_labels = le_label.inverse_transform(predicted_indices)


    # 튜플 리스트로 반환
    return list(zip(predicted_labels, predicted_probs))
    

#######################
### DNN 모델 예측 함수 ###
#######################


# def predict_model(data):
#     print(len(data))
#     # 모델 및 인코더, 스케일러 불러오기
#     model = load_model('model_artifacts/DNN_multi_class.h5')
#     le_protocol = joblib.load('model_artifacts/le_protocol_type_DNN.pkl')
#     le_service = joblib.load('model_artifacts/le_service_DNN.pkl')
#     le_flag = joblib.load('model_artifacts/le_flag_DNN.pkl')
#     scaler = joblib.load('model_artifacts/scaler_DNN.pkl')
#     le_label = joblib.load('model_artifacts/le_label_DNN.pkl')


#     # DataFrame으로 변환
#     if not isinstance(data, pd.DataFrame):
#         data = pd.DataFrame([data])
    
#     # LabelEncoder를 사용해 인코딩
#     data['protocol_type'] = le_protocol.transform(data['protocol_type'].values.reshape(-1))
#     data['service'] = le_service.transform(data['service'].values.reshape(-1))
#     data['flag'] = le_flag.transform(data['flag'].values.reshape(-1))
    
#     # MinMaxScaler를 사용해 스케일링
#     X_test_scaled = scaler.transform(data)
#     X_test_scaled = X_test_scaled.reshape(X_test_scaled.shape[0], X_test_scaled.shape[1], 1)

#     # 모델 예측
#     predictions = model.predict(X_test_scaled)
#     predictions = np.argmax(predictions, axis=1)  # 가장 높은 확률을 가진 클래스의 인덱스를 가져옵니다.


#     # 예측된 레이블 디코딩
#     predicted_labels = le_label.inverse_transform(predictions)
    
#     return predicted_labels
