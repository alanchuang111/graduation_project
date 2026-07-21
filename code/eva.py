import torch
import torch.nn.functional as F
import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import classification_report, confusion_matrix
from sgan_model import Discriminator


MODEL_PATH = 'model/sgan0522.pth'
SCALER_PATH = 'model/scaler0522.pkl'
TEST_CSV_PATH = 'dataa/TestDataset.csv' 

CLASSES = ['正常流量 (0)', '已知攻擊 (1)', '未知變形 (2)']

def evaluate_with_confidence(model_path, csv_path, scaler_path):
    print(f"載入測試資料集: {csv_path}")
    

    df = pd.read_csv(csv_path)
    
    if 'Label' not in df.columns:
        print("找不到 Label 欄位")
        y_true = np.zeros(len(df))
    else:
        y_true = df['Label'].values

    feature_cols = [
        'Direction', 'Packet_Length', 'IAT', 'Burst_Count', 
        'Burst_Bytes', 'Flow_Up_Bytes', 'Flow_Down_Bytes', 'Up_Down_Ratio'
    ]
    
    # 數值轉換
    skewed_cols = ['IAT', 'Burst_Bytes', 'Flow_Up_Bytes', 'Flow_Down_Bytes', 'Up_Down_Ratio']
    for col in skewed_cols:
        df[col] = np.log1p(df[col])
        
    cols_to_scale = [c for c in feature_cols if c != 'Direction']
    
    print("載入正規化縮放器...")
    scaler = joblib.load(scaler_path)
    df[cols_to_scale] = scaler.transform(df[cols_to_scale])
    
    # 轉換為 Tensor
    X_tensor = torch.FloatTensor(df[feature_cols].values.copy())

    # ------------------------------------------
    # 3. 載入模型與推論 (加入 Softmax 信心值)
    # ------------------------------------------
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"使用運算裝置: {device}")
    
    model = Discriminator().to(device)
    model.load_state_dict(torch.load(model_path, map_location=device))
    model.eval() # 確保進入評估模式
    
    X_tensor = X_tensor.to(device)
    
    print("信心值推論\n")
    with torch.no_grad():
        logits = model(X_tensor)
        # 套用 Softmax 將 Logits 轉為 0.0 ~ 1.0 的機率分佈
        probabilities = F.softmax(logits, dim=1)
        # 取出最大機率值 (信心值) 與對應的類別索引
        confidences, preds = torch.max(probabilities, dim=1)

    y_pred = preds.cpu().numpy()
    conf_scores = confidences.cpu().numpy() * 100 # 轉為百分比

    # ------------------------------------------
    # 4. 產出分析報告
    # ------------------------------------------
    unique_labels = np.unique(np.concatenate((y_true, y_pred)))
    target_names = [CLASSES[int(i)] for i in unique_labels]

    y_pred_binary = np.where(y_pred == 1, 1, 0)
    
    # 真實標籤不變 (大於 0 的都是真實攻擊)
    y_true_binary = np.where(y_true > 0, 1, 0) 
    
    print("\n防禦率")
    print(classification_report(y_true_binary, y_pred_binary, target_names=['正常 (0)', '惡意 (1)'], zero_division=0))

    # ------------------------------------------
    # 5. SOAR 自動化回應模擬 (基於信心值)
    # ------------------------------------------
    print("SOAR 自動化處置統計\n")

    
    # 修改處：只抓取被模型判定為 1 (已知攻擊) 的索引，2 (未知變形) 已經被放行了，不進入處置
    threat_indices = np.where(y_pred == 1)[0]
    
    if len(threat_indices) > 0:
        threat_confs = conf_scores[threat_indices]
        
        action_drop = np.sum(threat_confs >= 90.0)
        action_qos = np.sum((threat_confs >= 70.0) & (threat_confs < 90.0))
        action_alert = np.sum(threat_confs < 70.0)
        
        total_threats = len(threat_indices)
        avg_conf = np.mean(threat_confs)
        
        print(f"共攔截到 {total_threats} 筆已知威脅流量 (平均信心水準: {avg_conf:.2f}%)\n")
        print(f" [直接阻斷 (Drop)]   > 90% 信心 : {action_drop} 筆 ({action_drop/total_threats*100:.1f}%) -> 將寫入 iptables 並通報 MISP")
        print(f" [流量降速 (QoS)] 70% ~ 90% 信心 : {action_qos} 筆 ({action_qos/total_threats*100:.1f}%) -> 啟動 Traffic Control 限制頻寬")
        print(f" [僅發告警 (Alert)]  < 70% 信心 : {action_alert} 筆 ({action_alert/total_threats*100:.1f}%) -> 寫入日誌，交由人工復判")
        

    else:
        print("本次測試未偵測到任何已知威脅流量。")

        
    print("\n評估完成")

if __name__ == "__main__":
    evaluate_with_confidence(MODEL_PATH, TEST_CSV_PATH, SCALER_PATH)