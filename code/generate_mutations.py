import torch
import pandas as pd
import numpy as np
import joblib
from lstm_dataset import QUICSequenceDataset
from lstm_mutator import LSTMAdversarialMutator

def generate_mutated_csv(input_csv, output_csv, scaler_path, intensity=0.1):
    print("[*] 步驟 1: 載入序列資料與縮放器")
    # 注意：is_train=False 代表我們只使用已經訓練好的 Scaler，不重新 Fit
    dataset = QUICSequenceDataset(input_csv, seq_len=20, is_train=False, scaler_path=scaler_path)
    scaler = joblib.load(scaler_path)
    
    # 找出所有標籤為 1 (攻擊) 的索引
    attack_indices = torch.where(dataset.labels == 1)[0]
    if len(attack_indices) == 0:
        print("[!] 找不到任何攻擊流量 (Label == 1)，請確認輸入的資料集。")
        return
        
    original_attacks = dataset.sequences[attack_indices]
    print(f"[*] 找到 {len(original_attacks)} 條攻擊連線，準備進行 LSTM 變形...")

    print(f"[*] 步驟 2: 啟動 LSTM 變異器 (變形強度 = {intensity})")
    mutator = LSTMAdversarialMutator(feature_dim=8, hidden_dim=64, seq_len=20)
    
    # 實務提示：若是正式實驗，應先將 mutator 訓練為 Autoencoder。
    # 這裡我們直接利用神經網路的隨機初始化權重與高斯雜訊來產生變形。
    mutator.eval() 
    
    with torch.no_grad():
        # 產生變形流量 (Shape: [Batch, 20, 8])
        mutated_attacks = mutator(original_attacks, mutation_intensity=intensity)
    
    print("[*] 步驟 3: 數學反向轉換 (神經網路空間 -> 真實物理空間)")
    # 將 3D 張量展平回 2D，準備寫入 CSV
    mutated_2d = mutated_attacks.numpy().reshape(-1, 8)
    
    feature_cols = [
        'Direction', 'Packet_Length', 'IAT', 'Burst_Count', 
        'Burst_Bytes', 'Flow_Up_Bytes', 'Flow_Down_Bytes', 'Up_Down_Ratio'
    ]
    df_mutated = pd.DataFrame(mutated_2d, columns=feature_cols)
    
    # 3.1 分離 Direction (不參與縮放) 與其他特徵
    cols_to_scale = [c for c in feature_cols if c != 'Direction']
    
    # 3.2 反向 Min-Max 縮放 (從 [-1, 1] 變回 Log 空間)
    df_mutated[cols_to_scale] = scaler.inverse_transform(df_mutated[cols_to_scale])
    
    # 3.3 反向 Log1p 轉換 (使用 expm1 變回真實的 Bytes 和 Seconds)
    skewed_cols = ['IAT', 'Burst_Bytes', 'Flow_Up_Bytes', 'Flow_Down_Bytes', 'Up_Down_Ratio']
    for col in skewed_cols:
        df_mutated[col] = np.expm1(df_mutated[col])
        
    # 3.4 物理合理性清理 (Packet Size 不能是小數點，IAT 不能是負數)
    df_mutated['Direction'] = df_mutated['Direction'].apply(lambda x: 1 if x >= 0 else -1)
    int_cols = ['Packet_Length', 'Burst_Count', 'Burst_Bytes', 'Flow_Up_Bytes', 'Flow_Down_Bytes']
    for col in int_cols:
        # 四捨五入並限制最小值為 0
        df_mutated[col] = df_mutated[col].round().clip(lower=0).astype(int)
    
    df_mutated['IAT'] = df_mutated['IAT'].clip(lower=0.0)

    print("[*] 步驟 4: 重建連線特徵與計算真實 Timestamp")
    # 4.1 為每 20 個封包編配一個新的虛擬 Flow_ID
    num_flows = len(original_attacks)
    flow_ids = [i+50490 for i in range(num_flows) for _ in range(20)]
    df_mutated.insert(0, 'Flow_ID', flow_ids)
    
    # 4.2 利用 IAT 計算時間戳 (Timestamp)
    # 假設這批變形攻擊發生在一個特定的起始時間 (可以自訂 Epoch Time)
    base_timestamp = 0.0 
    
    # 使用 Pandas 的 groupby 和 cumsum (累加)，計算該連線從第 1 個到第 20 個封包經過的總時間
    cumulative_time = df_mutated.groupby('Flow_ID')['IAT'].cumsum()
    
    # Timestamp = 起始時間 + 累積時間差
    df_mutated.insert(1, 'Timestamp', base_timestamp + cumulative_time)
    
    # 4.3 標記為攻擊 (1)
    df_mutated['Label'] = 1
    
    # 儲存檔案
    df_mutated.to_csv(output_csv, index=False)
    print(f"[V] 成功！已生成 {len(df_mutated)} 筆極具欺騙性的變形封包，儲存至 {output_csv}")

if __name__ == "__main__":
    # 執行生成腳本
    generate_mutated_csv(
        input_csv='dataa/Dataset0522.csv',    # 來源：你原本結合好的資料集
        output_csv='dataa/mutated_attacks_v1.csv',  # 輸出：第一代變形攻擊
        scaler_path='model/scaler0522.pkl',                  # 依賴：之前訓練好的縮放器
        intensity=0.15                             # 變形強度 (可隨意調整 0.05 ~ 0.5 測試)
    )