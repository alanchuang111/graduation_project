import torch
import pandas as pd
import numpy as np
from torch.utils.data import Dataset, DataLoader
from sklearn.preprocessing import MinMaxScaler
import joblib

class QUICSequenceDataset(Dataset):
    def __init__(self, csv_file, seq_len=20, is_train=True, scaler_path='scaler.pkl'):
        """
        將 2D 的封包特徵，依照 Flow_ID 轉換成 3D 的時間序列張量 (Tensor)
        - seq_len: 每個連線要看前幾個封包 (預設 20)
        """
        print(f"[*] 載入並構建 LSTM 序列資料集: {csv_file}")
        self.df = pd.read_csv(csv_file)
        self.seq_len = seq_len
        
        # 定義特徵欄位
        self.feature_cols = [
            'Direction', 'Packet_Length', 'IAT', 'Burst_Count', 
            'Burst_Bytes', 'Flow_Up_Bytes', 'Flow_Down_Bytes', 'Up_Down_Ratio'
        ]
        
        # ==========================================
        # 1. 數值預處理 (與 SGAN 相同的邏輯)
        # ==========================================
        skewed_cols = ['IAT', 'Burst_Bytes', 'Flow_Up_Bytes', 'Flow_Down_Bytes', 'Up_Down_Ratio']
        for col in skewed_cols:
            self.df[col] = np.log1p(self.df[col])
            
        cols_to_scale = [c for c in self.feature_cols if c != 'Direction']
        
        if is_train:
            self.scaler = MinMaxScaler(feature_range=(-1, 1))
            self.df[cols_to_scale] = self.scaler.fit_transform(self.df[cols_to_scale])
            joblib.dump(self.scaler, scaler_path)
        else:
            self.scaler = joblib.load(scaler_path)
            self.df[cols_to_scale] = self.scaler.transform(self.df[cols_to_scale])

        # ==========================================
        # 2. 2D 轉 3D (GroupBy Flow_ID + Padding/Truncating)
        # ==========================================
        print(f"[*] 正在將封包按 Flow_ID 進行分組與序列化 (長度={seq_len})...")
        
        # 準備存放 3D 矩陣與標籤的 List
        sequences = []
        labels = []
        
        # 依照連線 ID 分群
        grouped = self.df.groupby('Flow_ID')
        
        for flow_id, group in grouped:
            # 萃取出該連線所有的特徵數值矩陣 (Shape: [封包數, 8])
            flow_features = group[self.feature_cols].values
            
            # 判斷標籤 (假設一條 Flow 的標籤由它的第一個封包決定)
            if 'Label' in group.columns:
                flow_label = group['Label'].iloc[0]
            else:
                flow_label = 0 # 預設為正常
                
            # [核心邏輯] 截斷與補零
            if len(flow_features) >= self.seq_len:
                # 封包太多：只取前 seq_len 個封包 (截斷)
                seq = flow_features[:self.seq_len, :]
            else:
                # 封包太少：在後面補上數值為 0 的空封包 (Padding)
                pad_length = self.seq_len - len(flow_features)
                # 建立一個全為 0 的矩陣來當填充物
                padding_matrix = np.zeros((pad_length, len(self.feature_cols)))
                seq = np.vstack((flow_features, padding_matrix))
            
            sequences.append(seq)
            labels.append(flow_label)

        # 轉換為 PyTorch Tensor (加入 .copy() 避免記憶體唯讀警告)
        self.sequences = torch.FloatTensor(np.array(sequences).copy())
        self.labels = torch.LongTensor(np.array(labels).copy())
        
        print(f"[V] 序列化完成！共產出 {len(self.sequences)} 條連線，張量形狀: {self.sequences.shape}")

    def __len__(self):
        return len(self.sequences)

    def __getitem__(self, idx):
        return self.sequences[idx], self.labels[idx]

# 測試用程式區塊
if __name__ == "__main__":
    # 假設我們載入一個測試檔案
    # 注意檔案路徑，請依據你上一動的修正來調整
    dataset = QUICSequenceDataset('data/combined_features.csv', seq_len=20, is_train=True)
    dataloader = DataLoader(dataset, batch_size=32, shuffle=True)
    
    # 抓取一個 Batch 看看結構
    seqs, lbls = next(iter(dataloader))
    print(f"\n[測試成功] 第一個 Batch 的形狀: {seqs.shape}") 
    # 預期輸出: torch.Size([32, 20, 8]) -> (批次大小, 序列長度, 特徵維度)