import torch
import pandas as pd
import numpy as np
from torch.utils.data import Dataset, DataLoader
from sklearn.preprocessing import MinMaxScaler
import joblib

class QUICAnomalyDataset(Dataset):
    def __init__(self, csv_file, is_train=True, scaler_path='model/scaler.pkl'):
        """
        初始化資料集並執行正規化與標準化
        """
        print(f"載入資料集: {csv_file}")
        self.df = pd.read_csv(csv_file)
        
        self.feature_cols = [
            'Direction', 'Packet_Length', 'IAT', 'Burst_Count', 
            'Burst_Bytes', 'Flow_Up_Bytes', 'Flow_Down_Bytes', 'Up_Down_Ratio'
        ]
        
        # 針對進行 Log1p 轉換
        skewed_cols = ['IAT', 'Burst_Bytes', 'Flow_Up_Bytes', 'Flow_Down_Bytes', 'Up_Down_Ratio']
        for col in skewed_cols:
            self.df[col] = np.log1p(self.df[col])
            
        # 排除 Direction 對其餘 7 個特徵進行 Min-Max 縮放
        cols_to_scale = [c for c in self.feature_cols if c != 'Direction']
        
        if is_train:

            self.scaler = MinMaxScaler(feature_range=(-1, 1))
            self.df[cols_to_scale] = self.scaler.fit_transform(self.df[cols_to_scale])
            joblib.dump(self.scaler, scaler_path)
            print(f"縮放器已儲存至 {scaler_path}")
        else:

            self.scaler = joblib.load(scaler_path)
            self.df[cols_to_scale] = self.scaler.transform(self.df[cols_to_scale])


        self.features = torch.FloatTensor(self.df[self.feature_cols].values.copy())
        

        if 'Label' in self.df.columns:
            self.labels = torch.LongTensor(self.df['Label'].values.copy())
        else:
            self.labels = torch.zeros(len(self.df), dtype=torch.long) # 預設全為正常

    def __len__(self):
        return len(self.features)

    def __getitem__(self, idx):
        return self.features[idx], self.labels[idx]


if __name__ == "__main__":

    csv_path = 'dataa/Dataset0522.csv'
    dataset = QUICAnomalyDataset(csv_path, is_train=True)
    dataloader = DataLoader(dataset, batch_size=64, shuffle=True)
    

    features, labels = next(iter(dataloader))
    print(f"\nBatch 特徵形狀: {features.shape}") 
    print(f"數值範圍檢查 (需介於 -1 到 1 之間):")
    print(f"最大值: {features.max().item():.4f}")
    print(f"最小值: {features.min().item():.4f}")