from dataset import QUICAnomalyDataset
from torch.utils.data import DataLoader
from sgan_model import train_sgan

def main():
    csv_path = 'dataa/Dataset0522.csv'
    
    # 初始化 Dataset
    dataset = QUICAnomalyDataset(csv_path, is_train=True, scaler_path='model/scaler0522.pkl')
    
    # 建立 DataLoader 
    dataloader = DataLoader(dataset, batch_size=64, shuffle=True)
    
    # SGAN 訓練
    trained_discriminator = train_sgan(dataloader, num_epochs=150, lr=0.0002)

if __name__ == "__main__":
    main()