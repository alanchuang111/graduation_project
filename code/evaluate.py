import torch
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from sklearn.metrics import confusion_matrix, classification_report
from torch.utils.data import DataLoader

# 引入我們之前寫好的模組
from dataset import QUICAnomalyDataset
from sgan_model import Discriminator

def evaluate_and_plot(model_path, test_csv, scaler_path, PLOT_PATH):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"載入測試環境於: {device}")

    # 初始化模型並載入權重
    netD = Discriminator().to(device)
    netD.load_state_dict(torch.load(model_path, map_location=device))
    netD.eval()

    # 2. 載入測試資料集
    test_dataset = QUICAnomalyDataset(test_csv, is_train=False, scaler_path=scaler_path)
    test_loader = DataLoader(test_dataset, batch_size=64, shuffle=False)

    all_preds = []
    all_labels = []

    with torch.no_grad():
        for data, labels in test_loader:
            data = data.to(device)
            
            outputs = netD(data)
            
            _, predicted = torch.max(outputs.data, 1)
            
            predicted[predicted == 2] = 0

            all_preds.extend(predicted.cpu().numpy())
            all_labels.extend(labels.numpy())

    # 計算混淆矩陣

    classes = ['Normal (0)', 'Attack (1)']
    cm = confusion_matrix(all_labels, all_preds, labels=[0, 1])

    # 繪製混淆矩陣
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=classes, yticklabels=classes,
                annot_kws={"size": 14})
    
    plt.title('Confusion Matrix', fontsize=16)
    plt.ylabel('True', fontsize=12)
    plt.xlabel('Predicted', fontsize=12)
    
    # 儲存圖片
    plt.tight_layout()
    plt.savefig(PLOT_PATH, dpi=300)
    
    # 印出分類報告
    print("\n報告\n")
    unique_labels = np.unique(all_labels)
    target_names = [classes[i] for i in unique_labels]
    print(classification_report(all_labels, all_preds, labels=unique_labels, target_names=target_names))

if __name__ == "__main__":

    TEST_CSV_PATH = 'dataa/TestDataset.csv' 
    MODEL_PATH = 'model/sgan0522.pth'
    SCALER_PATH = 'model/scaler0522.pkl'
    PLOT_PATH = 'model/confusion_matrix0522.png'

    evaluate_and_plot(MODEL_PATH, TEST_CSV_PATH, SCALER_PATH, PLOT_PATH)