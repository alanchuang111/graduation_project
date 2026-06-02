import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np


#  參數

FEATURE_DIM = 8        # 特徵維度 
NUM_REAL_CLASSES = 2   # 資料的類別數 0正常 1攻擊
D_OUT_CLASSES = 3      # 判別器輸出維度 0正常 1攻擊 2假資料
LATENT_DIM = 32        # input雜訊維度


# 生成器

class Generator(nn.Module):
    def __init__(self):
        super(Generator, self).__init__()

        self.net = nn.Sequential(
            nn.Linear(LATENT_DIM, 64),
            nn.BatchNorm1d(64),
            nn.LeakyReLU(0.2, inplace=True),
            
            nn.Linear(64, 128),
            nn.BatchNorm1d(128),
            nn.LeakyReLU(0.2, inplace=True),
            
            nn.Linear(128, FEATURE_DIM),
            nn.Tanh() 
        )

    def forward(self, z):
        return self.net(z)


# 判別器

class Discriminator(nn.Module):
    def __init__(self):
        super(Discriminator, self).__init__()

        self.net = nn.Sequential(
            nn.Linear(FEATURE_DIM, 128),
            nn.LeakyReLU(0.2, inplace=True),
            nn.Dropout(0.3), 
            
            nn.Linear(128, 64),
            nn.LeakyReLU(0.2, inplace=True),
            nn.Dropout(0.3),
            
            nn.Linear(64, D_OUT_CLASSES)
        )

    def forward(self, x):
        return self.net(x)


# SGAN 訓練迴圈

def train_sgan(dataloader, num_epochs=100, lr=0.0002):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"使用: {device}")

    # 初始化網路
    netG = Generator().to(device)
    netD = Discriminator().to(device)

    # 損失函數 Cross Entropy

    criterion = nn.CrossEntropyLoss()

    # 優化器
    optimizerD = optim.Adam(netD.parameters(), lr=lr, betas=(0.5, 0.999))
    optimizerG = optim.Adam(netG.parameters(), lr=lr, betas=(0.5, 0.999))

    print("開始訓練 SGAN...")
    
    for epoch in range(num_epochs):
        for i, (real_data, real_labels) in enumerate(dataloader):
            batch_size = real_data.size(0)
            real_data = real_data.to(device)
            real_labels = real_labels.to(device)

            # 更新 判別器

            netD.zero_grad()

            # 訓練真實資料
            output_real = netD(real_data)
            loss_D_real = criterion(output_real, real_labels)
            loss_D_real.backward()

            # 訓練假資料
            noise = torch.randn(batch_size, LATENT_DIM, device=device)
            fake_data = netG(noise)

            fake_labels = torch.full((batch_size,), NUM_REAL_CLASSES, dtype=torch.long, device=device) 
            
            output_fake = netD(fake_data.detach())
            loss_D_fake = criterion(output_fake, fake_labels)
            loss_D_fake.backward()

            # 總結 D 的 Loss 並更新權重
            loss_D = loss_D_real + loss_D_fake
            optimizerD.step()

            # 更新 生成器
            netG.zero_grad()

            trick_labels = torch.zeros(batch_size, dtype=torch.long, device=device)
            
            output_fake_for_G = netD(fake_data)
            loss_G = criterion(output_fake_for_G, trick_labels)
            loss_G.backward()
            
            optimizerG.step()

        # 印出進度
        if (epoch + 1) % 10 == 0:
            print(f"[Epoch {epoch+1}/{num_epochs}] Loss_D: {loss_D.item():.4f} | Loss_G: {loss_G.item():.4f}")

    
    # 儲存判別器
    torch.save(netD.state_dict(), 'model/sgan0522.pth')
    print("模型已儲存為 sgan0522.pth")
    
    return netD