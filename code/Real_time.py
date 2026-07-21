import torch
import torch.nn.functional as F
import numpy as np
import joblib
from scapy.all import sniff, IP, UDP
import time
from sgan_model import Discriminator  

# 初始化與模型載入
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# 載入特徵縮放器
try:
    SCALER = joblib.load('model/scaler0522.pkl')
    print("成功載入 scaler0522.pkl")
except Exception as e:
    print(f"無法載入縮放器 {e}")
    exit(1)

# 載入 SGAN 判別器
try:
    NET_D = Discriminator().to(DEVICE)
    NET_D.load_state_dict(torch.load('model/sgan0522.pth', map_location=DEVICE))
    NET_D.eval()
    print("載入 SGAN 判別器")
except Exception as e:
    print(f"無法載入模型 {e}")
    exit(1)

# 類別名稱對照表
CLASSES = ['正常流量 (0)', '已知攻擊 (1)', '未知變形 (2)']

# 連線狀態追蹤器
ACTIVE_FLOWS = {}

def get_flow_id(ip_layer, udp_layer):
    src, dst = ip_layer.src, ip_layer.dst
    sport, dport = udp_layer.sport, udp_layer.dport
    
    # 使用排序確保 A-B 與 B-A 產生相同的 Tuple Key
    if src < dst:
        return (src, dst, sport, dport)
    return (dst, src, dport, sport)

# 封包處理與特徵萃取邏輯
def process_packet(packet):
    if not (packet.haslayer(IP) and packet.haslayer(UDP)):
        return

    ip_layer = packet[IP]
    udp_layer = packet[UDP]
    
    if udp_layer.sport not in [443, 4433] and udp_layer.dport not in [443, 4433]:
        return

    flow_id = get_flow_id(ip_layer, udp_layer)
    current_time = time.time()
    packet_length = len(packet)
    
    if flow_id not in ACTIVE_FLOWS:
        ACTIVE_FLOWS[flow_id] = {
            'client_ip': ip_layer.src,
            'last_time': current_time,
            'burst_count': 1,
            'burst_bytes': packet_length,
            'flow_up_bytes': 0,
            'flow_down_bytes': 0,
            'packet_count': 0
        }
    
    state = ACTIVE_FLOWS[flow_id]
    
    # 計算特徵 Direction
    direction = 1 if ip_layer.src == state['client_ip'] else -1
    
    # 計算特徵 IAT
    iat = current_time - state['last_time']
    state['last_time'] = current_time
    
    # 更新累積流量特徵
    if direction == 1:
        state['flow_up_bytes'] += packet_length
    else:
        state['flow_down_bytes'] += packet_length
        
    # Burst邏輯
    if iat < 0.01:
        state['burst_count'] += 1
        state['burst_bytes'] += packet_length
    else:
        state['burst_count'] = 1
        state['burst_bytes'] = packet_length
        
    state['packet_count'] += 1
    
    # 計算特徵 Up_Down_Ratio
    up_down_ratio = state['flow_up_bytes'] / (state['flow_down_bytes'] + 1)
    
    # AI 推論 每 20 個封包推論一次
    if state['packet_count'] % 20 == 0:
        raw_features = [
            direction, packet_length, iat, 
            state['burst_count'], state['burst_bytes'], 
            state['flow_up_bytes'], state['flow_down_bytes'], up_down_ratio
        ]
        trigger_inference(flow_id, raw_features)

# 模型推論與決策模組
def trigger_inference(flow_id, raw_features):
    # 特徵轉換
    features = np.array(raw_features, dtype=np.float64)
    
    skewed_indices = [2, 4, 5, 6, 7]
    features[skewed_indices] = np.log1p(features[skewed_indices])
    
    # Min-Max 正規化
    features_to_scale = features[1:].reshape(1, -1)
    scaled_features = SCALER.transform(features_to_scale)[0]
    
    final_features = np.insert(scaled_features, 0, features[0])
    
    # 轉換為 Tensor 並送入神經網路
    tensor_features = torch.FloatTensor(final_features).unsqueeze(0).to(DEVICE)
    
    with torch.no_grad():
        logits = NET_D(tensor_features)
        probabilities = F.softmax(logits, dim=1)
        confidence, pred_class = torch.max(probabilities, dim=1)
        
    conf_score = confidence.item() * 100
    pred_idx = pred_class.item()
    
    # 決策輸出
    target_ip = flow_id[0]
    if pred_idx in [1, 2] and conf_score > 70.0:
        print(f"\n[威脅告警] 來源 IP: {target_ip}")
        print(f"   => 判定結果: {CLASSES[pred_idx]}")
        print(f"   => 信心水準: {conf_score:.2f}%")
        print(f"   => 建議處置: {'阻斷 (Drop)' if conf_score > 90 else '降速 (QoS)'}")
    else:
        pass


if __name__ == "__main__":
    print("正在監聽網卡上的 QUIC (UDP 443/4433) 流量...")
    print("請使用 Ctrl+C 停止程式\n")
    
    try:
        sniff(filter="udp port 443 or udp port 4433", prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\n系統已安全關閉。")