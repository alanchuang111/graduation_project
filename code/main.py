import torch
import torch.nn.functional as F
import numpy as np
import pandas as pd
import joblib
import time
import subprocess
import urllib3
from scapy.all import sniff, IP, UDP
from pymisp import PyMISP, MISPEvent
from sgan_model import Discriminator

# 關閉 MISP 自簽憑證警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 系統與 MISP 設定
MISP_URL = 'https://127.0.0.1'
MISP_KEY = 'API_KEY' 
MISP_VERIFYCERT = False

print("正在連線至 MISP")
try:
    misp = PyMISP(MISP_URL, MISP_KEY, MISP_VERIFYCERT)
    print("連線成功！")
except Exception as e:
    print(f"MISP 連線失敗: {e}")
    misp = None

# 模型與狀態追蹤初始化

print("正在載入 SGAN")
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

try:
    SCALER = joblib.load('scaler.pkl')
    NET_D = Discriminator().to(DEVICE)
    NET_D.load_state_dict(torch.load('sgan_discriminator.pth', map_location=DEVICE))
    NET_D.eval()
    print(" SGAN 載入完成！")
except Exception as e:
    print(f"模型載入失敗: {e}")
    exit(1)

CLASSES = ['正常流量 (0)', '惡意攻擊 (1)']
ACTIVE_FLOWS = {}
HANDLED_IPS = set()  # 紀錄已經處置過的 IP，避免重複通報與寫入防火牆

def get_flow_id(ip_layer, udp_layer):
    src, dst = ip_layer.src, ip_layer.dst
    sport, dport = udp_layer.sport, udp_layer.dport
    if src < dst:
        return (src, dst, sport, dport)
    return (dst, src, dport, sport)

# SOAR 與 MISP 模組
def execute_soar_and_report(target_ip, conf_score, threat_type):
    if target_ip in HANDLED_IPS:
        return # 已經處理過，不再重複執行

    print(f"\n正在處理惡意來源: {target_ip}")
    
    # --- 動作 A: 實體防火牆阻斷 (iptables) ---
    drop_cmd = f"sudo iptables -A FORWARD -s {target_ip} -j DROP"
    result = subprocess.run(drop_cmd, shell=True, stderr=subprocess.DEVNULL)
    if result.returncode == 0:
        print(f"iptables 阻斷規則已生效")
    
    # --- 動作 B: MISP 威脅情資通報 ---
    if misp:
        try:
            event = MISPEvent()
            event.info = f'DeepQUIC 偵測到 {threat_type} 攻擊'
            event.distribution = 0 # 0 代表僅限本組織 (Your Organization Only)
            event.threat_level_id = 1 # 1 代表 High (高危險)
            event.analysis = 2 # 2 代表 Completed (分析完成)
            
            # 加入 IP 作為攻擊指標 (IoC)
            event.add_attribute('ip-src', target_ip, comment=f'AI 信心水準: {conf_score:.2f}%')
            
            # 推送至 MISP
            created_event = misp.add_event(event)
            print(f"成功通報 MISP 戰情中心 (Event ID: {created_event['Event']['id']})")
        except Exception as e:
            print(f"MISP 通報失敗: {e}")

    HANDLED_IPS.add(target_ip)
    print("-" * 50)

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
    direction = 1 if ip_layer.src == state['client_ip'] else -1
    
    iat = current_time - state['last_time']
    state['last_time'] = current_time
    
    if direction == 1:
        state['flow_up_bytes'] += packet_length
    else:
        state['flow_down_bytes'] += packet_length
        
    if iat < 0.01:
        state['burst_count'] += 1
        state['burst_bytes'] += packet_length
    else:
        state['burst_count'] = 1
        state['burst_bytes'] = packet_length
        
    state['packet_count'] += 1
    up_down_ratio = state['flow_up_bytes'] / (state['flow_down_bytes'] + 1)
    
    # 每累積 20 個封包推論一次
    if state['packet_count'] % 20 == 0:
        raw_features = [
            direction, packet_length, iat, 
            state['burst_count'], state['burst_bytes'], 
            state['flow_up_bytes'], state['flow_down_bytes'], up_down_ratio
        ]
        trigger_inference(flow_id, raw_features)


# 模型推論與決策模組
def trigger_inference(flow_id, raw_features):
    features = np.array(raw_features, dtype=np.float64)
    skewed_indices = [2, 4, 5, 6, 7]
    features[skewed_indices] = np.log1p(features[skewed_indices])
    
    features_to_scale = features[1:].reshape(1, -1)
    cols = ['Packet_Length', 'IAT', 'Burst_Count', 'Burst_Bytes', 'Flow_Up_Bytes', 'Flow_Down_Bytes', 'Up_Down_Ratio']
    df_to_scale = pd.DataFrame(features_to_scale, columns=cols)
    scaled_features = SCALER.transform(df_to_scale)[0]
    
    final_features = np.insert(scaled_features, 0, features[0])
    tensor_features = torch.FloatTensor(final_features).unsqueeze(0).to(DEVICE)
    
    with torch.no_grad():
        logits = NET_D(tensor_features)
        probabilities = F.softmax(logits, dim=1)
        confidence, pred_class = torch.max(probabilities, dim=1)
        
    conf_score = confidence.item() * 100
    pred_idx = pred_class.item()
    target_ip = flow_id[0]
    
    if pred_idx == 1:
        if conf_score >= 90.0:
            print(f"偵測到已知攻擊 ({target_ip}) | 信心值: {conf_score:.1f}% -> 觸發阻斷")
            # 呼叫 SOAR 與 MISP 模組
            execute_soar_and_report(target_ip, conf_score, "洪水攻擊 (Volumetric)")
        elif conf_score >= 70.0:
            print(f"可疑攻擊 ({target_ip}) | 信心值: {conf_score:.1f}% -> 建議降速 (QoS)")
            # 若未來實作 tc 降速，可在此處呼叫
            
    else:
        print(f"正常流量 ({target_ip})")


# 主程式

if __name__ == "__main__":
    print("正在監聽網卡 QUIC (UDP 443/4433) 流量")
    
    try:
        sniff(iface="enp0s8", filter="udp port 443 or udp port 4433", prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\n系統已關閉。")