import csv
import argparse
from scapy.all import rdpcap, IP, UDP

def extract_features_v2(pcap_file, output_csv):
    print(f"[*] 正在分析 {pcap_file} 並萃取進階特徵 (V2)...")
    packets = rdpcap(pcap_file)
    
    # 紀錄各連線狀態的字典
    flows = {}
    
    with open(output_csv, mode='w', newline='') as file:
        writer = csv.writer(file)
        # 擴充後的特徵標題列
        writer.writerow([
            'Flow_ID', 'Timestamp', 'Direction', 'Packet_Length', 'IAT',
            'Burst_Count', 'Burst_Bytes', 'Flow_Up_Bytes', 'Flow_Down_Bytes', 'Up_Down_Ratio'
        ])
        
        packet_count = 0
        for pkt in packets:
            if IP in pkt and UDP in pkt:
                ip_src = pkt[IP].src
                ip_dst = pkt[IP].dst
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                pkt_time = float(pkt.time)
                pkt_len = len(pkt)
                
                # 建立前向與後向的識別 Key
                forward_key = f"{ip_src}:{sport}->{ip_dst}:{dport}"
                backward_key = f"{ip_dst}:{dport}->{ip_src}:{sport}"
                
                # 初始化或判斷方向
                if forward_key in flows or (forward_key not in flows and backward_key not in flows):
                    if forward_key not in flows:
                        flows[forward_key] = {
                            'last_time': pkt_time,
                            'burst_dir': 1, 'burst_count': 0, 'burst_bytes': 0,
                            'up_bytes': 0, 'down_bytes': 0
                        }
                    flow_id = forward_key
                    direction = 1
                    flow_data = flows[forward_key]
                elif backward_key in flows:
                    flow_id = backward_key
                    direction = -1
                    flow_data = flows[backward_key]
                
                # 計算 IAT (排除第一個封包的計算)
                if flow_data['burst_count'] > 0 or flow_data['down_bytes'] > 0 or flow_data['up_bytes'] > 0:
                    iat = pkt_time - flow_data['last_time']
                else:
                    iat = 0.0
                flow_data['last_time'] = pkt_time
                
                # 累加 Flow 層級的上/下行位元組
                if direction == 1:
                    flow_data['up_bytes'] += pkt_len
                else:
                    flow_data['down_bytes'] += pkt_len
                    
                # 計算上下行比例 (分母加 1 避免除以零錯誤)
                up_down_ratio = flow_data['up_bytes'] / (flow_data['down_bytes'] + 1)
                
                # 計算 Burst (叢發) 層級特徵
                if direction != flow_data['burst_dir']:
                    # 方向改變，重置叢發計數
                    flow_data['burst_dir'] = direction
                    flow_data['burst_count'] = 1
                    flow_data['burst_bytes'] = pkt_len
                else:
                    # 方向相同，持續累加叢發
                    flow_data['burst_count'] += 1
                    flow_data['burst_bytes'] += pkt_len
                
                # 將該封包的當下狀態寫入資料集
                writer.writerow([
                    flow_id, pkt_time, direction, pkt_len, f"{iat:.6f}",
                    flow_data['burst_count'], flow_data['burst_bytes'],
                    flow_data['up_bytes'], flow_data['down_bytes'], f"{up_down_ratio:.4f}"
                ])
                packet_count += 1
                
    print(f"[V] 進階特徵萃取完成！共處理了 {packet_count} 個 UDP 封包。")
    print(f"[V] 豐富化數據已儲存至 {output_csv}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DeepQUIC Guard - 進階流量特徵萃取工具 V2")
    parser.add_argument("-f", "--file", type=str, required=True, help="輸入的 PCAP 檔名")
    parser.add_argument("-o", "--output", type=str, default="features_v2.csv", help="輸出的 CSV 檔名")
    
    args = parser.parse_args()
    extract_features_v2(args.file, args.output)