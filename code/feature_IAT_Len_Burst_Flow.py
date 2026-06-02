import csv
import argparse
from scapy.all import rdpcap, IP, UDP

def extract_features_v5(pcap_file, output_csv, label_value, flow_counter):
    print(f"[*] 正在分析 {pcap_file} 並萃取特徵 (格式對齊版 V5)...")
    packets = rdpcap(pcap_file)
    
    # 紀錄各連線狀態的字典
    flows = {}

    
    with open(output_csv, mode='w', newline='') as file:
        writer = csv.writer(file)
        # 完全依照要求的標題列格式
        writer.writerow([
            'Flow_ID', 'Timestamp', 'Direction', 'Packet_Length', 'IAT',
            'Burst_Count', 'Burst_Bytes', 'Flow_Up_Bytes', 'Flow_Down_Bytes', 'Up_Down_Ratio', 'Label'
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
                
                # 判斷連線歸屬與分配 Flow_ID
                if forward_key in flows or (forward_key not in flows and backward_key not in flows):
                    if forward_key not in flows:
                        flows[forward_key] = {
                            'id': flow_counter,
                            'last_time': pkt_time,
                            'relative_timestamp_ms': 0,
                            'burst_dir': 1, 'burst_count': 0, 'burst_bytes': 0,
                            'up_bytes': 0, 'down_bytes': 0
                        }
                        flow_counter += 1
                        
                    flow_id = flows[forward_key]['id']
                    direction = 1
                    flow_data = flows[forward_key]
                    
                elif backward_key in flows:
                    flow_id = flows[backward_key]['id']
                    direction = -1
                    flow_data = flows[backward_key]
                
                # 計算 IAT (毫秒整數)
                if flow_data['burst_count'] > 0 or flow_data['down_bytes'] > 0 or flow_data['up_bytes'] > 0:
                    iat_sec = pkt_time - flow_data['last_time']
                    iat_ms = int(round(iat_sec * 1000))
                else:
                    iat_ms = 0
                    
                flow_data['last_time'] = pkt_time
                
                # 累加相對時間戳記
                flow_data['relative_timestamp_ms'] += iat_ms
                current_timestamp_ms = flow_data['relative_timestamp_ms']
                
                # 累加 Flow 上/下行位元組
                if direction == 1:
                    flow_data['up_bytes'] += pkt_len
                else:
                    flow_data['down_bytes'] += pkt_len
                    
                # 計算上下行比例
                up_down_ratio = flow_data['up_bytes'] / (flow_data['down_bytes'] + 1)
                
                # 計算叢發特徵
                if direction != flow_data['burst_dir']:
                    flow_data['burst_dir'] = direction
                    flow_data['burst_count'] = 1
                    flow_data['burst_bytes'] = pkt_len
                else:
                    flow_data['burst_count'] += 1
                    flow_data['burst_bytes'] += pkt_len
                
                # 嚴格依照要求格式化輸出
                writer.writerow([
                    flow_id, 
                    f"{float(current_timestamp_ms):.6f}", # Timestamp 轉為小數點後 6 位
                    direction, 
                    pkt_len, 
                    f"{float(iat_ms):.6f}",              # IAT 轉為小數點後 6 位
                    flow_data['burst_count'], 
                    flow_data['burst_bytes'],
                    flow_data['up_bytes'], 
                    flow_data['down_bytes'], 
                    f"{up_down_ratio:.4f}",              # Ratio 轉為小數點後 4 位
                    label_value                          # 新增的 Label 欄位
                ])
                packet_count += 1
                
    print(f"[V] 格式對齊完畢！共處理了 {packet_count} 個 UDP 封包。")
    print(f"[V] 資料集已儲存至 {output_csv}，標籤設定為: {label_value}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DeepQUIC Guard - 流量特徵萃取工具 (標準格式化版)")
    parser.add_argument("-f", "--file", type=str, required=True, help="輸入的 PCAP 檔名")
    parser.add_argument("-o", "--output", type=str, default="dataset_formatted.csv", help="輸出的 CSV 檔名")
    # 新增 label 參數，預設為 0
    parser.add_argument("-l", "--label", type=int, default=0, help="資料集的標籤 (0: 正常流量, 1: 惡意流量)")
    parser.add_argument("-c", "--counter", type=int, default=0, help="Flow_ID 的起始計數")
    
    args = parser.parse_args()
    extract_features_v5(args.file, args.output, args.label, args.counter)
