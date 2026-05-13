import csv
import argparse
from scapy.all import rdpcap, IP, UDP

def extract_features(pcap_file, output_csv):
    print(f"[*] 正在讀取 {pcap_file} ... (這可能需要一點時間)")
    packets = rdpcap(pcap_file)
    
    # 用來追蹤不同連線 (Flow) 的字典
    flows = {}
    
    # 準備寫入 CSV
    with open(output_csv, mode='w', newline='') as file:
        writer = csv.writer(file)
        # 寫入標題列 (Flow_ID: 五元組, Direction: 1=Client->Server, -1=Server->Client)
        writer.writerow(['Flow_ID', 'Timestamp', 'Direction', 'Packet_Length', 'IAT'])
        
        packet_count = 0
        for pkt in packets:
            # 我們只分析 IP 和 UDP 層的封包
            if IP in pkt and UDP in pkt:
                ip_src = pkt[IP].src
                ip_dst = pkt[IP].dst
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                pkt_time = float(pkt.time)
                pkt_len = len(pkt) # 取得整個封包的大小 (Wire length)
                
                # 判斷連線方向的唯一識別碼 (假設發起方是 Client)
                forward_key = f"{ip_src}:{sport}->{ip_dst}:{dport}"
                backward_key = f"{ip_dst}:{dport}->{ip_src}:{sport}"
                
                # 初始化新的連線 Flow
                if forward_key not in flows and backward_key not in flows:
                    flows[forward_key] = {'last_time': pkt_time}
                    flow_id = forward_key
                    direction = 1  # 1 代表前向 (Client to Server)
                    iat = 0.0      # 第一個封包的 IAT 為 0
                    
                # 已經記錄過的前向連線
                elif forward_key in flows:
                    flow_id = forward_key
                    direction = 1
                    iat = pkt_time - flows[forward_key]['last_time']
                    flows[forward_key]['last_time'] = pkt_time
                    
                # 已經記錄過的後向連線 (Server 回傳給 Client)
                elif backward_key in flows:
                    flow_id = backward_key
                    direction = -1 # -1 代表後向 (Server to Client)
                    iat = pkt_time - flows[backward_key]['last_time']
                    flows[backward_key]['last_time'] = pkt_time
                
                # 寫入 CSV: 保留小數點後 6 位數的 IAT (微秒級別)
                writer.writerow([flow_id, pkt_time, direction, pkt_len, f"{iat:.6f}"])
                packet_count += 1
                
    print(f"[V] 特徵萃取完成！共處理了 {packet_count} 個 UDP 封包。")
    print(f"[V] 結果已儲存至 {output_csv}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DeepQUIC Guard - 流量特徵萃取工具")
    parser.add_argument("-f", "--file", type=str, required=True, help="輸入的 PCAP 檔名")
    parser.add_argument("-o", "--output", type=str, default="features.csv", help="輸出的 CSV 檔名")
    
    args = parser.parse_args()
    extract_features(args.file, args.output)