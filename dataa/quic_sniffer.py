import argparse
from scapy.all import sniff, wrpcap

def packet_callback(packet):
    """
    每當抓到一個封包時的即時回饋
    """
    # 簡單印出封包長度，讓你知道程式還活著
    print(f"[+] 捕捉到 QUIC 封包，大小: {len(packet)} bytes")

def start_sniffing(interface, output_file, packet_count=0):
    """
    啟動網路監聽
    """
    print(f"[*] 開始在網卡 {interface} 上監聽 QUIC 流量 (UDP Port 4433)...")
    print("[*] 按下 Ctrl+C 停止並儲存檔案。")
    
    try:
        # filter: 只抓 UDP 且 port 是 4433 的封包
        # prn: 每個封包抓到後要執行的 callback
        # store: 設為 True 才會把封包存在記憶體中以便後續存檔
        packets = sniff(iface=interface, filter="udp port 4433", prn=packet_callback, count=packet_count)
        
        print(f"\n[*] 監聽結束，共捕捉到 {len(packets)} 個封包。")
        
        # 將捕捉到的封包寫入 PCAP 檔
        wrpcap(output_file, packets)
        print(f"[V] 成功將流量儲存至 {output_file}")
        
    except KeyboardInterrupt:
        print("\n[*] 使用者強制停止。")
    except Exception as e:
        print(f"[!] 發生錯誤: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DeepQUIC Guard - 流量側錄工具")
    # 請把預設網卡改成你 VM-2 負責連接 VM-1 的那張網卡代號 (例如 enp0s8)
    parser.add_argument("-i", "--iface", type=str, default="enp0s8", help="要監聽的網卡名稱")
    parser.add_argument("-o", "--output", type=str, default="quic_traffic.pcap", help="輸出的 PCAP 檔名")
    
    args = parser.parse_args()
    start_sniffing(args.iface, args.output)
