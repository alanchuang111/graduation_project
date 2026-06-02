import pandas as pd
import ast
import csv
import argparse

def convert_cesnet_to_custom(cesnet_csv, output_csv, max_flows=50000):
    print(f"[*] 正在讀取 CESNET 資料集: {cesnet_csv} ...")
    
    # 增加讀取筆數，因為我們要萃取大量的正常流量
    try:
        df = pd.read_csv(cesnet_csv, nrows=max_flows)
    except Exception as e:
        print(f"[!] 檔案讀取失敗: {e}")
        return
    
    # 【更新點】使用診斷報告中實際存在的正確分類名稱
    benign_categories = [
        'Streaming media', 
        'Social', 
        'Search', 
        'File sharing', 
        'Blogs & News',
        'Instant messaging'
    ]
    
    if 'CATEGORY' in df.columns:
        original_len = len(df)
        df = df[df['CATEGORY'].isin(benign_categories)]
        print(f"[*] 分類過濾完成: 從 {original_len} 筆中挑選出 {len(df)} 條正常 Flow。")
    else:
        print("[!] 找不到 CATEGORY 欄位，停止執行。")
        return
        
    with open(output_csv, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([
            'Flow_ID', 'Timestamp', 'Direction', 'Packet_Length', 'IAT',
            'Burst_Count', 'Burst_Bytes', 'Flow_Up_Bytes', 'Flow_Down_Bytes', 'Up_Down_Ratio', 'Label'
        ])
        
        flow_count = 0
        packet_count = 0
        
        for index, row in df.iterrows():
            flow_id = row['ID']
            
            try:
                ppi = ast.literal_eval(row['PPI'])
                ipts, dirs, sizes = ppi[0], ppi[1], ppi[2]
            except Exception:
                continue # 解析失敗跳過
                
            burst_dir = 0
            burst_count = 0
            burst_bytes = 0
            flow_up_bytes = 0
            flow_down_bytes = 0
            current_time = 0.0 
            
            # 遍歷 Flow 內的封包
            for i in range(len(sizes)):
                iat = ipts[i]
                direction = 1 if dirs[i] == 1 else -1 
                pkt_len = sizes[i]
                current_time += iat
                
                if direction == 1:
                    flow_up_bytes += pkt_len
                else:
                    flow_down_bytes += pkt_len
                
                up_down_ratio = flow_up_bytes / (flow_down_bytes + 1)
                
                if direction != burst_dir:
                    burst_dir = direction
                    burst_count = 1
                    burst_bytes = pkt_len
                else:
                    burst_count += 1
                    burst_bytes += pkt_len
                
                writer.writerow([
                    flow_id, f"{current_time:.6f}", direction, pkt_len, f"{iat:.6f}",
                    burst_count, burst_bytes, flow_up_bytes, flow_down_bytes, f"{up_down_ratio:.4f}", 0
                ])
                packet_count += 1
            
            flow_count += 1
            
            # 每處理 1000 條 Flow 印一次進度
            if flow_count % 1000 == 0:
                print(f"  ...已處理 {flow_count} 條 Flow...")

    print(f"\n[V] 轉換大功告成！")
    print(f"    - 處理的連線數 (Flows): {flow_count}")
    print(f"    - 產出的特徵資料數 (Packets): {packet_count}")
    print(f"    - 黃金訓練集已儲存至: {output_csv}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DeepQUIC Guard - CESNET 資料轉換器 (修正版)")
    parser.add_argument("-f", "--file", type=str, required=True, help="輸入的 CESNET CSV")
    parser.add_argument("-o", "--output", type=str, default="cesnet_aligned.csv", help="輸出的黃金資料集")
    args = parser.parse_args()
    
    convert_cesnet_to_custom(args.file, args.output)