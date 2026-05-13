import os
import time
import random
import subprocess

# --- 設定區 ---
SERVER_URL_BASE = "https://10.10.20.2:4433"
AIOQUIC_CLIENT = "python3 examples/http3_client.py"
# 確保每次執行都是不檢查憑證
CMD_TEMPLATE = f"{AIOQUIC_CLIENT} --insecure {{url}}"

# 模擬的資源池 (權重：80% 機率看小網頁，20% 機率下載大檔案)
RESOURCES = [
    {"path": "/index.html", "weight": 80, "desc": "瀏覽網頁 (小封包)"},
    {"path": "/100mb.bin", "weight": 20, "desc": "下載檔案 (大封包)"}
]

def get_random_resource():
    """根據權重隨機挑選要存取的資源"""
    paths = [r["path"] for r in RESOURCES]
    weights = [r["weight"] for r in RESOURCES]
    chosen_path = random.choices(paths, weights=weights, k=1)[0]
    
    # 找出對應的描述
    desc = next(r["desc"] for r in RESOURCES if r["path"] == chosen_path)
    return chosen_path, desc

def simulate_user(sessions=20):
    print(f"[*] 開始模擬正常人類上網行為，預計執行 {sessions} 次請求...")
    
    for i in range(1, sessions + 1):
        # 1. 決定這次要看什麼
        path, desc = get_random_resource()
        url = f"{SERVER_URL_BASE}{path}"
        
        print(f"\n[+] 第 {i}/{sessions} 次動作: {desc}")
        print(f"    -> 請求網址: {url}")
        
        # 2. 執行請求 (將輸出導向 null 讓終端機保持乾淨)
        cmd = CMD_TEMPLATE.format(url=url)
        try:
            # 使用 subprocess 執行指令，等待它完成
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("    -> 請求完成。")
        except Exception as e:
            print(f"    -> [!] 請求失敗: {e}")
            
        # 3. 模擬人類的「思考時間」 (讀網頁的時間)
        # 如果是最後一次就不需要 sleep 了
        if i < sessions:
            # 使用 uniform 產生 2 到 8 秒的均勻隨機延遲
            # 也可以使用 random.expovariate() 模擬更真實的卜瓦松分佈
            think_time = random.uniform(2.0, 8.0)
            print(f"    -> 模擬閱讀時間... 停頓 {think_time:.2f} 秒")
            time.sleep(think_time)

    print("\n[V] 正常流量模擬結束！")

if __name__ == "__main__":
    # 為了收集足夠的訓練資料，建議至少跑 50 次以上
    # 測試時可以先設為 10 次看效果
    simulate_user(sessions=30)