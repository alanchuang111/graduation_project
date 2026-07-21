from pymisp import PyMISP, MISPEvent 
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# MISP 伺服器設定
MISP_URL = 'https://127.0.0.1'
MISP_KEY = 'wVMYwgLoEzDDQ9xajnMpGnJJOsbN67c1bgfVT3v6'
MISP_VERIFYCERT = False

def report_to_misp(attacker_ip, attack_type, confidence_score):
    """
    將 AI 偵測到的威脅自動寫入 MISP 戰情中心
    """
    try:
        print(f"[*] 正在將威脅情資 (IoC) 同步至 MISP...")

        misp = PyMISP(MISP_URL, MISP_KEY, MISP_VERIFYCERT)
        
        # 建立一個新的資安事件 (Event)
        event = MISPEvent()
        event.info = f"DeepQUIC Guard 自動告警: 偵測到 {attack_type}"
        event.distribution = 0 
        event.threat_level_id = 2 if confidence_score < 90 else 1 # 1:High, 2:Medium
        event.analysis = 2 
        

        event.add_attribute('ip-src', attacker_ip, comment=f"AI 信心值: {confidence_score:.2f}%")
        
        # 將包裝好的一整包 Event (包含 IP 特徵) 推送到 MISP
        event = misp.add_event(event, pythonify=True)
        
        print(f"[V] 成功寫入 MISP！事件 ID: {event.id}")
        
    except Exception as e:
        print(f"[!] 無法連線至 MISP: {e}")

# 測試腳本
if __name__ == "__main__":
    # 模擬 SGAN 抓到 VM-1 (10.10.10.2) 正在發動變形攻擊，信心值 96.5%
    report_to_misp('10.10.10.2', 'HTTP/3 Split-and-Delay 變形攻擊', 96.5)