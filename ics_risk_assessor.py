# مقيّم أمان الأجهزة الصناعية - Industrial Device Risk Assessor
# مستوحى من مبادئ IEC 62443 ومنطق تقييم الخطر في System DA

DEVICES = [
    {"name": "PLC-Pump-01", "open_ports": [502, 22], "default_password": True, "encrypted": False, "firmware_updated": False},
    {"name": "RTU-Pipeline-07", "open_ports": [20000], "default_password": False, "encrypted": False, "firmware_updated": True},
    {"name": "HMI-ControlRoom-02", "open_ports": [3389, 80], "default_password": True, "encrypted": True, "firmware_updated": False},
    {"name": "Sensor-Gateway-11", "open_ports": [443], "default_password": False, "encrypted": True, "firmware_updated": True},
    {"name": "SCADA-Server-01", "open_ports": [445, 1433, 3389], "default_password": False, "encrypted": True, "firmware_updated": False},
]

‎# منافذ خطرة شائعة في البيئات الصناعية
RISKY_PORTS = {
    502: "Modbus (بدون مصادقة)",
    20000: "DNP3",
    23: "Telnet",
    80: "HTTP غير مشفر",
    445: "SMB",
    1433: "SQL Server",
    3389: "RDP",
    22: "SSH",
}

def assess(device):
    score = 0
    findings = []
    recommendations = []

    for port in device["open_ports"]:
        if port in RISKY_PORTS:
            score += 15
            findings.append(f"منفذ مفتوح {port}: {RISKY_PORTS[port]}")
    if any(p in RISKY_PORTS for p in device["open_ports"]):
        recommendations.append("أغلقي المنافذ غير الضرورية وقيّدي الوصول بجدار حماية")

    if device["default_password"]:
        score += 30
        findings.append("كلمة مرور افتراضية")
        recommendations.append("غيّري كلمة المرور فوراً واستخدمي مصادقة قوية")

    if not device["encrypted"]:
        score += 25
        findings.append("الاتصال غير مشفر")
        recommendations.append("فعّلي التشفير (TLS/VPN) لنقل البيانات")

    if not device["firmware_updated"]:
        score += 20
        findings.append("البرنامج الثابت قديم")
        recommendations.append("حدّثي البرنامج الثابت وفق جدول صيانة")

    score = min(score, 100)
    if score >= 70:
        level = "حرج"
    elif score >= 40:
        level = "عالي"
    elif score >= 20:
        level = "متوسط"
    else:
        level = "منخفض"
    return score, level, findings, recommendations

def main():
    results = []
    for d in DEVICES:
        score, level, findings, recs = assess(d)
        results.append((score, level, d["name"], findings, recs))

    results.sort(reverse=True)  # الأخطر أولاً

    print("=" * 50)
    print("تقرير تقييم أمان الأجهزة الصناعية")
    print("=" * 50)
    for score, level, name, findings, recs in results:
        print(f"\n{name} | الخطر: {score}/100 ({level})")
        for f in findings:
            print(f"  - {f}")
        for r in recs:
            print(f"  * التوصية: {r}")

    critical = sum(1 for r in results if r[1] == "حرج")
    print(f"\nالملخص: {len(results)} أجهزة تم فحصها، منها {critical} بمستوى حرج.")

if __name__ == "__main__":
    main()
