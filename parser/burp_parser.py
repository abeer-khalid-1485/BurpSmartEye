import xml.etree.ElementTree as ET
import json
import os

VULN_DB_PATH = os.path.join('db', 'vuln_db.json')

def load_vuln_db():
    with open(VULN_DB_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)

def parse_burp_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    vuln_db = load_vuln_db()
    results = []
    seen = set()

    for issue in root.findall(".//issue"):
        name = issue.findtext("name", "غير معروف")
        if name in seen:
            continue
        seen.add(name)

        background = issue.findtext("issueBackground", "").strip()
        severity = issue.findtext("severity", "غير محدد")
        path = issue.findtext("path", "—")
        description = background if background else "لا يوجد وصف من التقرير."

        # مطابقة القاعدة حسب الكلمات المفتاحية
        vuln_key = "DEFAULT"
        for key, data in vuln_db.items():
            keywords = data.get("keywords", [])
            if any(kw.lower() in name.lower() or kw.lower() in background.lower() for kw in keywords):
                vuln_key = key
                break

        vuln_info = vuln_db.get(vuln_key, {})

        print(f"[+] ثغرة مرصودة: {name} - التصنيف المتوقع: {vuln_key}")

        results.append({
            "name": name,
            "severity": severity,
            "path": path,
            "description": description,
            "details": vuln_info.get("description", "لا يوجد تفاصيل."),
            "impact": vuln_info.get("impact", "—"),
            "solution": vuln_info.get("solution", "—"),
            "references": vuln_info.get("references", []),
            "ai_advice": vuln_info.get("ai_advice", "")  # 👈 الحقل الجديد
        })

    return results
