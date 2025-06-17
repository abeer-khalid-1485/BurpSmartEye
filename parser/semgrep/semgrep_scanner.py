import subprocess
import json
import os

def load_vuln_db():
    path = os.path.join(os.path.dirname(__file__), '../data/vuln_database.json')
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def run_semgrep_scan(project_path):
    try:
        config_path = os.path.join(os.path.dirname(__file__), 'semgrep_rules.json')
        result = subprocess.run(
            ["semgrep", "--config", config_path, "--json", project_path],
            capture_output=True,
            text=True
        )
        raw_data = json.loads(result.stdout)
        db = load_vuln_db()

        findings = []

        for r in raw_data.get("results", []):
            vuln_id = r["check_id"].lower().replace("_", "-")
            vuln_info = db.get(vuln_id, {})

            findings.append({
                "path": r.get("path", "غير معروف"),
                "name": vuln_info.get("name", r["check_id"]),
                "severity": vuln_info.get("severity", r.get("severity", "LOW")),
                "description": vuln_info.get("description", "لا يوجد وصف."),
                "solution": vuln_info.get("solution", "لم يتم اقتراح حل."),
                "impact": vuln_info.get("category", "عام"),
                "details": r["extra"].get("message", "لا توجد تفاصيل."),
                "references": vuln_info.get("references", [])
            })

        return findings

    except Exception as e:
        return [{"error": f"خطأ أثناء تحليل semgrep: {str(e)}"}]
