import json
import sys
from datetime import datetime

def triage_findings(input_file, output_file):
    try:
        with open(input_file, 'r') as f:
            findings = [json.loads(line) for line in f if line.strip()]
    except:
        print("No findings")
        return

    priority = []
    for f in findings:
        severity = f.get('info', {}).get('severity', 'info').lower()
        name = f.get('info', {}).get('name', 'Unknown')
        host = f.get('host', 'unknown')
        
        score = 0
        if severity == 'critical': score = 100
        elif severity == 'high': score = 70
        elif severity == 'medium': score = 40
        
        priority.append({
            "severity": severity,
            "name": name,
            "host": host,
            "score": score,
            "url": f.get('matched-at', '')
        })

    priority.sort(key=lambda x: x['score'], reverse=True)

    with open(output_file, 'w') as f:
        json.dump({
            "target": "unknown",
            "scan_time": datetime.now().isoformat(),
            "total_findings": len(priority),
            "priority": priority[:20]  # Top 20
        }, f, indent=2)

if __name__ == "__main__":
    if len(sys.argv) > 2:
        triage_findings(sys.argv[1], sys.argv[2])
    else:
        print("Usage: python ai-triage.py input.json output.json")
