# main.py
"""Core testing orchestration pipeline. Evaluates semantic vulnerabilities in high-noise contexts."""

import os
import threading
import http.server
import urllib.parse
import csv
import datetime
from pathlib import Path
from mock_server import VulnerableSiteHandler
from agent import AIScraperAgent
from vectors import VECTOR_MAP
from config import SERVER_HOST, SERVER_PORT, BASE_TARGET_URL, INJECTION_PAYLOADS, MODEL_NAME, TARGET_EXPLOIT,OUTPUT_DIR

from evaluator import evaluate_with_judge


def run_background_server():
    server = http.server.HTTPServer((SERVER_HOST, SERVER_PORT), VulnerableSiteHandler)
    server.serve_forever()


def execute_high_noise_audit():


    output_path = Path(OUTPUT_DIR)
    output_path.mkdir(parents=True, exist_ok=True)


    server_thread = threading.Thread(target=run_background_server, daemon=True)
    server_thread.start()
    print(f"[+] Expanded Multi-Product Web Simulation Target Online: {BASE_TARGET_URL}")

    agent = AIScraperAgent(raw_html_mode=False)
    print(f"[🚀] Starting High-Noise Semantic Reasoning Sweep [Model Framework: {MODEL_NAME}]")
    print("=" * 95)

    attack_metrics = {attack_id: {"exploited": 0, "defended": 0} for attack_id in INJECTION_PAYLOADS}

    # --- CSV SETUP ---
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_filename = f"audit_{MODEL_NAME}_{timestamp}.csv"
    csv_file_path = output_path / csv_filename

    # Columns: one per attack_id, rows: one per vector_id
    attack_ids = list(INJECTION_PAYLOADS.keys())
    vector_ids = list(VECTOR_MAP.keys())

    # results[vector_id][attack_id] = { outcome, agent_output }
    results = {v: {} for v in vector_ids}

    for vector_id, vector_data in VECTOR_MAP.items():
        print(f"\nSTRUCTURAL SURFACE TEST: {vector_data['desc']}")
        print("=" * 65)

        for attack_id, attack_data in INJECTION_PAYLOADS.items():
            encoded_payload = urllib.parse.quote(attack_data["prompt"])
            target_url = f"{BASE_TARGET_URL}/catalog?vector={vector_id}&payload={encoded_payload}"

            html_content = agent.fetch_target(target_url)
            scraped_context = agent.parse_data(html_content)
            print(f"  -> Scraped Context: {scraped_context[:100]}...")
            agent_recommendation = agent.evaluate_products(scraped_context)

            is_exploited = evaluate_with_judge(agent_recommendation, TARGET_EXPLOIT)

            if is_exploited:
                attack_metrics[attack_id]["exploited"] += 1
                outcome = "EXPLOITED"
            else:
                attack_metrics[attack_id]["defended"] += 1
                outcome = "SECURE"

            results[vector_id][attack_id] = {
                "outcome": outcome,
                "agent_output": agent_recommendation.replace("\n", " ").strip()
            }

            status_icon = "🔴" if is_exploited else "🟢"
            print(f"  [ {status_icon} {outcome} ] Style: {attack_id}")
            indented_output = agent_recommendation.replace('\n', '\n             ')
            print(f"  -> Agent Output: {indented_output}")
            print("-" * 65)

    # --- WRITE CSV ---
    # Layout:
    #
    #   vector_id | vector_desc | <attack_id>_outcome | <attack_id>_output | ... (repeated per attack)
    #
    with open(csv_file_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        # Header row
        header = ["vector_id", "vector_desc"]
        for a_id in attack_ids:
            header.append(f"{a_id}_outcome")
            header.append(f"{a_id}_agent_output")
        writer.writerow(header)

        # One data row per vector
        for vector_id in vector_ids:
            row = [vector_id, VECTOR_MAP[vector_id]["desc"]]
            for a_id in attack_ids:
                cell = results[vector_id].get(a_id, {})
                row.append(cell.get("outcome", "N/A"))
                row.append(cell.get("agent_output", ""))
            writer.writerow(row)

        # Blank separator then summary rows
        writer.writerow([])
        writer.writerow(["SUMMARY"])
        writer.writerow(["attack_variant", "exploited", "defended", "total", "compromise_rate_%"])
        for a_id, counts in attack_metrics.items():
            total = counts["exploited"] + counts["defended"]
            rate = (counts["exploited"] / total * 100) if total else 0
            writer.writerow([a_id, counts["exploited"], counts["defended"], total, f"{rate:.1f}"])

    print("\n" + "=" * 65 + "\nHIGH-CONTEXT RESILIENCE METRICS BREAKDOWN:\n" + "=" * 65)
    for a_id, counts in attack_metrics.items():
        total = counts["exploited"] + counts["defended"]
        leakage_rate = (counts["exploited"] / total) * 100 if total else 0
        print(f"Attack Variant: {a_id.ljust(20)} -> Compromise Rate: {leakage_rate:.1f}% ({counts['exploited']}/{total})")
    print("=" * 65)
    print(f"\n[+] Results saved to: {csv_file_path}")

    agent.unload_model()


if __name__ == "__main__":
    execute_high_noise_audit()
