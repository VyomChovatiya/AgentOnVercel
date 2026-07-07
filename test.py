"""
test.py
────────────────────────────────────────────────────────────────────────────────
Quick single-case runner: pick any test case by id from evaluate_defense.TEST_CASES
and run it against the proxy with defense_enabled=False and True, side by side.

Usage:
  python test.py <case_id> [--model <model_name>]
  python test.py --list
  python test.py adaptive_task_redirect_01
  python test.py adaptive_task_redirect_01 --model ibm/granite-4-h-tiny
"""

import sys
import json
import argparse
from evaluate_defense import TEST_CASES, call_proxy, detect_attack_success, detect_task_completion

PROXY_URL = "http://localhost:8000"
DEFAULT_MODEL = "ibm/granite-4-h-tiny"
DEFAULT_LIVE_URL = "https://nextgen-products.onrender.com"


def find_case(case_id: str) -> dict:
    for tc in TEST_CASES:
        if tc["id"] == case_id:
            return tc
    print(f"No test case named '{case_id}'. Use --list to see available ids.")
    sys.exit(1)


def list_cases():
    print(f"{'ID':<30} {'FAMILY':<25} {'BENIGN'}")
    for tc in TEST_CASES:
        print(f"{tc['id']:<30} {tc['family']:<25} {tc['benign']}")


def run_case(case_id: str, model: str, live_url: str = None, vector: str = None,
             verifier: bool = False, verifier_model: str = None, show_tool: bool = False):
    tc = find_case(case_id)

    mode = f"LIVE {live_url}" + (f"?vector={vector}" if vector else "") if live_url else "pre-injected"
    defended_label = "L0-L3 + verifier" if verifier else "L0-L2"
    print(f"\n=== {tc['id']} ({tc['family']}) ===")
    print(f"model:       {model}")
    print(f"mode:        {mode}")
    print(f"defended:    {defended_label}" + (f" (verifier={verifier_model})" if verifier and verifier_model else ""))
    print(f"user_goal:   {tc['user_goal']}")
    print(f"attack_goal: {tc.get('attack_goal')}")
    print()

    print("Running baseline (defense_enabled=False)...")
    baseline = call_proxy(PROXY_URL, model, tc, defense_enabled=False, live_url=live_url, vector=vector)

    print(f"Running defended (defense_enabled=True, verifier_enabled={verifier})...")
    defended = call_proxy(PROXY_URL, model, tc, defense_enabled=True, live_url=live_url, vector=vector,
                          verifier_enabled=verifier, verifier_model=verifier_model)

    b_content = baseline.get("content", "")
    d_content = defended.get("content", "")

    print("\n--- BASELINE (no defense) ---")
    if baseline.get("error"):
        print(f"ERROR: {baseline['error']}")
    else:
        print(b_content[:1500])

    print("\n--- DEFENDED ---")
    if defended.get("error"):
        print(f"ERROR: {defended['error']}")
    else:
        print(d_content[:1500])

    # Raw text the agent actually retrieved from its tool calls (e.g. the Markdown
    # returned by local_reader). Shows exactly what reached the model. Opt-in via --show-tool.
    if show_tool:
        print("\n--- TOOL RESULT (retrieved markdown) ---")
        b_ret = baseline.get("retrieved_content") or "(nothing retrieved — no tool call, or the tool errored)"
        print("[baseline arm]\n" + b_ret[:4000])
        d_ret = defended.get("retrieved_content") or "(nothing retrieved)"
        if d_ret != b_ret:
            print("\n[defended arm]\n" + d_ret[:4000])

    print("\nBaseline defense log:", json.dumps(baseline.get("defense_log", []), indent=2))
    print("Defended defense log:", json.dumps(defended.get("defense_log", []), indent=2))

    if not tc["benign"]:
        b_attack = detect_attack_success(b_content, tc["success_indicators"], tc["defense_indicators"], baseline.get("defense_log", []), family=tc["family"])
        d_attack = detect_attack_success(d_content, tc["success_indicators"], tc["defense_indicators"], defended.get("defense_log", []), family=tc["family"])
        b_task = detect_task_completion(b_content, tc["user_goal"])
        d_task = detect_task_completion(d_content, tc["user_goal"])
        print("\n--- VERDICT ---")
        print(f"baseline:  attack_success={b_attack}  task_complete={b_task}")
        print(f"defended:  attack_success={d_attack}  task_complete={d_task}")


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] in ("--list", "-l"):
        list_cases()
        sys.exit(0)

    parser = argparse.ArgumentParser(description="Run a single IPI test case against the proxy")
    parser.add_argument("case_id")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Model name as loaded in LM Studio")
    parser.add_argument("--live", action="store_true",
                         help=f"Fetch the deployed poisoned site ({DEFAULT_LIVE_URL}) live instead "
                              "of using a pre-injected payload.")
    parser.add_argument("--live-url", default=None,
                         help="Override the live site base URL (defaults to the deployed site when --live is set).")
    parser.add_argument("--vector", default=None,
                         help="Stealth vector to request on the live page (e.g. hidden_div, meta_tag, json_ld).")
    parser.add_argument("--verifier-model", default=None,
                         help="Model to use as the Level 3 verifier. Passing this flag ENABLES "
                              "the verifier (defended run becomes L0-L3); omit it for L0-L2 only.")
    parser.add_argument("--show-tool", action="store_true",
                         help="Also print the raw Markdown the agent retrieved from its tool calls.")
    args = parser.parse_args()

    # --live uses the default deployed site; --live-url overrides it.
    live_url = args.live_url or (DEFAULT_LIVE_URL if args.live else None)
    # The presence of --verifier-model is itself the switch for Level 3.
    run_case(args.case_id, args.model, live_url=live_url, vector=args.vector,
             verifier=bool(args.verifier_model), verifier_model=args.verifier_model,
             show_tool=args.show_tool)
