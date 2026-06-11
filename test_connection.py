import requests

# --- CONFIGURATION ---
# Change this to your friend's EXACT current Wi-Fi IP address
TARGET_IP = "192.168.1.101"
PORT = "1234"
MODEL_NAME = "google/gemma-4-e4b"  # LM Studio usually ignores this and uses whatever is loaded

URL = f"http://{TARGET_IP}:{PORT}/v1/chat/completions"

print("=========================================")
print(f"[*] Testing Connection to: {URL}")
print("=========================================")

payload = {
    "model": MODEL_NAME,
    "messages": [
        {"role": "user", "content": "If you receive this, reply with exactly: 'NETWORK SUCCESS' and nothing else."}
    ],
    "temperature": 0.1,
    "max_tokens": 20
}

try:
    # 5-second timeout so we don't wait forever
    response = requests.post(URL, json=payload, timeout=5)
    response.raise_for_status()

    # Extract OpenAI-formatted response
    reply = response.json()["choices"][0]["message"]["content"]

    print("\n✅ CONNECTION SUCCESSFUL!")
    print(f"🤖 Model Reply: {reply.strip()}")
    print("\nYour computers are talking perfectly. You can now run the main demo script!")

except requests.exceptions.Timeout:
    print("\n❌ ERROR: Connection Timed Out.")
    print("-> Meaning: Your computer found the IP address, but the server didn't answer.")
    print("-> Fix: Ensure LM Studio is actually 'Server On' and their firewall is off.")

except requests.exceptions.ConnectionError as e:
    print("\n❌ ERROR: Connection Refused or No Route.")
    print("-> Meaning: A firewall blocked it, AP Isolation is on, or the IP is completely wrong.")
    print(f"-> Raw Error: {e}")

except Exception as e:
    print(f"\n❌ ERROR: API format mismatch or other issue.")
    print(f"-> Raw Error: {e}")