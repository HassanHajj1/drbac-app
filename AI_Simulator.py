import requests
import random
import csv
from datetime import datetime
# 🌐 Your deployed DRBAC endpoint
URL = "https://drbac-app-1.onrender.com/simulate_login"
# 🧠 Test dataset (balanced, realistic)
legit_users = [
   {"username": "admin", "device": "Windows PC", "location": "Lebanon", "time": "10:00", "ip": "10.0.0.1", "is_attack": False, "reason": "Business hours login from Lebanon"},
   {"username": "hassan", "device": "Mac", "location": "Lebanon", "time": "13:00", "ip": "10.0.0.2", "is_attack": False, "reason": "Regular login during working hours"},
   {"username": "maria", "device": "Windows PC", "location": "Lebanon", "time": "11:30", "ip": "10.0.0.3", "is_attack": False, "reason": "Standard working login"},
   {"username": "fares", "device": "iPhone", "location": "Lebanon", "time": "09:15", "ip": "10.0.0.4", "is_attack": False, "reason": "Morning mobile login"},
   {"username": "jane", "device": "Dell Laptop", "location": "Lebanon", "time": "14:00", "ip": "10.0.0.5", "is_attack": False, "reason": "Afternoon laptop login"},
]
attack_users = [
   {"username": "admin", "device": "Linux VM", "location": "Russia", "time": "03:00", "ip": "185.76.23.5", "is_attack": True, "reason": "Suspicious midnight login"},
   {"username": "maria", "device": "Unknown", "location": "Brazil", "time": "02:00", "ip": "89.12.45.67", "is_attack": True, "reason": "Unknown device from foreign location"},
   {"username": "john", "device": "Tor Browser", "location": "Iran", "time": "00:30", "ip": "37.45.89.1", "is_attack": True, "reason": "Tor access at night"},
   {"username": "hassan", "device": "Android Device", "location": "Syria", "time": "01:00", "ip": "185.44.12.88", "is_attack": True, "reason": "Unusual mobile access at night"},
   {"username": "maria", "device": "iPad", "location": "USA", "time": "02:30", "ip": "99.48.12.12", "is_attack": True, "reason": "Odd login hour and location"},
]
def simulate():
   results = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
   logs = []
   for _ in range(50):  # Legit users
       run_test_case(random.choice(legit_users), results, logs)
   for _ in range(50):  # Attack users
       run_test_case(random.choice(attack_users), results, logs)
   total = sum(results.values())
   accuracy = round(((results["TP"] + results["TN"]) / total) * 100, 2)
   print("\n==== Confusion Matrix ====")
   print(results)
   print(f"🎯 Detection Accuracy: {accuracy}%")
   with open("simulation_results.csv", "w", newline="") as csvfile:
       fieldnames = ["timestamp", "username", "device", "location", "time", "ip", "actual", "risk", "reason", "result"]
       writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
       writer.writeheader()
       writer.writerows(logs)
   print("✅ Results exported to 'simulation_results.csv'")

def run_test_case(user, results, logs):
   user_data = user.copy()
   ground_truth = user_data.pop("is_attack")
   reason = user_data.pop("reason")
   actual_label = "Attack" if ground_truth else "Legit"
   try:
       response = requests.post(URL, json=user_data)
       risk = response.json().get("risk")
   except Exception as e:
       print(f"Error: {e}")
       return
   predicted_attack = (risk == "High")
   # Confusion matrix classification
   if ground_truth and predicted_attack:
       results["TP"] += 1
       detection_reason = "✔️ Correctly blocked attack (TP)"
   elif not ground_truth and predicted_attack:
       results["FP"] += 1
       detection_reason = "⚠️ False alarm on legit user (FP)"
   elif not ground_truth and not predicted_attack:
       results["TN"] += 1
       detection_reason = "✔️ Correctly allowed legit login (TN)"
   else:
       results["FN"] += 1
       detection_reason = "❌ Missed attack (FN)"
   print(f"[{actual_label}] {user_data['username']} ➜ {risk} | Reason: {reason} → {detection_reason}")
   logs.append({
       "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
       "username": user_data["username"],
       "device": user_data["device"],
       "location": user_data["location"],
       "time": user_data["time"],
       "ip": user_data["ip"],
       "actual": actual_label,
       "risk": risk,
       "reason": reason,
       "result": detection_reason
   })

if __name__ == "__main__":
   simulate()