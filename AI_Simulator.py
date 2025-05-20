import requests
import random
import csv
from datetime import datetime
 
# Replace this with your actual Render URL
URL = "https://drbac-app-1.onrender.com/simulate_login"
 
# Full sample user data
users = [
    # ✅ Legit logins
    {"username": "admin", "device": "iPhone", "location": "Lebanon", "time": "10:00", "ip": "10.0.0.1", "is_attack": False},
    {"username": "hassan", "device": "Samsung", "location": "Lebanon", "time": "11:00", "ip": "10.0.0.5", "is_attack": False},
    {"username": "maria", "device": "Macbook", "location": "France", "time": "14:00", "ip": "10.10.10.10", "is_attack": False},
 
    # ⚠️ Suspicious logins (Time, Location, IP)
    {"username": "admin", "device": "Linux VM", "location": "Russia", "time": "03:00", "ip": "185.76.23.5", "is_attack": True},
    {"username": "hassan", "device": "Unknown", "location": "Brazil", "time": "02:00", "ip": "89.12.45.67", "is_attack": True},
    {"username": "john", "device": "Tor Browser", "location": "Iran", "time": "00:30", "ip": "37.45.89.1", "is_attack": True},
 
    # 😬 Suspicious weekend login
    {"username": "admin", "device": "iPhone", "location": "Lebanon", "time": "05:00", "ip": "10.0.0.1", "is_attack": True},
    {"username": "maria", "device": "Samsung", "location": "Germany", "time": "23:00", "ip": "185.44.12.1", "is_attack": True},
 
    # ✅ More legit users
    {"username": "hassan", "device": "Samsung", "location": "Lebanon", "time": "13:00", "ip": "10.1.1.1", "is_attack": False},
    {"username": "admin", "device": "iPhone", "location": "USA", "time": "15:00", "ip": "10.0.0.10", "is_attack": False}
]
 
def simulate():
    results = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    logs = []
 
    for i in range(100):
        original = random.choice(users)
        user = original.copy()
        ground_truth = user.pop("is_attack")
        actual_label = "Attack" if ground_truth else "Legit"
 
        try:
            response = requests.post(URL, json=user)
            risk = response.json().get("risk")
        except Exception as e:
            print(f"Error: {e}")
            continue
 
        predicted_attack = (risk == "High")
 
        # Confusion matrix logic
        if ground_truth and predicted_attack:
            results["TP"] += 1
        elif not ground_truth and predicted_attack:
            results["FP"] += 1
        elif not ground_truth and not predicted_attack:
            results["TN"] += 1
        elif ground_truth and not predicted_attack:
            results["FN"] += 1
 
        # Log each attempt
        logs.append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "username": user.get("username"),
            "device": user.get("device"),
            "location": user.get("location"),
            "time": user.get("time"),
            "ip": user.get("ip"),
            "actual": actual_label,
            "risk": risk
        })
 
        print(f"Simulated login: {user} → Risk: {risk}")
 
    print("\n==== Confusion Matrix ====")
    print(results)
 
    # Export results to CSV
    with open("simulation_results.csv", "w", newline="") as csvfile:
        fieldnames = ["timestamp", "username", "device", "location", "time", "ip", "actual", "risk"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(logs)
 
    print("✅ Results exported to 'simulation_results.csv'")
 
if __name__ == "__main__":
    simulate()