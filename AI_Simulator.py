import requests
import random
 
# Replace this with your real Render app URL once deployed
URL = "https://drbac-app-1.onrender.com/simulate_login" 
# Define test cases
users = [
    # ✅ Legit logins
    {"username": "admin", "device": "iPhone", "location": "Lebanon", "time": "10:00", "ip": "10.0.0.1", "is_attack": False},
    {"username": "hassan", "device": "Samsung", "location": "Lebanon", "time": "11:00", "ip": "10.0.0.5", "is_attack": False},
    {"username": "maria", "device": "Macbook", "location": "France", "time": "14:00", "ip": "10.10.10.10", "is_attack": False},
 
    # ⚠️ Suspicious logins (Time, Location, IP)
    {"username": "admin", "device": "Linux VM", "location": "Russia", "time": "03:00", "ip": "185.76.23.5", "is_attack": True},
    {"username": "hassan", "device": "Unknown", "location": "Brazil", "time": "02:00", "ip": "89.12.45.67", "is_attack": True},
    {"username": "john", "device": "Tor Browser", "location": "Iran", "time": "00:30", "ip": "37.45.89.1", "is_attack": True},
 
    # 😬 Suspicious weekend login (adjust based on today)
    {"username": "admin", "device": "iPhone", "location": "Lebanon", "time": "05:00", "ip": "10.0.0.1", "is_attack": True},
    {"username": "maria", "device": "Samsung", "location": "Germany", "time": "23:00", "ip": "185.44.12.1", "is_attack": True},
 
    # ✅ More legit users
    {"username": "hassan", "device": "Samsung", "location": "Lebanon", "time": "13:00", "ip": "10.1.1.1", "is_attack": False},
    {"username": "admin", "device": "iPhone", "location": "USA", "time": "15:00", "ip": "10.0.0.10", "is_attack": False}
]

results = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
 
def simulate():
    for i in range(100):
        original = random.choice(users)
        user = original.copy()  # Prevent pop() from modifying original list
        ground_truth = user.pop("is_attack")
        try:
            response = requests.post(URL, json=user)
            risk = response.json().get("risk")
        except Exception as e:
            print(f"Error: {e}")
            continue
 
        # Compare system's risk with ground truth
        is_high_risk = risk == "High"
 
        if ground_truth and is_high_risk:
            results["TP"] += 1
        elif not ground_truth and is_high_risk:
            results["FP"] += 1
        elif not ground_truth and not is_high_risk:
            results["TN"] += 1
        elif ground_truth and not is_high_risk:
            results["FN"] += 1
 
        print(f"Simulated login: {user} → Risk: {risk}")
 
    print("\n==== Confusion Matrix ====")
    print(results)
 
if __name__ == "__main__":
    simulate()