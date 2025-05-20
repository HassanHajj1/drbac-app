import requests
import random
 
# Replace this with your real Render app URL once deployed
URL = "https://drbac-app-1.onrender.com/simulate_login" 
# Define test cases
users = [
    {"username": "admin", "device": "iPhone", "location": "Lebanon", "time": "10:00", "is_attack": False},
    {"username": "admin", "device": "Linux VM", "location": "Russia", "time": "03:00", "is_attack": True},
    {"username": "hassan", "device": "Samsung", "location": "Lebanon", "time": "11:00", "is_attack": False},
    {"username": "hassan", "device": "Unknown", "location": "Brazil", "time": "02:00", "is_attack": True},
    {"username": "john", "device": "Macbook", "location": "Germany", "time": "23:30", "is_attack": True},
    {"username": "maria", "device": "Samsung", "location": "Lebanon", "time": "13:00", "is_attack": False}
]
 
results = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
 
def simulate():
    for i in range(100):
        user = random.choice(users)
        ground_truth = user.pop("is_attack")  # Get actual label
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