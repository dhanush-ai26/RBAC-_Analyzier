import csv
import random
from collections import defaultdict
from datetime import datetime

import matplotlib.pyplot as plt


class RBACRiskScorer:
    def __init__(self, roles, data_sensitivity, historical_incidents, threat_intelligence):
        self.roles = roles
        self.data_sensitivity = data_sensitivity
        self.historical_incidents = historical_incidents
        self.threat_intelligence = threat_intelligence

    def calculate_all_risk_scores(self):
        risk_scores = {}
        for role, data in self.roles.items():
            risk_scores[role] = self.calculate_risk_score(role)
        return risk_scores

    def calculate_risk_score(self, role):
        # Precompute sensitivity scores for all actions in the role's permissions
        sensitivity_score = sum(self.data_sensitivity[action] for action in self.roles[role]["permissions"])

        # Get the number of historical incidents for the role
        incident_score = self.historical_incidents.get(role, 0)

        # Use the current threat level from threat intelligence
        threat_level = self.threat_intelligence["current_threat_level"]

        # Base score is the number of permissions
        base_score = len(self.roles[role]["permissions"])

        # Calculate the risk score
        risk_score = base_score + sensitivity_score + incident_score * threat_level
        return risk_score

    def visualize_risk_levels(self, risk_scores):
        plt.figure(figsize=(10, 5))
        plt.bar(risk_scores.keys(), risk_scores.values())
        plt.xlabel('Role')
        plt.ylabel('Risk Score')
        plt.title('Risk Scores by Role')
        plt.show()

    def update_threat_intelligence(self):
        new_threat_level = random.uniform(1.0, 5.0)
        self.threat_intelligence["current_threat_level"] = new_threat_level
        self.threat_intelligence["last_updated"] = datetime.now()
        return new_threat_level


def load_csv_data(file_path):
    with open(file_path, 'r') as file:
        reader = csv.DictReader(file)
        data = list(reader)
    return data


def process_user_log(log_data):
    roles = defaultdict(lambda: {"permissions": set()})
    data_sensitivity = defaultdict(int)
    historical_incidents = defaultdict(int)
    threat_intelligence = {"current_threat_level": 1.0, "last_updated": datetime.now()}

    for entry in log_data:
        role = entry['role']
        action = entry['action']
        timestamp = datetime.strptime(entry['timestamp'], '%Y-%m-%d %H:%M:%S')

        # Process roles and permissions
        roles[role]["permissions"].add(action)

        # Process data sensitivity (assuming higher frequency means higher sensitivity)
        data_sensitivity[action] += 1

        # Process historical incidents (assuming 'failed' actions are incidents)
        if entry['status'] == 'failed':
            historical_incidents[role] += 1

        # Update threat intelligence (using the most recent entry as the last update)
        if timestamp > threat_intelligence["last_updated"]:
            threat_intelligence["last_updated"] = timestamp

    # Convert sets to lists for JSON serialization
    roles = {k: {"permissions": list(v["permissions"])} for k, v in roles.items()}

    # Normalize data sensitivity
    max_sensitivity = max(data_sensitivity.values(), default=1)
    data_sensitivity = {k: (v / max_sensitivity) * 10 for k, v in data_sensitivity.items()}

    return roles, data_sensitivity, dict(historical_incidents), threat_intelligence


# Load data from CSV file
log_data = load_csv_data(r'C:\Users\kamal\DRBAC\data genetartor05\user_log.csv')

# Process the loaded data
roles, data_sensitivity, historical_incidents, threat_intelligence = process_user_log(log_data)

# Display fetched roles
print("Roles fetched from the file:")
for role in roles.keys():
    print(f" - {role}")

# Create the risk scorer
risk_scorer = RBACRiskScorer(roles, data_sensitivity, historical_incidents, threat_intelligence)

# Calculate initial risk scores
initial_risk_scores = risk_scorer.calculate_all_risk_scores()
print("\nInitial Risk Scores:")
for role, score in initial_risk_scores.items():
    print(f" - {role}: {score:.2f}")

# Visualize initial risk levels
risk_scorer.visualize_risk_levels(initial_risk_scores)

# Simulate a threat intelligence update
new_threat_level = risk_scorer.update_threat_intelligence()
print(f"\nThreat intelligence updated. New threat level: {new_threat_level:.2f}")

# Recalculate risk scores after threat update
updated_risk_scores = risk_scorer.calculate_all_risk_scores()
print("\nUpdated Risk Scores:")
for role, score in updated_risk_scores.items():
    print(f" - {role}: {score:.2f}")

# Display changes in risk scores
print("\nChanges in Risk Scores after Threat Intelligence Update:")
for role in initial_risk_scores.keys():
    change = updated_risk_scores[role] - initial_risk_scores[role]
    print(f" - {role}: {change:.2f}")

# Visualize updated risk levels
risk_scorer.visualize_risk_levels(updated_risk_scores)
