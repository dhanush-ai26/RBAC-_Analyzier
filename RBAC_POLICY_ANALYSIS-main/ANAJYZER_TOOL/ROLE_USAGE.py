import json
from datetime import datetime, timedelta
from pathlib import Path


class RBACPolicyScorer:
    def __init__(self, roles, usage_log, sod_rules):
        self.roles = roles
        self.usage_log = usage_log
        self.sod_rules = sod_rules

    def calculate_permission_utilization_rate(self):
        utilization_rates = {}
        for role, details in self.roles.items():
            total_permissions = len(details["permissions"])
            used_permissions = sum(
                any(self.usage_log.get(perm, {}).values()) for perm in details["permissions"]
            )
            utilization_rates[role] = used_permissions / total_permissions if total_permissions else 0
        return utilization_rates

    def calculate_role_complexity_score(self):
        complexity_scores = {}
        for role, details in self.roles.items():
            user_count = len(details["users"])
            permission_count = len(details["permissions"])
            complexity_scores[role] = permission_count * user_count
        return complexity_scores

    def check_segregation_of_duties(self):
        sod_violations = {}
        for role1, role2 in self.sod_rules:
            users_with_both_roles = set(self.roles[role1]["users"]).intersection(self.roles[role2]["users"])
            if users_with_both_roles:
                for user in users_with_both_roles:
                    if user not in sod_violations:
                        sod_violations[user] = []
                    sod_violations[user].append((role1, role2))
        return sod_violations

    def identify_unused_permissions(self):
        unused_permissions = {}
        cutoff_date = datetime.now() - timedelta(days=90)
        for role, details in self.roles.items():
            unused_permissions[role] = [
                perm for perm in details["permissions"]
                if not any(date > cutoff_date for date in self.usage_log.get(perm, {}).values())
            ]
        return unused_permissions

    def find_overlapping_roles(self):
        overlapping_roles = []
        roles = list(self.roles.keys())
        for i in range(len(roles)):
            for j in range(i + 1, len(roles)):
                role1, role2 = roles[i], roles[j]
                permissions1, permissions2 = set(self.roles[role1]["permissions"]), set(
                    self.roles[role2]["permissions"])
                overlap = len(permissions1 & permissions2) / len(permissions1 | permissions2)
                if overlap > 0.8:
                    overlapping_roles.append((role1, role2, overlap))
        return overlapping_roles

    def evaluate_policy_effectiveness(self):
        utilization_rates = self.calculate_permission_utilization_rate()
        complexity_scores = self.calculate_role_complexity_score()
        sod_violations = self.check_segregation_of_duties()
        unused_permissions = self.identify_unused_permissions()
        overlapping_roles = self.find_overlapping_roles()

        print("1. Permission Utilization Rates:")
        for role, rate in utilization_rates.items():
            print(f"   {role}: {rate:.2%}")

        print("\n2. Role Complexity Scores:")
        for role, score in complexity_scores.items():
            print(f"   {role}: {score:.2f}")

        print("\n3. Segregation of Duties Violations:")
        for user, violations in sod_violations.items():
            print(f"   {user}: {violations}")

        print("\n4. Unused Permissions (last 90 days):")
        for role, permissions in unused_permissions.items():
            print(f"   {role}: {permissions}")

        print("\n5. Overlapping Roles (>80% shared permissions):")
        for role1, role2, overlap in overlapping_roles:
            print(f"   {role1} and {role2}: {overlap:.2%} overlap")


def main():
    input_file_path = Path(r'C:\Users\kamal\DRBAC\rbac_policy.json')

    if input_file_path.is_file():
        with open(input_file_path, "r") as file:
            data = json.load(file)
            roles = data["roles"]
            usage_log = {k: {user: datetime.strptime(date, "%Y-%m-%d") for user, date in v.items()} for k, v in
                         data["usage_log"].items()}
            sod_rules = data["sod_rules"]

            scorer = RBACPolicyScorer(roles, usage_log, sod_rules)
            scorer.evaluate_policy_effectiveness()
    else:
        print(f"Input file '{input_file_path}' not found.")


if __name__ == "__main__":
    main()
