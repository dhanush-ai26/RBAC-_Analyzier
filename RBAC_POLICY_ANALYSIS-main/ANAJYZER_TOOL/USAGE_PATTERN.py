from datetime import datetime

import pandas as pd


def identify_unused_permissions(roles, usage_log, days_threshold=90):
    today = datetime.now()
    unused_permissions = {}

    for role, data in roles.items():
        unused = []
        for permission in data['permissions']:
            if permission not in usage_log:
                unused.append(permission)
            else:
                last_used = max(usage_log[permission].values())
                if (today - last_used).days > days_threshold:
                    unused.append(permission)

        if unused:
            unused_permissions[role] = unused

    return unused_permissions


def detect_overlapping_roles(roles, overlap_threshold=0.8):
    overlapping_roles = []
    role_names = list(roles.keys())

    for i in range(len(role_names)):
        for j in range(i + 1, len(role_names)):
            role1 = set(roles[role_names[i]]['permissions'])
            role2 = set(roles[role_names[j]]['permissions'])

            overlap = len(role1.intersection(role2)) / len(role1.union(role2))

            if overlap >= overlap_threshold:
                overlapping_roles.append((role_names[i], role_names[j], overlap))

    return overlapping_roles


def find_least_privilege_violations(roles, required_permissions):
    violations = {}

    for role, data in roles.items():
        extra_permissions = set(data['permissions']) - set(required_permissions.get(role, []))
        if extra_permissions:
            violations[role] = list(extra_permissions)

    return violations


def analyze_permission_usage_patterns(roles, usage_log, days_threshold=30):
    today = datetime.now()
    usage_patterns = {}

    for role, data in roles.items():
        permission_usage = {}
        for permission in data['permissions']:
            if permission in usage_log:
                recent_usage = [user for user, date in usage_log[permission].items()
                                if (today - date).days <= days_threshold]
                usage_ratio = len(recent_usage) / len(data['users'])
                permission_usage[permission] = usage_ratio
            else:
                permission_usage[permission] = 0

        usage_patterns[role] = permission_usage

    return usage_patterns


def analyze_rbac_policies_from_csv(csv_path):
    df = pd.read_csv(csv_path)

    # Dynamically detect column names
    role_col = None
    permission_col = None
    user_col = None
    last_used_col = None

    for col in df.columns:
        if 'role' in col.lower():
            role_col = col
        elif 'permission' in col.lower():
            permission_col = col
        elif 'user' in col.lower():
            user_col = col
        elif 'last' in col.lower() and 'used' in col.lower():
            last_used_col = col

    if not (role_col and permission_col and user_col and last_used_col):
        raise ValueError("CSV file must contain columns for Role, Permission, User, and LastUsed.")

    # Extracting roles
    roles = {}
    usage_log = {}

    for _, row in df.iterrows():
        role = row[role_col]
        permission = row[permission_col]
        user = row[user_col]
        last_used = datetime.strptime(row[last_used_col], '%Y-%m-%d')

        if role not in roles:
            roles[role] = {'permissions': set(), 'users': set()}

        roles[role]['permissions'].add(permission)
        roles[role]['users'].add(user)

        if permission not in usage_log:
            usage_log[permission] = {}

        usage_log[permission][user] = last_used

    # Example required permissions (this could be extracted from another source if needed)
    required_permissions = {
        "role1": ["p1", "p2"],
        "role2": ["p2", "p3"],
        "role3": ["p3", "p4", "p5"]
    }

    unused_permissions = identify_unused_permissions(roles, usage_log)
    overlapping_roles = detect_overlapping_roles(roles)
    least_privilege_violations = find_least_privilege_violations(roles, required_permissions)
    permission_usage_patterns = analyze_permission_usage_patterns(roles, usage_log)

    print("1. Unused Permissions:")
    for role, permissions in unused_permissions.items():
        print(f"  - {role}: {', '.join(permissions)}")

    print("\n2. Overlapping Roles:")
    if overlapping_roles:
        for role1, role2, overlap in overlapping_roles:
            print(f"  - {role1} and {role2}: {overlap:.2%} overlap")
    else:
        print("  - None")

    print("\n3. Least Privilege Violations:")
    for role, permissions in least_privilege_violations.items():
        print(f"  - {role}: {', '.join(permissions)}")

    print("\n4. Permission Usage Patterns:")
    for role, patterns in permission_usage_patterns.items():
        print(f"  - {role}:")
        for permission, ratio in patterns.items():
            print(f"    - {permission}: {ratio:.2%}")


# Example usage
csv_path = r'C:\Users\kamal\DRBAC\rbac_policy_logs.csv'  # Path to your CSV file
analyze_rbac_policies_from_csv(csv_path)
