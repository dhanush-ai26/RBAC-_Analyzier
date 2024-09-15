import csv
import json
from datetime import datetime, timedelta
from collections import defaultdict
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import os

class RBACComplianceReporter:
    def __init__(self, csv_file_path):
        self.roles = {}
        self.policy_changes = []
        self.access_logs = []
        self.audit_trail = []
        self.compliance_standards = {
            "GDPR": self.check_gdpr_compliance,
            "HIPAA": self.check_hipaa_compliance,
            "SOX": self.check_sox_compliance
        }
        self.load_data_from_csv(csv_file_path)

    def load_data_from_csv(self, csv_file_path):
        with open(csv_file_path, 'r') as csvfile:
            csv_reader = csv.DictReader(csvfile)
            headers = csv_reader.fieldnames

            for row in csv_reader:
                # Assume each row represents an access log
                timestamp = self.parse_timestamp(row.get('timestamp', row.get('date', '')))
                self.access_logs.append({
                    'timestamp': timestamp,
                    'user': row.get('user', ''),
                    'resource': row.get('resource', ''),
                    'action': row.get('action', '')
                })

                # Extract role information if available
                if 'role' in row and 'permissions' in row:
                    self.roles[row['role']] = row['permissions'].split(',')

    def parse_timestamp(self, timestamp_str):
        # Try different date formats
        date_formats = ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d', '%m/%d/%Y %H:%M:%S', '%m/%d/%Y']
        for date_format in date_formats:
            try:
                return datetime.strptime(timestamp_str, date_format)
            except ValueError:
                continue
        return None  # Return None if no format matches

    def generate_report(self, report_type, start_date, end_date):
        if report_type == "IT_ADMIN":
            return self.generate_it_admin_report(start_date, end_date)
        elif report_type == "COMPLIANCE_OFFICER":
            return self.generate_compliance_report(start_date, end_date)
        elif report_type == "EXECUTIVE":
            return self.generate_executive_summary(start_date, end_date)
        else:
            return "Invalid report type"

    def generate_it_admin_report(self, start_date, end_date):
        report = "IT Administrator Report\n"
        report += f"Period: {start_date} to {end_date}\n\n"

        report += "1. Role Permissions:\n"
        for role, permissions in self.roles.items():
            report += f"   {role}: {', '.join(permissions)}\n"

        report += "\n2. Access Logs Summary:\n"
        access_summary = defaultdict(int)
        for access in self.access_logs:
            if start_date <= access['timestamp'] <= end_date:
                access_summary[f"{access['user']} - {access['resource']}"] += 1
        for access, count in access_summary.items():
            report += f"   {access}: {count} accesses\n"

        return report

    def generate_compliance_report(self, start_date, end_date):
        report = "Compliance Report\n"
        report += f"Period: {start_date} to {end_date}\n\n"

        report += "1. Compliance Check Results:\n"
        for standard, check_function in self.compliance_standards.items():
            is_compliant, violations = check_function()
            report += f"   {standard}: {'Compliant' if is_compliant else 'Non-compliant'}\n"
            if not is_compliant:
                for violation in violations:
                    report += f"      - {violation}\n"

        report += "\n2. Access Anomalies:\n"
        anomalies = self.detect_access_anomalies(start_date, end_date)
        for anomaly in anomalies:
            report += f"   {anomaly}\n"

        return report

    def generate_executive_summary(self, start_date, end_date):
        summary = "Executive Summary\n"
        summary += f"Period: {start_date} to {end_date}\n\n"

        total_roles = len(self.roles)
        total_accesses = sum(1 for access in self.access_logs if start_date <= access['timestamp'] <= end_date)

        summary += f"1. Total Roles: {total_roles}\n"
        summary += f"2. Total Access Attempts: {total_accesses}\n"

        compliance_status = all(check()[0] for check in self.compliance_standards.values())
        summary += f"3. Overall Compliance Status: {'Compliant' if compliance_status else 'Non-compliant'}\n"

        anomalies = self.detect_access_anomalies(start_date, end_date)
        summary += f"4. Access Anomalies Detected: {len(anomalies)}\n"

        return summary

    def check_gdpr_compliance(self):
        violations = []
        for role, permissions in self.roles.items():
            if 'read_personal_data' in permissions and 'modify_personal_data' in permissions:
                violations.append(f"Role '{role}' has both read and modify permissions for personal data")
        return len(violations) == 0, violations

    def check_hipaa_compliance(self):
        violations = []
        medical_access_roles = [role for role, perms in self.roles.items() if 'access_medical_records' in perms]
        if len(medical_access_roles) > 2:
            violations.append("Too many roles have access to medical records")
        return len(violations) == 0, violations

    def check_sox_compliance(self):
        violations = []
        for role, permissions in self.roles.items():
            if 'create_financial_report' in permissions and 'approve_financial_report' in permissions:
                violations.append(f"Role '{role}' can both create and approve financial reports")
        return len(violations) == 0, violations

    def detect_access_anomalies(self, start_date, end_date):
        anomalies = []
        access_count = defaultdict(int)
        for access in self.access_logs:
            if start_date <= access['timestamp'] <= end_date:
                key = (access['user'], access['resource'])
                access_count[key] += 1
                if access_count[key] > 100:
                    anomalies.append(
                        f"High access frequency: User '{access['user']}' accessed '{access['resource']}' over 100 times")
        return anomalies

    def generate_pdf_report(self, start_date, end_date, pdf_file_path):
        it_admin_report = self.generate_report("IT_ADMIN", start_date, end_date)
        compliance_report = self.generate_report("COMPLIANCE_OFFICER", start_date, end_date)
        executive_summary = self.generate_report("EXECUTIVE", start_date, end_date)

        # Ensure directory exists
        os.makedirs(os.path.dirname(pdf_file_path), exist_ok=True)

        c = canvas.Canvas(pdf_file_path, pagesize=letter)
        width, height = letter

        reports = [
            ("IT Administrator Report", it_admin_report),
            ("Compliance Officer Report", compliance_report),
            ("Executive Summary", executive_summary)
        ]

        y = height - 40
        for title, report in reports:
            c.setFont("Helvetica-Bold", 12)
            c.drawString(40, y, title)
            y -= 20

            c.setFont("Helvetica", 10)
            for line in report.split("\n"):
                if y < 40:
                    c.showPage()
                    y = height - 40
                c.drawString(40, y, line)
                y -= 14

            y -= 20  # Add some space between reports

        c.save()

# Example usage
csv_file_path = r'C:\Users\kamal\DRBAC\data genetartor05\user_log.csv'
reporter = RBACComplianceReporter(csv_file_path)

# Determine date range from the data
if reporter.access_logs:
    start_date = min(log['timestamp'] for log in reporter.access_logs if log['timestamp'])
    end_date = max(log['timestamp'] for log in reporter.access_logs if log['timestamp'])
else:
    start_date = datetime(2023, 1, 1)
    end_date = datetime(2023, 12, 31)

# Generate PDF report
pdf_file_path = r'C:\Users\kamal\DRBAC\output\rbac_compliance_report.pdf'
reporter.generate_pdf_report(start_date, end_date, pdf_file_path)

print(f"PDF report generated and saved to: {pdf_file_path}")
