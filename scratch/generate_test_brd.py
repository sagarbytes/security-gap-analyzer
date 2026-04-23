from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from pathlib import Path

def generate_brd(output_path):
    c = canvas.Canvas(str(output_path), pagesize=letter)
    width, height = letter
    
    # Title
    c.setFont("Helvetica-Bold", 16)
    c.drawString(72, height - 72, "Business Requirements Document: Nexus Cloud Platform")
    
    c.setFont("Helvetica", 12)
    y = height - 100
    
    sections = [
        ("1. Executive Summary", "This document outlines the security architecture for the Nexus Cloud application."),
        
        ("2. Authorization", "The system implements Role-Based Access Control (RBAC) with three distinct tiers: Global Admin, Project Manager, and Read-Only Viewer. "
                            "Access reviews are conducted quarterly via the Identity Governance portal, and all privilege escalations are recorded."),
        
        ("3. Authentication", "Primary authentication is handled via corporate SSO (OpenID Connect). "
                            "Multi-Factor Authentication (MFA) is strictly enforced for all administrative logins and external developer access using FIDO2 hardware keys."),
        
        ("4. Logging & Monitoring", "All application events and API calls are streamed to a centralized Datadog instance. "
                                   "Logs are retained for 365 days in cold storage (S3) for compliance audits. "
                                   "Real-time alerting is configured for unauthorized access attempts."),
        
        ("5. Application Patching", "The DevOps team follows a tiered patching schedule. Low and Medium vulnerabilities are patched within 30 days. "
                                   "Critical vulnerabilities and Zero-Day exploits are addressed within 48 hours of disclosure."),
        
        ("6. System Hardening", "Infrastructure is provisioned as code (Terraform). All EC2 instances use CIS-hardened Amazon Linux 2 images. "
                                "Non-essential services like Telnet and FTP are disabled by default, and SSH is only accessible via a Bastion host."),
        
        ("7. Compliance Status", "The Nexus platform is designed to be compatible with SOC2 Type II requirements. "
                                 "Annual penetration testing is performed by a third-party security firm."),
    ]
    
    for title, body in sections:
        if y < 100: # New page if needed
            c.showPage()
            y = height - 72
            c.setFont("Helvetica", 12)
            
        c.setFont("Helvetica-Bold", 12)
        c.drawString(72, y, title)
        y -= 20
        
        c.setFont("Helvetica", 11)
        # Simple text wrapping logic
        words = body.split()
        line = ""
        for word in words:
            if c.stringWidth(line + word) < width - 144:
                line += word + " "
            else:
                c.drawString(72, y, line.strip())
                y -= 15
                line = word + " "
        c.drawString(72, y, line.strip())
        y -= 30

    # Note: Session Management is intentionally omitted to test "info not found"
    
    c.save()
    print(f"Generated BRD at: {output_path}")

if __name__ == "__main__":
    out = Path("/Users/sagaryadav/Desktop/security-gap-analyzer/dummy_brd.pdf")
    generate_brd(out)
