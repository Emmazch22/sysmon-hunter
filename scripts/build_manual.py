"""Build the Sysmon Hunter user manual as a black-and-white, professional PDF."""

from __future__ import annotations

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
)
from reportlab.platypus.flowables import Flowable

VERSION = "0.3.4"
DOC_TITLE = "Sysmon Hunter — User Manual"
OUT_PATH = "Sysmon_Hunter_Manual.pdf"

BLACK = colors.HexColor("#111111")
GRAY_DARK = colors.HexColor("#3a3a3a")
GRAY_MID = colors.HexColor("#6b6b6b")
GRAY_LIGHT = colors.HexColor("#9a9a9a")
GRAY_RULE = colors.HexColor("#c9c9c9")
GRAY_FILL = colors.HexColor("#f0f0f0")
GRAY_FILL2 = colors.HexColor("#e2e2e2")
WHITE = colors.white

PAGE_W, PAGE_H = A4
MARGIN_L = 22 * mm
MARGIN_R = 22 * mm
MARGIN_T = 30 * mm
MARGIN_B = 22 * mm


def draw_logo(c: pdfcanvas.Canvas, cx: float, cy: float, size: float, stroke=BLACK, fill=None):
    """Draw the shield mark centred at (cx, cy), `size` points tall."""
    c.saveState()
    c.translate(cx, cy)
    scale = size / 32.0
    c.scale(scale, scale)
    c.setLineWidth(1.6)
    c.setStrokeColor(stroke)
    c.setFillColor(fill if fill else colors.white)

    p = c.beginPath()
    p.moveTo(0, 12)
    p.curveTo(4.2, 10.2, 4.5, 10.0, 4.5, 6.4)
    p.lineTo(4.5, -0.6)
    p.curveTo(4.5, -6.4, 1.6, -9.9, 0, -11.5)
    p.curveTo(-1.6, -9.9, -4.5, -6.4, -4.5, -0.6)
    p.lineTo(-4.5, 6.4)
    p.curveTo(-4.5, 10.0, -4.2, 10.2, 0, 12)
    p.close()
    c.setLineJoin(1)
    c.drawPath(p, stroke=1, fill=0)

    c.setLineWidth(1.4)
    c.circle(0, 1, 2.5, stroke=1, fill=0)
    c.line(0, -1.5, 0, -4.5)
    c.restoreState()


class LogoFlowable(Flowable):
    def __init__(self, size=42 * mm):
        super().__init__()
        self.size = size
        self.width = size
        self.height = size

    def draw(self):
        draw_logo(self.canv, self.size / 2, self.size / 2, self.size, stroke=BLACK)


def draw_cover(c: pdfcanvas.Canvas, doc):
    c.saveState()
    c.setFillColor(WHITE)
    c.rect(0, 0, PAGE_W, PAGE_H, stroke=0, fill=1)

    c.setStrokeColor(GRAY_RULE)
    c.setLineWidth(0.8)
    c.rect(14 * mm, 14 * mm, PAGE_W - 28 * mm, PAGE_H - 28 * mm, stroke=1, fill=0)

    cx = PAGE_W / 2
    draw_logo(c, cx, PAGE_H - 78 * mm, 30 * mm, stroke=BLACK)

    c.setFillColor(BLACK)
    c.setFont("Helvetica-Bold", 30)
    c.drawCentredString(cx, PAGE_H - 100 * mm, "SYSMON HUNTER")

    c.setFont("Helvetica", 13)
    c.setFillColor(GRAY_DARK)
    c.drawCentredString(cx, PAGE_H - 109 * mm, "Detection Engineering & Analyst Console")

    c.setLineWidth(0.6)
    c.setStrokeColor(GRAY_LIGHT)
    c.line(cx - 30 * mm, PAGE_H - 116 * mm, cx + 30 * mm, PAGE_H - 116 * mm)

    c.setFont("Helvetica", 11)
    c.setFillColor(GRAY_MID)
    c.drawCentredString(cx, PAGE_H - 124 * mm, "User Manual")

    c.setFont("Helvetica-Bold", 11)
    c.setFillColor(BLACK)
    c.drawCentredString(cx, PAGE_H - 145 * mm, f"Version {VERSION}")

    c.setFont("Helvetica", 9)
    c.setFillColor(GRAY_MID)
    c.drawCentredString(cx, PAGE_H - 151 * mm, "Real-time Sysmon detection, correlation, and incident triage")

    c.setFont("Helvetica", 8)
    c.setFillColor(GRAY_LIGHT)
    c.drawCentredString(cx, 22 * mm, "Sysmon Hunter is a detection-engineering research project.")
    c.drawCentredString(cx, 18 * mm, "This manual documents the console and detection engine as of the version above.")

    c.restoreState()


def draw_header_footer(c: pdfcanvas.Canvas, doc):
    c.saveState()
    page_num = c.getPageNumber()

    draw_logo(c, MARGIN_L + 3 * mm, PAGE_H - 16 * mm, 7 * mm, stroke=GRAY_DARK)
    c.setFont("Helvetica-Bold", 8.5)
    c.setFillColor(GRAY_DARK)
    c.drawString(MARGIN_L + 9 * mm, PAGE_H - 14.6 * mm, "SYSMON HUNTER")
    c.setFont("Helvetica", 8)
    c.setFillColor(GRAY_LIGHT)
    c.drawRightString(PAGE_W - MARGIN_R, PAGE_H - 14.6 * mm, f"User Manual · v{VERSION}")
    c.setStrokeColor(GRAY_RULE)
    c.setLineWidth(0.6)
    c.line(MARGIN_L, PAGE_H - 19 * mm, PAGE_W - MARGIN_R, PAGE_H - 19 * mm)

    c.line(MARGIN_L, 15 * mm, PAGE_W - MARGIN_R, 15 * mm)
    c.setFont("Helvetica", 8)
    c.setFillColor(GRAY_LIGHT)
    c.drawString(MARGIN_L, 11 * mm, "sysmon-hunter")
    c.drawRightString(PAGE_W - MARGIN_R, 11 * mm, f"Page {page_num - 1}")
    c.restoreState()


ss = getSampleStyleSheet()

styles = {
    "H1": ParagraphStyle("H1", parent=ss["Heading1"], fontName="Helvetica-Bold",
                          fontSize=17, leading=21, spaceBefore=6, spaceAfter=10,
                          textColor=BLACK, keepWithNext=True),
    "H2": ParagraphStyle("H2", parent=ss["Heading2"], fontName="Helvetica-Bold",
                          fontSize=12.5, leading=16, spaceBefore=14, spaceAfter=6,
                          textColor=BLACK, keepWithNext=True),
    "H3": ParagraphStyle("H3", parent=ss["Heading3"], fontName="Helvetica-Bold",
                          fontSize=10.5, leading=14, spaceBefore=10, spaceAfter=4,
                          textColor=GRAY_DARK, keepWithNext=True),
    "Body": ParagraphStyle("Body", parent=ss["Normal"], fontName="Helvetica",
                            fontSize=9.6, leading=14, spaceAfter=7,
                            textColor=BLACK, alignment=TA_JUSTIFY),
    "BodyTight": ParagraphStyle("BodyTight", parent=ss["Normal"], fontName="Helvetica",
                                 fontSize=9.2, leading=12.5, spaceAfter=3,
                                 textColor=BLACK),
    "Bullet": ParagraphStyle("Bullet", parent=ss["Normal"], fontName="Helvetica",
                              fontSize=9.6, leading=13.6, spaceAfter=5,
                              leftIndent=12, bulletIndent=0, textColor=BLACK),
    "Mono": ParagraphStyle("Mono", parent=ss["Normal"], fontName="Courier",
                            fontSize=8.4, leading=12, textColor=BLACK,
                            backColor=GRAY_FILL, borderPadding=6, spaceAfter=8),
    "Caption": ParagraphStyle("Caption", parent=ss["Normal"], fontName="Helvetica-Oblique",
                               fontSize=8.3, leading=11, textColor=GRAY_MID, spaceAfter=8),
    "TOC1": ParagraphStyle("TOC1", fontName="Helvetica-Bold", fontSize=10.5,
                            textColor=BLACK, leftIndent=0, spaceBefore=8, spaceAfter=2),
    "TOC2": ParagraphStyle("TOC2", fontName="Helvetica", fontSize=9.6,
                            textColor=GRAY_DARK, leftIndent=12, spaceAfter=2),
}


def H1(text):
    return Paragraph(text, styles["H1"])


def H2(text):
    return Paragraph(text, styles["H2"])


def H3(text):
    return Paragraph(text, styles["H3"])


def P(text):
    return Paragraph(text, styles["Body"])


def bullets(items):
    return [Paragraph(f"&#8226;&nbsp;&nbsp;{it}", styles["Bullet"]) for it in items]


def rule(space_before=4, space_after=10):
    return [Spacer(1, space_before),
            HRFlowable(width="100%", thickness=0.6, color=GRAY_RULE,
                       spaceBefore=0, spaceAfter=space_after)]


RULES = [
    ("SYS-001", "1", "High", "Office application spawned a command interpreter", "T1566.001, T1059"),
    ("SYS-002", "1", "High", "PowerShell executed an encoded command", "T1059.001, T1027"),
    ("SYS-003", "1", "High", "LOLBin used to download a remote payload", "T1105, T1218"),
    ("SYS-004", "1", "Critical", "Volume shadow copies deleted", "T1490"),
    ("SYS-005", "1", "High", "Script engine spawned from a browser or mail client", "T1204.002, T1566"),
    ("SYS-006", "1", "Medium", "Executable ran from a user-writable staging path", "T1204"),
    ("SYS-007", "1", "High", "System binary running from the wrong path", "T1036.005"),
    ("SYS-008", "1", "Medium", "rundll32 executed without a DLL argument", "T1218.011"),
    ("SYS-009", "1", "High", "PowerShell download cradle", "T1059.001, T1105"),
    ("SYS-010", "10", "Critical", "Suspicious process accessed LSASS memory", "T1003.001"),
    ("SYS-020", "3", "Medium", "Scripting or LOLBin process made an outbound connection", "T1071"),
    ("SYS-021", "3", "Medium", "Connection to a common C2 port from a non-browser process", "T1571"),
    ("SYS-030", "13", "High", "Autorun registry key modified", "T1547.001"),
    ("SYS-031", "13", "High", "Windows Defender setting disabled via registry", "T1685"),
    ("SYS-032", "13", "High", "Image File Execution Options debugger set", "T1546.012"),
    ("SYS-034", "1", "High", "Control panel item (.cpl) executed from a user-writable path", "T1218.002"),
    ("SYS-035", "1", "High", "Script host executing an encoded script", "T1059.005, T1059.007, T1027"),
    ("SYS-036", "1", "High", "Script host spawned by rundll32", "T1059, T1218.011"),
    ("SYS-037", "1", "High", "rundll32 invoking a known LOLBAS DLL export", "T1218.011, T1204.001"),
    ("SYS-038", "1", "High", "IIS credentials extracted via appcmd", "T1552.001, T1003"),
    ("SYS-039", "1", "Medium", "appcmd executed by a web server worker or script host", "T1552.001"),
    ("SYS-040", "7", "High", "PowerShell engine loaded by a non-PowerShell process", "T1059.001"),
    ("SYS-041", "10", "Critical", "LSASS opened with credential-dumping access rights", "T1003.001"),
    ("SYS-050", "11", "High", "File dropped into a Startup folder", "T1547.001"),
    ("SYS-051", "11", "High", "Office application wrote a script or executable", "T1566.001"),
    ("SYS-060", "17", "High", "Named pipe matching a known C2 default", "T1071, T1055"),
    ("SYS-070", "1", "Medium", "WMI persistence staged via mofcomp or wmic", "T1546.003"),
    ("SYS-071", "20", "High", "WMI event consumer registered for code execution", "T1546.003"),
    ("SYS-072", "17", "High", "Named pipe matching PsExec-style remote execution", "T1021.002, T1569.002"),
    ("SYS-073", "1", "High", "PsExec service binary executed on this host", "T1569.002, T1021.002"),
    ("SYS-074", "1", "High", "Regsvr32 registering a scriptlet via scrobj.dll (Squiblydoo)", "T1218.010"),
    ("SYS-075", "1", "Medium", "Certutil used to decode or encode a local file", "T1140"),
    ("SYS-076", "1", "Medium", "BITS job created via the Start-BitsTransfer cmdlet", "T1197"),
    ("SYS-077", "6", "High", "Unsigned kernel driver loaded", "T1211, T1562.001"),
    ("SYS-078", "13", "High", "Registry Run key written by the WMI provider host", "T1047, T1547.001"),
    ("SYS-079", "1", "High", "FTP client spawned a child process", "T1105, T1202"),
    ("SYS-080", "11", "Critical", "Ransom note dropped", "T1486, T1491.001"),
    ("SYS-081", "11", "Critical", "File written with a known ransomware encryption extension", "T1486"),
    ("SYS-082", "1", "Critical", "Credential dumping via comsvcs.dll MiniDump export", "T1003.001"),
    ("SYS-083", "13", "High", "Fileless UAC bypass via auto-elevate registry hijack", "T1548.002"),
    ("SYS-084", "1", "High", "cmstp executed with a silent or auto-install flag", "T1218.003"),
    ("SYS-085", "13", "High", "Port forwarding rule added via netsh", "T1090.001"),
    ("SYS-086", "13", "High", "PowerShell script block logging disabled via registry", "T1562.001"),
    ("SYS-087", "12", "High", "PowerShell Constrained Language Mode lockdown policy removed", "T1562.001"),
    ("SYS-088", "1", "Critical", "IIS worker process spawned a command shell", "T1505.003"),
    ("SYS-089", "1", "Critical", "SQL Server process spawned a command shell", "T1059.003, T1190"),
    ("SYS-090", "1", "Medium", "Process spawned by the PowerShell remoting host", "T1021.006"),
    ("SYS-091", "13", "Medium", "Local account or administrators-group membership changed in the SAM hive", "T1136.001, T1098"),
    ("SYS-092", "1", "High", "PE metadata claims a trusted binary, but it runs from a staging path", "T1036.005"),
    ("SYS-093", "1", "High", "Scheduled task created via schtasks", "T1053.005"),
    ("SYS-094", "13", "High", "New service image path points at a user-writable staging location", "T1543.003"),
    ("SYS-095", "8", "Critical", "Remote thread created inside LSASS", "T1055, T1003.001"),
    ("SYS-096", "1", "High", "Firewall rule added to allow inbound traffic", "T1562.004"),
    ("SYS-097", "1", "High", "Windows event log cleared via wevtutil", "T1070.001"),
    ("SYS-098", "1", "Medium", "Archive utility invoked with a password, staging data for exfiltration", "T1560.001"),
    ("SYS-099", "1", "High", ".NET installer utility executed from a user-writable staging path", "T1218.004, T1218.009"),
    ("SYS-100", "1", "High", "mshta executed a remote HTA", "T1218.005"),
    ("SYS-101", "1", "Medium", "Compiled HTML Help opened from a user-writable staging path", "T1218.001"),
    ("SYS-102", "1", "High", "msiexec installed a package from a remote URL", "T1218.007"),
    ("SYS-103", "1", "Medium", "Account added to the local Administrators group via net.exe", "T1098, T1136.001"),
    ("SYS-104", "1", "High", "A security or update service was stopped from the command line", "T1489, T1562.001"),
    ("SYS-105", "1", "High", "Sysinternals sdelete executed", "T1070.004"),
    ("SYS-106", "1", "Medium", "cipher used to wipe free disk space", "T1070.004"),
    ("SYS-107", "13", "Medium", "Remote Desktop enabled via registry", "T1021.001"),
    ("SYS-108", "1", "Critical", "Credential hive saved to disk via reg.exe", "T1003.002"),
    ("SYS-109", "1", "Critical", "Sysinternals procdump run against LSASS", "T1003.001"),
    ("SYS-110", "1", "Critical", "NTDS.dit extracted via ntdsutil", "T1003.003"),
    ("SYS-111", "1", "High", "mavinject used to inject into a running process", "T1055.001"),
    ("SYS-112", "1", "Medium", "WSL used to execute a command outside its Linux filesystem", "T1202, T1059.004"),
    ("SYS-113", "1", "High", "MSBuild ran a project file staged in a user-writable path", "T1127.001"),
    ("SYS-114", "1", "Medium", "Uncommon signed proxy-execution binary run against a staged target", "T1218, T1216"),
    ("SYS-115", "1", "High", "RDP session hijacked via tscon", "T1563.002"),
    ("SYS-116", "1", "High", "Active Directory reconnaissance tool executed", "T1087, T1482"),
    ("SYS-117", "1", "Medium", "Cloud sync/transfer tool executed", "T1567.002"),
    ("SYS-118", "1", "High", "Kerberoasting tooling executed", "T1558.003"),
    ("SYS-119", "1", "High", "PowerShell launched in version-2 downgrade mode", "T1059.001"),
    ("SYS-120", "1", "High", "Command line references a known AMSI-bypass signature", "T1562.001"),
    ("SYS-121", "1", "Medium", "bitsadmin used to transfer a file", "T1197"),
    ("SYS-122", "13", "High", "CLSID InprocServer32 handler registered under a user's own hive", "T1546.015"),
    ("SYS-123", "1", "High", "Command line references a known privilege-escalation token-theft tool", "T1134"),
    ("SYS-124", "22", "Medium", "DNS query to a dynamic DNS domain", "T1071.004, T1568"),
    ("SYS-125", "23", "Medium", "Executable deleted from a staging path shortly after being dropped", "T1070.004"),
    ("SYS-126", "25", "Critical", "Process image tampering detected (hollowing or doppelganging)", "T1055.012, T1055.013"),
    ("SYS-127", "15", "High", "Executable content staged inside an NTFS alternate data stream", "T1564.004"),
    ("SYS-128", "9", "High", "Raw volume access by a process outside known disk utilities", "T1006"),
    ("SYS-129", "2", "Medium", "File creation timestamp changed outside a servicing process", "T1070.006"),
    ("SYS-130", "1", "Critical", "DCSync-style directory replication requested from a command line", "T1003.006"),
    ("SYS-131", "1", "Critical", "Command line references a known Mimikatz module or command", "T1003.001"),
    ("SYS-132", "1", "High", "Odbcconf used as a signed proxy-execution binary", "T1218.008"),
    ("SYS-133", "1", "High", "mmc.exe loaded a Management Saved Console from a staging path", "T1218.014"),
    ("SYS-135", "11", "High", "Non-browser process touched a browser credential database", "T1555.003"),
    ("SYS-136", "11", "High", "Script interpreter touched a KeePass database", "T1555"),
    ("SYS-137", "11", "High", "Browser credential database written into a staging directory", "T1555.003"),
    ("SYS-138", "1", "Medium", "Network configuration discovery command executed", "T1016"),
    ("SYS-139", "1", "Medium", "Active network connections enumerated via netstat", "T1049"),
    ("SYS-140", "1", "Medium", "Recursive filesystem enumeration executed", "T1083"),
    ("SYS-141", "1", "High", "Security or EDR product enumerated from the command line", "T1518.001"),
    ("SYS-142", "1", "Medium", "Archive created with its header/file-list encrypted", "T1560.001"),
    ("SYS-143", "1", "High", "Rclone ran a copy/sync against a remote destination", "T1567.002"),
    ("SYS-144", "1", "High", "Command-line tooling uploaded a file to a remote server", "T1048"),
    ("SYS-148", "1", "High", "SharpHound invoked via script or named by its collection arguments", "T1482"),
    ("SYS-149", "1", "Medium", "Active Directory account or group enumeration command executed", "T1087"),
    ("SYS-150", "1", "High", "AS-REP roasting tooling executed", "T1558.004"),
    ("SYS-151", "1", "High", "ClickFix/FileFix decoy verification lure pasted from Explorer", "T1204.004"),
    ("SYS-152", "1", "High", "PowerShell launched from Explorer with bypass + hidden window", "T1204.004"),
    ("SYS-153", "1", "High", "Script host from Explorer immediately fetching remote code", "T1204.004"),
    ("SYS-154", "1", "High", "PowerShell reads and executes clipboard contents", "T1204.004"),
    ("SYS-155", "1", "High", "Remote-access/RMM software launched from a non-Explorer parent", "T1219"),
    ("SYS-156", "1", "High", "Remote-access/RMM software installed with a silent flag", "T1219"),
    ("SYS-157", "1", "High", "PowerShell reads and overwrites the clipboard (crypto-clipper)", "T1115"),
    ("SYS-158", "1", "High", "Problem Steps Recorder invoked for silent screen capture", "T1113"),
    ("SYS-159", "1", "High", "Chat-service webhook or bot API used as a covert channel", "T1102"),
    ("SYS-160", "1", "High", "Public paste service used as a C2 dead-drop", "T1102"),
    ("SYS-161", "1", "Medium", "Archive utility packaged a broad user data directory", "T1074"),
    ("SYS-162", "1", "Medium", "robocopy mass-mirrored a broad user directory tree", "T1119, T1074"),
    ("SYS-163", "1", "Critical", "Rubeus used to pass or renew a Kerberos ticket", "T1550.003"),
    ("SYS-164", "1", "Critical", "Mimikatz used to pass a hash or a Kerberos ticket", "T1550.002, T1550.003"),
    ("SYS-165", "1", "Critical", "Known Group Policy abuse tooling or cmdlet invoked", "T1484.001"),
    ("SYS-166", "1", "Critical", "Domain trust modified to disable SID-filtering protections", "T1484.002"),
    ("SYS-167", "1", "Critical", "Command-line destructive wipe of a broad user directory or volume", "T1485"),
    ("SYS-168", "1", "Critical", "PowerShell bulk-disabled or reset a broad set of AD accounts", "T1531"),
    ("SYS-169", "11", "Critical", "Script interpreter staged a cloud CLI credential file", "T1552.001"),
    ("SYS-170", "1", "Critical", "Cloud instance metadata service queried by a non-agent process", "T1552.005"),
    ("SYS-171", "11", "High", "Script interpreter staged an SSH or PuTTY private key", "T1552.004"),
    ("SYS-172", "1", "High", "WMI used to create a process via Win32_Process", "T1047"),
    ("SYS-173", "1", "High", "mmc.exe spawned a shell consistent with MMC20.Application DCOM abuse", "T1021.003"),
    ("SYS-174", "1", "High", "Docker container launched with --privileged", "T1611"),
    ("SYS-175", "11", "Critical", "Accessibility binary replaced on disk", "T1546.008"),
    ("SYS-176", "13", "High", "Winlogon helper DLL persistence key set", "T1547.004"),
    ("SYS-177", "13", "High", "Security Support Provider registered", "T1547.005"),
    ("SYS-178", "13", "High", "Active Setup StubPath persistence key set", "T1547.014"),
    ("SYS-179", "1", "High", "Domain account created", "T1136.002"),
    ("SYS-180", "1", "Critical", "Boot configured into Safe Mode", "T1562.009"),
    ("SYS-181", "1", "High", "Windows Event Log service or channel disabled", "T1562.002"),
    ("SYS-182", "1", "High", "Disk image mounted via PowerShell", "T1204.003"),
    ("SYS-183", "1", "Critical", "Mimikatz used to dump LSA secrets or cached domain credentials", "T1003.004/.005"),
    ("SYS-184", "1", "Critical", "Mimikatz used to forge a Kerberos golden ticket", "T1558.001"),
    ("SYS-185", "11", "High", "File written with a double extension masking an executable", "T1036.007"),
    ("SYS-186", "1", "High", "Registry queried for an autologon or default password", "T1552.002"),
    ("SYS-187", "1", "Critical", "Group Policy Preferences cpassword harvested", "T1552.006"),
    ("SYS-188", "1", "High", "SSH client used with a private key for lateral movement", "T1021.004"),
    ("SYS-189", "1", "High", "Tor or a multi-hop proxy tool launched", "T1090.003"),
    ("SYS-190", "1", "High", "PowerShell archived data via .NET compression", "T1560.002"),
    ("SYS-191", "16", "Critical", "Sysmon configuration reloaded", "T1562.001/.006"),
    ("SYS-192", "19", "High", "WMI event filter registered", "T1546.003"),
    ("SYS-193", "21", "High", "WMI filter bound to a consumer", "T1546.003"),
    ("SYS-194", "18", "High", "Named pipe connected matching a known C2/lateral-movement signature", "T1071/T1055/T1021.002/T1569.002"),
    ("SYS-195", "24", "Medium", "Clipboard accessed by a scripting engine or LOLBIN", "T1115"),
    ("SYS-196", "14", "High", "Persistence-relevant registry key renamed", "T1112/T1564.001"),
]

EVENT_ID_NAMES = {
    "1": "Process Create", "3": "Network Connection", "6": "Driver Load",
    "7": "Image Load", "8": "Remote Thread Created", "10": "Process Access",
    "11": "File Create", "12": "Registry Create/Delete", "13": "Registry Set",
    "17": "Pipe Created", "20": "WMI Event",
}

API_ROUTES = [
    ("POST", "/ingest", "Accept one normalized Sysmon/Winlogbeat event; runs it through the full pipeline."),
    ("GET", "/incidents", "List incidents, most recent first."),
    ("GET", "/incidents/{id}", "Full incident detail: detections, process tree, forensics."),
    ("PUT", "/incidents/{id}/status", "Close an incident, mark it a false positive, or reopen it."),
    ("PUT", "/incidents/{id}/notes", "Set the incident's analyst note (500-word limit)."),
    ("DELETE", "/incidents/{id}/notes", "Clear the incident's analyst note."),
    ("GET", "/incidents/{id}/profile", "Kill-chain narrative summary for the incident."),
    ("GET", "/incidents/{id}/report", "Generate and download the incident's PDF report."),
    ("GET", "/incidents/{id}/stix", "Generate and download the incident as a STIX 2.1 bundle."),
    ("GET", "/detections", "List raw detections, most recent first."),
    ("GET", "/search", "Free-text and field-filtered search across incidents."),
    ("GET", "/attack/coverage", "Rule-coverage report: rule/detector count per ATT&amp;CK technique."),
    ("GET", "/attack/coverage/navigator", "The coverage report as a downloadable MITRE ATT&amp;CK Navigator layer."),
    ("GET", "/attack/{technique_id}", "MITRE ATT&amp;CK technique description, from the local dataset."),
    ("GET", "/stats", "Dashboard aggregates: incidents/day, severity mix, triage totals, top rules and techniques."),
    ("GET", "/enrich", "On-demand reputation lookup for an IP, domain, or hash."),
    ("DELETE", "/admin/database", "Wipe all detections and incidents; reset the live engine."),
    ("POST", "/admin/rules/import-sigma", "Convert and load one or more Sigma YAML files; live immediately."),
    ("GET", "/health", "Liveness/readiness probe: rule count, tracked processes."),
    ("GET", "/metrics", "Prometheus text-exposition scrape target: request, ingest, and detection counters."),
    ("WS", "/ws", "Live event stream: new detections, incident updates, resets."),
    ("GET", "/", "The analyst console (single page app)."),
    ("GET", "/incident/{id}", "Full-page view of one incident, with notes editor."),
    ("GET", "/incident/{id}/explore", "Full-screen Explore view: process tree, timeline, or logs, picked by tab."),
    ("GET", "/incident/{id}/tree", "Alias for /explore?view=tree, kept for old links."),
    ("GET", "/dashboard", "The stats dashboard page: incident trends and top rules/techniques, charted."),
]

CONFIG_SETTINGS = [
    ("HUNTER_DB_URL", "sqlite+aiosqlite:///data/hunter.db", "Database connection string."),
    ("HUNTER_API_KEY", "(unset)", "Shared secret for the JSON API. Unset = no auth (trusted network)."),
    ("HUNTER_CORRELATION_WINDOW_MINUTES", "10", "Time window for grouping detections into one incident."),
    ("HUNTER_INCIDENT_SCORE_THRESHOLD", "12", "Cumulative severity score to promote an incident to active."),
    ("HUNTER_PROCESS_TTL_MINUTES", "120", "How long an inactive process stays in the in-memory tree."),
    ("HUNTER_BEACON_ENABLED", "true", "Enable/disable statistical beacon detection."),
    ("HUNTER_BEACON_MIN_CONNECTIONS", "6", "Callbacks required before a beacon verdict."),
    ("HUNTER_BEACON_REGULARITY_THRESHOLD", "0.75", "Minimum regularity score (0-1) to flag a beacon."),
    ("HUNTER_BEACON_MIN_INTERVAL_SECONDS", "5.0", "Fastest interval considered beacon-like, not streaming."),
    ("HUNTER_BEACON_MAX_INTERVAL_SECONDS", "3600.0", "Slowest interval still distinguishable from a scheduled task."),
    ("HUNTER_DISCOVERY_ENABLED", "true", "Enable/disable reconnaissance-burst detection."),
    ("HUNTER_DISCOVERY_MIN_DISTINCT", "4", "Distinct recon techniques required to flag a burst."),
    ("HUNTER_SCAN_ENABLED", "true", "Enable/disable statistical network-scan detection."),
    ("HUNTER_SCAN_MIN_DISTINCT_IPS", "10", "Distinct destination IPs from one process required to flag a host sweep."),
    ("HUNTER_SCAN_MIN_DISTINCT_PORTS", "15", "Distinct destination ports from one process required to flag a port scan."),
    ("HUNTER_NOISE_SIMILARITY_THRESHOLD", "0.6", "Similarity score (0-1) an open incident needs to be flagged as probable noise."),
    ("HUNTER_ABUSEIPDB_API_KEY", "(unset)", "Optional key for IP reputation enrichment."),
    ("HUNTER_VIRUSTOTAL_API_KEY", "(unset)", "Optional key for hash/IP/domain reputation enrichment."),
    ("HUNTER_ENRICHMENT_CACHE_TTL_SECONDS", "3600", "How long a reputation lookup is cached."),
    ("HUNTER_LOG_JSON", "false", "One JSON object per log line, for log aggregators, instead of human-readable text."),
    ("HUNTER_INGEST_RATE_LIMIT_PER_SECOND", "0", "Token-bucket rate limit on /ingest per source IP. 0 disables it."),
    ("HUNTER_INGEST_RATE_LIMIT_BURST", "50", "Burst allowance above the steady-state /ingest rate limit."),
]


def table_style(header_fill=GRAY_FILL2, font_size=8.4, header_font_size=8.6):
    cmds = [
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), header_font_size),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 1), (-1, -1), font_size),
        ("TEXTCOLOR", (0, 0), (-1, 0), BLACK),
        ("TEXTCOLOR", (0, 1), (-1, -1), GRAY_DARK),
        ("BACKGROUND", (0, 0), (-1, 0), header_fill),
        ("LINEBELOW", (0, 0), (-1, 0), 0.8, BLACK),
        ("LINEBELOW", (0, -1), (-1, -1), 0.6, GRAY_RULE),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, GRAY_RULE),
    ]
    return TableStyle(cmds)


def data_table(headers, rows, col_widths, font_size=8.2, header_font_size=8.4):
    wrapped_headers = [Paragraph(f"<b>{h}</b>", ParagraphStyle(
        "th", fontName="Helvetica-Bold", fontSize=header_font_size, textColor=BLACK)) for h in headers]
    body_style = ParagraphStyle("td", fontName="Helvetica", fontSize=font_size,
                                 leading=font_size + 2.6, textColor=GRAY_DARK)
    mono_style = ParagraphStyle("tdmono", fontName="Courier", fontSize=font_size,
                                 leading=font_size + 2.6, textColor=BLACK)
    wrapped_rows = []
    for row in rows:
        wrapped_rows.append([
            Paragraph(str(cell), mono_style if i == 0 else body_style)
            for i, cell in enumerate(row)
        ])
    t = Table([wrapped_headers] + wrapped_rows, colWidths=col_widths, repeatRows=1)
    t.setStyle(table_style(font_size=font_size, header_font_size=header_font_size))
    return t


story = []

TOC_SECTIONS = [
    ("1", "Introduction", []),
    ("2", "System Architecture", ["2.1 Event Pipeline", "2.2 Data Flow"]),
    ("3", "Detection Engine", [
        "3.1 Rule-Based Detection", "3.2 Process-Tree Correlation",
        "3.3 Statistical Beacon Detection", "3.4 Reconnaissance-Burst Detection",
        "3.5 Ransomware Detection", "3.6 Behavior Profiling &amp; Derived Titles",
        "3.7 Incident Scoring", "3.9 Sigma Rule Import", "3.10 STIX 2.1 Export",
        "3.11 ATT&amp;CK Coverage Report &amp; Navigator Export",
        "3.12 False-Positive Similarity",
    ]),
    ("4", "Detection Rule Catalog", []),
    ("5", "The Analyst Console", [
        "5.1 Incident Queue", "5.2 Incident Detail Views",
        "5.3 Explore View", "5.4 Search",
        "5.5 IOC Enrichment", "5.6 ATT&amp;CK Technique Reference",
        "5.7 Analyst Notes", "5.8 PDF Reports &amp; STIX Export",
        "5.9 Incident Triage", "5.10 Sigma Rule Import",
        "5.11 Theme &amp; Database Reset", "5.12 Live WebSocket Feed",
        "5.13 ATT&amp;CK Coverage Download", "5.14 Stats Dashboard",
    ]),
    ("6", "REST API Reference", []),
    ("7", "Configuration Reference", []),
    ("8", "Installation &amp; Getting Started", []),
    ("9", "Testing", []),
    ("10", "Docker Deployment", []),
    ("11", "Design Decisions", []),
    ("12", "Project Layout", []),
]

story.append(Paragraph("Contents", styles["H1"]))
story += rule(space_before=2, space_after=10)
for num, title, subs in TOC_SECTIONS:
    story.append(Paragraph(f"{num}.&nbsp;&nbsp;{title}", styles["TOC1"]))
    for s in subs:
        story.append(Paragraph(s, styles["TOC2"]))
story.append(PageBreak())

story.append(H1("1.&nbsp;&nbsp;Introduction"))
story.append(P(
    "Sysmon Hunter is a real-time detection and correlation engine for Windows "
    "Sysmon telemetry, paired with a live analyst console. It ingests events "
    "from an endpoint, matches them against ATT&amp;CK-mapped detection rules, "
    "reconstructs the process tree to correlate related detections into "
    "incidents, detects command-and-control beaconing and ransomware activity "
    "statistically, and enriches indicators against external reputation "
    "sources -- all streamed to the console in real time."
))
story.append(P(
    "The project's guiding principle is that a single matched rule is a lead, "
    "not a verdict. A lone “PowerShell ran an encoded command” event is "
    "worth a glance. The same detection sitting under a Microsoft Word process, "
    "next to a reconnaissance burst and an outbound beacon, with a file hash "
    "confirmed malicious by VirusTotal, is an incident an analyst can act on "
    "immediately. Everything documented in this manual serves that one idea: "
    "turning individually weak signals into a correlated, prioritized, "
    "investigable incident."
))
story.append(P(
    "This manual documents the detection engine, the analyst console, the REST "
    "and WebSocket API, the configuration surface, and the deployment options "
    "as of the version printed on the cover page."
))
story.append(H3("Who this is for"))
story.append(P(
    "Detection engineers writing or tuning Sysmon-based rules; SOC analysts "
    "triaging incidents in the console; and anyone standing up the engine "
    "against their own endpoint telemetry or a corpus of recorded Sysmon "
    "events."
))

story.append(H1("2.&nbsp;&nbsp;System Architecture"))
story.append(H2("2.1&nbsp;&nbsp;Event Pipeline"))
story.append(P(
    "Every event, regardless of source -- a live Winlogbeat feed, a replayed "
    ".evtx file, or a seed script -- takes the same path through the engine. "
    "The pipeline is independent of HTTP: it runs identically under the "
    "<font face=\"Courier\">/ingest</font> endpoint, the EVTX replay script, "
    "and the automated test suite with no server running at all."
))

pipeline_rows = [
    ["1", "Ingest", "POST /ingest receives one normalized event and hands it to the pipeline. Holds no logic of its own."],
    ["2", "Normalize", "Winlogbeat/Sysmon JSON is converted into a uniform internal Event, so downstream code never branches on source format."],
    ["3", "Observe", "Every event feeds the in-memory process tree, not just the ones that match a rule -- a malicious process's ancestors are usually benign and must still be recorded."],
    ["4", "Detect", "The event is run against four parallel detectors: the YAML rule engine, the statistical beacon detector, the reconnaissance-burst detector, and the network-scan detector."],
    ["5", "Correlate", "New detections are grouped with existing ones that share a process-tree root within the correlation window, forming or extending an incident."],
    ["6", "Persist &amp; Broadcast", "The detection and incident are written to SQLite and pushed to every connected console over the WebSocket feed."],
]
story.append(data_table(["Step", "Stage", "What happens"], pipeline_rows,
                         col_widths=[16 * mm, 30 * mm, 108 * mm]))
story.append(Spacer(1, 10))

story.append(H2("2.2&nbsp;&nbsp;Data Flow"))
story.append(P(
    "The process tree is keyed on Sysmon's <font face=\"Courier\">ProcessGuid</font>, "
    "never on process ID. Windows recycles PIDs aggressively, so a tree keyed "
    "on PID would graft an unrelated later process onto a malicious parent's "
    "identity the moment that PID is reused; ProcessGuid is unique across "
    "reboots and PID reuse and does not have this failure mode."
))
story.append(P(
    "Incidents are not simply a rule match logged to a table -- the correlator "
    "groups every detection that shares a process-tree root within a "
    "configurable time window into a single incident, and carries the full "
    "branching tree with it, not just the linear chain from root to the "
    "triggering process."
))

story.append(H1("3.&nbsp;&nbsp;Detection Engine"))

story.append(H2("3.1&nbsp;&nbsp;Rule-Based Detection"))
story.append(P(
    "149 YAML detection rules, each mapped to one or more MITRE ATT&amp;CK "
    "technique IDs, are indexed by Sysmon Event ID so that only relevant rules "
    "are evaluated per event. Rules use Sigma-compatible matching semantics: "
    "field/operator pairs (<font face=\"Courier\">equals</font>, "
    "<font face=\"Courier\">contains</font>, <font face=\"Courier\">startswith</font>, "
    "<font face=\"Courier\">endswith</font>, <font face=\"Courier\">re</font>) combined "
    "with an <font face=\"Courier\">all</font>/<font face=\"Courier\">any</font> "
    "condition, and an operator's expected value may be a single value or a "
    "list, OR'd together -- for example, matching a file write against any of "
    "several known ransomware extensions in one clause."
))
story.append(P(
    "The full catalog, with severity and ATT&amp;CK mapping for every rule, is "
    "in Section 4."
))

story.append(H2("3.2&nbsp;&nbsp;Process-Tree Correlation"))
story.append(P(
    "Detections rarely stand alone in a real intrusion. The correlator "
    "reconstructs each host's process ancestry from Sysmon's ProcessGuid "
    "fields, and any detections whose processes share a tree root within the "
    "correlation window (10 minutes by default) are grouped into one incident "
    "carrying the complete branching tree -- not just the chain from root to "
    "the flagged process. A foothold that spawned several children shows every "
    "branch, whether or not each child individually fired a rule."
))

story.append(H2("3.3&nbsp;&nbsp;Statistical Beacon Detection"))
story.append(P(
    "No single network-connection event can reveal a periodic command-and-"
    "control channel; it takes a sequence of them. The beacon detector "
    "watches outbound connections (Sysmon Event ID 3) per process and scores "
    "their timing for regularity, requiring a minimum number of callbacks "
    "before rendering a verdict. It uses the median and median absolute "
    "deviation of the intervals, not the mean and standard deviation -- a live "
    "C2 session produces occasional large outliers (the operator interacts, a "
    "callback retries late), and those outliers distort a standard-deviation "
    "score badly enough to lose the channel entirely, while the median barely "
    "moves. Jitter up to and beyond Cobalt Strike's default 37% is still "
    "caught. A configurable exclusion list keeps common legitimately-periodic "
    "processes (browsers, sync clients, chat apps) from generating noise."
))

story.append(H2("3.4&nbsp;&nbsp;Reconnaissance-Burst Detection"))
story.append(P(
    "The discovery detector counts <i>distinct</i> ATT&amp;CK discovery "
    "techniques observed in one process tree within a short window, not raw "
    "execution counts. A script re-running <font face=\"Courier\">systeminfo</font> "
    "in a loop is volume without variety and stays quiet; an operator running "
    "<font face=\"Courier\">whoami</font>, <font face=\"Courier\">net</font>, "
    "<font face=\"Courier\">nltest</font>, and <font face=\"Courier\">systeminfo</font> "
    "in quick succession is variety, and is flagged as a reconnaissance burst."
))

story.append(H2("3.5&nbsp;&nbsp;Statistical Network-Scan Detection"))
story.append(P(
    "Beaconing looks at rhythm to one destination; the discovery burst looks "
    "at command variety. Neither sees a scanner, because a scanner is "
    "neither periodic nor does it run recon commands -- it simply opens many "
    "connections to many different places, fast. The scan detector watches "
    "outbound connections (Sysmon Event ID 3) per process and tracks the "
    "growing set of distinct destinations it has touched within a window, "
    "flagging breadth rather than timing. Two shapes are covered, either "
    "sufficient on its own: many distinct ports against a small number of "
    "hosts (a port scan, the textbook vertical case) and many distinct hosts "
    "on a small number of ports (a host sweep, the horizontal case, e.g. an "
    "SMB or RDP sweep across a subnet). Severity escalates when a later "
    "alert's accumulated breadth passes double the configured threshold, and "
    "ATT&amp;CK tagging reflects whichever shape -- or both -- was actually "
    "observed."
))

story.append(H2("3.6&nbsp;&nbsp;Ransomware Detection"))
story.append(P(
    "Two rules target the file-write behavior that precedes and accompanies a "
    "ransomware encryption event, in addition to the shadow-copy-deletion and "
    "recovery-disabling command-line rules that typically precede it: a "
    "ransom note dropped to disk, matched against the near-universal “how to "
    "decrypt / restore your files” naming convention used across ransomware "
    "families, and a mass file write ending in a known ransomware encryption "
    "extension (<font face=\"Courier\">.locked</font>, "
    "<font face=\"Courier\">.encrypted</font>, <font face=\"Courier\">.crypt</font>, "
    "<font face=\"Courier\">.wcry</font>, and others). Because these detections have "
    "no process command line to show as evidence -- the interesting fact is "
    "which file was written, not what process wrote it -- the console surfaces "
    "the exact matched file path everywhere the detection's detail is shown: "
    "the incident's detection list, its timeline and process-tree popups, and "
    "the full-screen tree viewer."
))

story.append(H2("3.7&nbsp;&nbsp;Behavior Profiling &amp; Derived Titles"))
story.append(P(
    "Rather than leaving an analyst to read a flat list of N detections, the "
    "profiling engine turns an incident's detections into a plain-language, "
    "kill-chain-ordered narrative -- for example: “gained initial access "
    "through a phishing document, executed an obfuscated PowerShell payload, "
    "harvested credentials from LSASS, beaconed to C2 every ~35 seconds.” Each "
    "incident is also given a derived title summarizing its contents at a "
    "glance in the queue -- “Phishing to reconnaissance,” “Credential access "
    "with C2,” “Ransomware preparation” -- instead of a generic “Incident "
    "#4821.”"
))

story.append(H2("3.8&nbsp;&nbsp;Incident Scoring"))
story.append(P(
    "Incident severity scoring is non-linear by design: one critical LSASS "
    "access outweighs three medium-severity suspicious-path executions, and "
    "two high-severity detections together read as critical. This mirrors how "
    "an analyst actually judges risk -- a single strong signal can outweigh "
    "several weak ones, and enough weak signals together compound into a "
    "strong one. An incident is promoted to “active” once its cumulative "
    "score crosses a configurable threshold (12, by default)."
))

story.append(H2("3.9&nbsp;&nbsp;Correlation Chains &amp; Classification"))
story.append(P(
    "Beyond the tactic-based titles in Section 3.6, three named, rule-ID-"
    "level patterns recognise a specific multi-stage story and outrank the "
    "generic titles when they match: a <b>ransomware activity chain</b> "
    "(shadow-copy deletion together with a ransom note or an encrypted-"
    "extension write), a <b>credential-theft campaign</b> (at least two "
    "distinct credential-access rules -- LSASS access, Mimikatz, DCSync, "
    "browser/KeePass credential-database staging, Kerberoasting, or AS-REP "
    "roasting -- firing on the same incident), and an "
    "<b>Office-to-PowerShell infection chain</b> (an Office application "
    "spawning a shell, followed by a PowerShell download cradle). A matched "
    "chain sets both the incident's title and a machine-readable "
    "<font face=\"Courier\">classification</font> field, shown as a badge in "
    "the console queue and on the incident's full page. This is deliberately "
    "an identity mechanism, not a scoring one -- every rule referenced by a "
    "chain is itself high or critical severity, so a matched chain has "
    "already cleared the actionable threshold on the ordinary scoring scale "
    "described in Section 3.7 before it is ever classified."
))

story.append(H2("3.10&nbsp;&nbsp;Sigma Rule Import"))
story.append(P(
    "The hand-written rule catalog in Section 4 can be extended at runtime "
    "by uploading Sigma YAML files (from the public SigmaHQ corpus or "
    "written by hand) through the console's settings menu, which posts to "
    "<font face=\"Courier\">POST /admin/rules/import-sigma</font>. Each "
    "document is converted independently by "
    "<font face=\"Courier\">backend/engine/sigma_import.py</font> into this "
    "engine's own rule schema and written under "
    "<font face=\"Courier\">rules/imported_sigma/</font>, then the whole "
    "rule store reloads from disk -- an import is live for the very next "
    "ingested event, no restart required."
))
story.append(P(
    "Sigma is a considerably richer language than the matcher in Section "
    "3.1 implements, so the importer supports a deliberately bounded "
    "subset: Windows Sysmon logsource categories mapped to the matching "
    "EventID, a single selection or several combined with a plain "
    "<font face=\"Courier\">and</font> / <font face=\"Courier\">or</font> / "
    "<font face=\"Courier\">1 of x*</font> / <font face=\"Courier\">all of "
    "x*</font> condition, one trailing <font face=\"Courier\">and not "
    "&lt;filter&gt;</font> exclusion, the "
    "<font face=\"Courier\">contains</font> / "
    "<font face=\"Courier\">startswith</font> / "
    "<font face=\"Courier\">endswith</font> / <font face=\"Courier\">re"
    "</font> modifiers, and automatic translation of bare glob wildcards "
    "(<font face=\"Courier\">*</font>, <font face=\"Courier\">?</font>) into "
    "the matching operator. A Sigma rule that needs nested boolean groups, "
    "an aggregation (<font face=\"Courier\">count()</font>, "
    "<font face=\"Courier\">near</font>), or a modifier this matcher cannot "
    "reproduce (<font face=\"Courier\">|all</font>, "
    "<font face=\"Courier\">|base64</font>, <font face=\"Courier\">|cidr"
    "</font>, numeric comparisons) is rejected with the specific reason "
    "rather than approximated -- the same policy the rule loader already "
    "applies to a malformed YAML file on disk: one bad rule is reported and "
    "skipped, never silently wrong and never fatal to the batch."
))

story.append(H2("3.11&nbsp;&nbsp;STIX 2.1 Export"))
story.append(P(
    "The counterpart to Sigma import: any incident can be downloaded as a "
    "STIX 2.1 bundle from <font face=\"Courier\">GET /incidents/{id}/stix"
    "</font> (or the “Download STIX bundle” button next to the PDF report "
    "button), for another threat-intel platform to ingest without ever "
    "needing to know this engine's own schema. "
    "<font face=\"Courier\">backend/engine/stix_export.py</font> builds an "
    "<font face=\"Courier\">identity</font> object for this engine, one "
    "<font face=\"Courier\">attack-pattern</font> per distinct ATT&amp;CK "
    "technique the incident's detections carry, one "
    "<font face=\"Courier\">indicator</font> per pivotable IOC already "
    "surfaced by the key-indicators consolidation in Section 5 (a C2 "
    "destination IP or domain, a file's SHA256, a persistence registry key "
    "-- deduplicated across detections, never one indicator per detection), "
    "and a <font face=\"Courier\">report</font> object whose "
    "<font face=\"Courier\">object_refs</font> ties all of it together, "
    "named and described from the incident's own title and behavior-"
    "profile narrative."
))
story.append(P(
    "Object identifiers are deterministic -- a UUIDv5 seeded on stable "
    "content (a technique ID, an indicator's own pattern string, the "
    "incident ID) rather than randomly generated -- so exporting the same "
    "incident twice, or the same technique across two different incidents, "
    "produces the same STIX ID both times. That is what lets a receiving "
    "platform de-duplicate objects across imports instead of accumulating a "
    "new copy of the same technique on every download. No "
    "<font face=\"Courier\">relationship</font> objects are generated "
    "between indicators and techniques: the underlying data is incident-"
    "level, not per-IOC, so asserting that a specific indicator indicates a "
    "specific technique would claim precision the source data does not "
    "have."
))

story.append(H2("3.12&nbsp;&nbsp;ATT&amp;CK Coverage Report &amp; Navigator Export"))
story.append(P(
    "Every other view in this manual answers what the engine has detected; "
    "this one answers what it never could. "
    "<font face=\"Courier\">GET /attack/coverage</font> counts how many "
    "rules and statistical detectors raise each ATT&amp;CK technique across "
    "the whole corpus, and <font face=\"Courier\">GET /attack/coverage/"
    "navigator</font> (also reachable from the settings menu as “Download "
    "ATT&amp;CK coverage”) renders that count as a MITRE ATT&amp;CK "
    "Navigator layer -- open it at the public Navigator and every technique "
    "is colored red through green by how many rules cover it, turning "
    "months of reactive rule-writing into a single prioritized worklist for "
    "the next rule."
))
story.append(P(
    "The report has two honesty levels, and it says which one it is giving "
    "you. <font face=\"Courier\">backend/data/attack_data.json</font> (Section "
    "5.6) only ever contains techniques this project already references, by "
    "design -- so on its own it can rank covered techniques against each "
    "other but can never show a technique with zero rules, since that "
    "technique was filtered out before the report ever runs. "
    "<font face=\"Courier\">scripts/fetch_attack.py</font> also writes a "
    "second, full-catalog file, <font face=\"Courier\">backend/data/"
    "attack_index.json</font> -- every non-deprecated Enterprise technique, "
    "covered or not, with just enough data (ID, name, tactics) to plot on a "
    "layer. When that file is present, "
    "<font face=\"Courier\">backend/engine/coverage.py</font> produces a "
    "true gap analysis; when it is absent, the report still runs, it is "
    "just explicitly marked <font face=\"Courier\">partial</font> in both "
    "the JSON response and the layer's own description -- a missing "
    "optional file changes how much the report can show, never whether it "
    "works."
))

story.append(H2("3.13&nbsp;&nbsp;False-Positive Similarity"))
story.append(P(
    "Every incident an analyst marks a false positive is a labeled example "
    "of noise -- <font face=\"Courier\">backend/engine/noise.py</font> is "
    "what makes that marking pay off for the next incident, without a "
    "trained model or a mountain of data to get there. A newly-opened "
    "incident is compared against the deployment's own history of confirmed "
    "false positives on four explainable signals: which detection rules "
    "fired (the most precise statement of “this is the same pattern” "
    "available, weighted highest), which ATT&amp;CK techniques were "
    "involved, whether the same process was the root of the tree, and how "
    "much of the process chain overlaps (weighted lowest, since two "
    "unrelated incidents can share common ancestor processes like "
    "<font face=\"Courier\">explorer.exe</font> by platform convention "
    "alone)."
))
story.append(P(
    "This is deliberately not a classifier. It produces a score -- e.g. "
    "“78% similar to incident abc123, because: same detection rules, same "
    "root process” -- from the very first false positive an analyst ever "
    "marks, and the explanation is exactly the weighted arithmetic that "
    "produced it, nothing hidden and nothing to retrain. A match at or "
    "above <font face=\"Courier\">HUNTER_NOISE_SIMILARITY_THRESHOLD</font> "
    "(default 0.6, Section 7) surfaces as a dashed “probable noise” badge "
    "in the console queue and on the incident page, naming the past "
    "incident it resembles and the specific signals that matched -- a hint "
    "for an analyst to weigh, never an automatic dismissal. Only open "
    "incidents are scored; a closed or already-dismissed incident has "
    "nothing left to warn about."
))

story.append(PageBreak())

story.append(H1("4.&nbsp;&nbsp;Detection Rule Catalog"))
story.append(P(
    "Every rule below was written and validated against real telemetry -- "
    "either a hand-built scenario exercised end-to-end through the console, "
    "or a known-malicious .evtx sample from a public detection-engineering "
    "corpus. Each has an automated true-positive case (the rule fires on the "
    "malicious sample) and a true-negative case (it stays quiet on adjacent "
    "legitimate activity) in the test suite."
))

rule_rows = [[rid, EVENT_ID_NAMES.get(eid, eid), sev, title, atk]
             for rid, eid, sev, title, atk in RULES]
story.append(data_table(
    ["Rule ID", "Event", "Severity", "Title", "ATT&amp;CK"],
    rule_rows,
    col_widths=[19 * mm, 24 * mm, 15 * mm, 68 * mm, 28 * mm],
    font_size=7.4, header_font_size=7.8,
))
story.append(Spacer(1, 8))
story.append(Paragraph(
    "Rule IDs follow no severity ordering; they are assigned sequentially as "
    "rules are added. “Event” is the Sysmon Event ID the rule is indexed "
    "under (Process Create = 1, Network Connection = 3, Driver Load = 6, "
    "Image Load = 7, Remote Thread Created = 8, Process Access = 10, File "
    "Create = 11, Registry Create/Delete = 12, Registry Set = 13, Pipe "
    "Created = 17, WMI Event = 20).",
    styles["Caption"]
))

story.append(PageBreak())

story.append(H1("5.&nbsp;&nbsp;The Analyst Console"))
story.append(P(
    "The console is a single-page, dark-surface application served directly "
    "by the backend at the site root, with a live WebSocket feed so every "
    "connected analyst sees the same state update in real time."
))

story.append(H2("5.1&nbsp;&nbsp;Incident Queue"))
story.append(P(
    "The primary view: every incident the engine has correlated, most recent "
    "first, filterable between “Triage” (actionable incidents only, i.e. "
    "those over the score threshold), “All” (everything the engine is "
    "tracking, including sub-threshold activity it has not promoted), and "
    "“Closed” (incidents an analyst has already resolved -- see Section 5.9). "
    "Each row shows the derived title, severity, host, cumulative score, the "
    "process chain, and ATT&amp;CK technique chips at a glance, before any "
    "drill-down. An incident that matches one of the correlation chains from "
    "Section 3.8 (ransomware, credential-theft campaign, Office-to-"
    "PowerShell) additionally carries a filled classification badge next to "
    "its title, repeated on the incident's full page."
))

story.append(H2("5.2&nbsp;&nbsp;Incident Detail Views"))
story.append(P(
    "Expanding an incident reveals its behavior-profile narrative, then three "
    "interchangeable views of the same underlying data:"
))
story += bullets([
    "<b>List</b> -- every detection with its full forensic context: process, parent, user, "
    "integrity level, hashes (with a one-click VirusTotal lookup), and, for file-write "
    "detections, the exact matched file path.",
    "<b>Timeline</b> -- detections placed in sequence with the real elapsed time between "
    "steps; clicking a node opens a floating forensic detail popup.",
    "<b>Process tree</b> -- the complete branching tree the incident spans, not just the "
    "chain to the triggering process. Nodes that fired a detection are colour-coded by "
    "severity; benign context processes are shown hollow so the whole tree's shape is "
    "visible, not only the flagged parts.",
])

story.append(H2("5.3&nbsp;&nbsp;Explore View"))
story.append(P(
    "The inline detail views are deliberately compact so they fit beside the "
    "detection list, which is too little room for a wide tree, a long "
    "timeline, or a long log list. “Explore” hands the same incident to a "
    "dedicated full-screen page "
    "(<font face=\"Courier\">/incident/{id}/explore</font>) with three tabs "
    "switchable in place, each a click away from the other: process tree, "
    "timeline, and a plain scrollable log. The tree and timeline gain "
    "click-and-drag panning, scroll-wheel zoom centred on the cursor, a "
    "zoom-to-fit control, and keyboard shortcuts "
    "(<font face=\"Courier\">+</font> / <font face=\"Courier\">-</font> / "
    "<font face=\"Courier\">0</font>). Clicking a node or a timeline entry "
    "opens the same forensic detail panel used inline."
))

story.append(H2("5.4&nbsp;&nbsp;Search"))
story.append(P(
    "One search box combines free text with field filters, mixed freely in a "
    "single query -- for example, "
    "<font face=\"Courier\">powershell severity:critical host:fin-ws</font>. "
    "Free text matches anywhere an analyst might remember something about an "
    "incident: a process name, a command-line fragment, a hash, a rule ID, the "
    "title. Field filters narrow precisely by substring match, not exact "
    "match, so <font face=\"Courier\">host:fin-ws</font> finds "
    "<font face=\"Courier\">FIN-WS-07</font>."
))
search_rows = [
    ["host:", "Substring match against the incident's host."],
    ["severity:", "Exact match: info, low, medium, high, or critical."],
    ["technique:", "Matches an ATT&amp;CK technique ID, exact or as a prefix."],
    ["rule:", "Matches a detection rule ID."],
    ["user:", "Matches the forensic user field on a detection."],
    ["command_line:", "Scoped substring match against a detection's command line only."],
    ["actionable:", "true/false -- restricts to incidents over (or under) the score threshold."],
]
story.append(data_table(["Filter", "Matches"], search_rows,
                         col_widths=[32 * mm, 103 * mm], font_size=8.2))

story.append(H2("5.5&nbsp;&nbsp;IOC Enrichment"))
story.append(P(
    "IP addresses, domains, and file hashes can be checked on demand against "
    "AbuseIPDB (IP reputation) and VirusTotal (IP, domain, and file-hash "
    "reputation). Results are cached for an hour. Every provider degrades "
    "gracefully to “unavailable” with no API key configured -- enrichment "
    "never blocks the rest of the console from working. Private IP ranges are "
    "never sent to a third party, and the strongest available hash (SHA-256 "
    "over SHA-1 over MD5) is always preferred, since MD5 collisions are cheap "
    "enough for malware authors to produce deliberately."
))

story.append(H2("5.6&nbsp;&nbsp;ATT&amp;CK Technique Reference"))
story.append(P(
    "Every technique chip shown anywhere in the console is clickable and opens "
    "its official MITRE description -- name, tactics, and full text -- from a "
    "local copy of the ATT&amp;CK STIX dataset, with a link out to the ATT&amp;CK "
    "site. No lookup leaves the console for an analyst who does not have "
    "T1003.001 memorized."
))

story.append(H2("5.7&nbsp;&nbsp;Analyst Notes"))
story.append(P(
    "Each incident's full-page view carries a free-text analyst note, capped "
    "at 500 words -- a summary, not a report -- with autosave on the incident "
    "page and a live word counter."
))

story.append(H2("5.8&nbsp;&nbsp;PDF Reports &amp; STIX Export"))
story.append(P(
    "Every incident can be downloaded as a self-contained PDF report, suitable "
    "for attaching to a ticket or handing to an incident-response lead. It is "
    "not a screenshot of the console -- it is the investigation written down: "
    "the behavior-profile narrative, the process chain, every detection with "
    "its forensics, and the incident's key indicators. Generated server-side "
    "with reportlab, requiring no headless browser in the deployment image. "
    "The button beside it, “Download STIX bundle”, exports the same incident "
    "as a machine-readable STIX 2.1 bundle instead -- see Section 3.10 for "
    "exactly what it contains."
))

story.append(H2("5.9&nbsp;&nbsp;Incident Triage"))
story.append(P(
    "Every incident carries a status: open, closed, or a verdict such as "
    "false positive or benign, set from a “Set verdict” menu on the incident "
    "card and cleared with a “Close” action. Any state can transition to any "
    "other -- a closed incident can be reopened if new evidence surfaces -- "
    "and there is no workflow enforced beyond that; the analyst is the one "
    "doing the triage, not the console. Closed incidents drop out of the "
    "default queue view and are reachable from the “Closed” filter tab "
    "(Section 5.1), so a shift's queue only ever shows what still needs a "
    "decision."
))
story.append(P(
    "Once at least one incident has been marked a false positive, later "
    "open incidents that resemble it closely enough gain a dashed “probable "
    "noise” badge next to the status badge, naming the similarity "
    "percentage -- see Section 3.12 for the scoring behind it."
))

story.append(H2("5.10&nbsp;&nbsp;Sigma Rule Import"))
story.append(P(
    "The same settings menu that holds the theme toggle also holds "
    "“Import Sigma rules”, which opens a file picker accepting one or more "
    "<font face=\"Courier\">.yml</font>/<font face=\"Courier\">.yaml</font> "
    "files. Selecting files immediately uploads them to "
    "<font face=\"Courier\">POST /admin/rules/import-sigma</font>; a report "
    "modal then lists every document that was accepted (with its generated "
    "rule ID) and every one that was rejected (with the specific reason), so "
    "a partially-successful batch is never a silent partial success. See "
    "Section 3.9 for exactly what subset of Sigma is supported."
))

story.append(H2("5.11&nbsp;&nbsp;Theme &amp; Database Reset"))
story.append(P(
    "A settings menu in the console header holds a light/dark theme toggle "
    "and one destructive action: wiping the database. The reset is confirmed "
    "with a dialog, since there is no undo -- every detection and incident is "
    "permanently removed, on every connected console, via the same WebSocket "
    "broadcast that delivers live updates."
))

story.append(H2("5.12&nbsp;&nbsp;Live WebSocket Feed"))
story.append(P(
    "The console holds a persistent WebSocket connection and reconnects "
    "automatically on drop, so it can be left open on a wall display "
    "indefinitely. New detections, incident updates, and database resets are "
    "pushed to every connected client the instant they happen -- there is no "
    "polling and no manual refresh."
))

story.append(H2("5.13&nbsp;&nbsp;ATT&amp;CK Coverage Download"))
story.append(P(
    "The same settings menu holds “Download ATT&amp;CK coverage”, a direct "
    "link to <font face=\"Courier\">GET /attack/coverage/navigator</font> -- "
    "no upload step, no report modal, just a MITRE ATT&amp;CK Navigator "
    "layer file ready to open at the public Navigator. See Section 3.11 for "
    "what it contains and how it degrades when the full technique index is "
    "not present."
))

story.append(H2("5.14&nbsp;&nbsp;Stats Dashboard"))
story.append(P(
    "A fourth console view, linked from the header (<font face=\"Courier\">"
    "GET /dashboard</font>), independent of any one incident: incidents per "
    "day over a 7/14/30/90-day range with every day in the window shown, "
    "including the zero-count ones, so a quiet stretch reads as a flat "
    "bar rather than a gap in the series; severity distribution and triage "
    "status across every incident on record; and the top 10 rules and top "
    "10 ATT&amp;CK techniques by detection count, each technique linking "
    "directly to its MITRE page. Backed by "
    "<font face=\"Courier\">GET /stats</font> "
    "(<font face=\"Courier\">backend/engine/stats.py</font>), which reads a "
    "narrow column set from SQLite and tallies it in Python rather than "
    "expressing a “group by calendar day” in SQL. Charted as plain "
    "HTML/CSS bars -- no charting library, matching the rest of the "
    "frontend's zero-dependency approach."
))

story.append(PageBreak())

story.append(H1("6.&nbsp;&nbsp;REST API Reference"))
story.append(P(
    "The full interactive OpenAPI documentation is served at "
    "<font face=\"Courier\">/api/docs</font> (Swagger UI) and "
    "<font face=\"Courier\">/api/redoc</font> (ReDoc) on a running instance. The "
    "table below is a static summary of every route."
))
api_rows = [[m, p, d] for m, p, d in API_ROUTES]
story.append(data_table(["Method", "Path", "Description"], api_rows,
                         col_widths=[16 * mm, 38 * mm, 100 * mm], font_size=8.0))

story.append(PageBreak())

story.append(H1("7.&nbsp;&nbsp;Configuration Reference"))
story.append(P(
    "Every tunable lives in one settings object and can be overridden from "
    "the environment or a <font face=\"Courier\">.env</font> file, without "
    "touching code. All variables are prefixed "
    "<font face=\"Courier\">HUNTER_</font>."
))
cfg_rows = [[k, v, d] for k, v, d in CONFIG_SETTINGS]
story.append(data_table(["Variable", "Default", "Purpose"], cfg_rows,
                         col_widths=[54 * mm, 40 * mm, 60 * mm], font_size=7.6))

story.append(PageBreak())

story.append(H1("8.&nbsp;&nbsp;Installation &amp; Getting Started"))
story.append(P("Requires Python 3.11 or newer."))
story.append(Paragraph(
    "python -m venv .venv<br/>"
    "source .venv/bin/activate&nbsp;&nbsp;&nbsp;&nbsp;# Windows: .venv\\Scripts\\Activate.ps1<br/>"
    "pip install -r requirements.txt<br/><br/>"
    "python -m alembic upgrade head&nbsp;&nbsp;&nbsp;&nbsp;# create the database schema<br/>"
    "python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000",
    styles["Mono"]
))
story.append(P(
    "Console: <font face=\"Courier\">http://localhost:8000</font> &nbsp;&#183;&nbsp; "
    "API docs: <font face=\"Courier\">http://localhost:8000/api/docs</font>"
))

story.append(H3("Seeding demo data"))
story.append(Paragraph(
    "python scripts/seed_apt.py&nbsp;&nbsp;&nbsp;&nbsp;# one deep multi-stage intrusion<br/>"
    "python scripts/seed_demo.py&nbsp;&nbsp;&nbsp;&nbsp;# varied incidents across the kill chain<br/>"
    "python scripts/seed_rw.py&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# a full ransomware chain in one incident",
    styles["Mono"]
))

story.append(H3("Analysing a real sample"))
story.append(P(
    "Replay a Sysmon .evtx file -- from a lab VM, or a public corpus such as "
    "EVTX-ATTACK-SAMPLES, where each file exercises one ATT&amp;CK technique:"
))
story.append(Paragraph(
    "pip install evtx<br/>"
    "python scripts/replay_evtx.py --file samples/sysmon_credential_access.evtx",
    styles["Mono"]
))

story.append(H3("Optional: IOC enrichment API keys"))
story.append(P(
    "Works with no keys configured (every provider reports unavailable). For "
    "live reputation data, add free-tier API keys to a "
    "<font face=\"Courier\">.env</font> file:"
))
story.append(Paragraph(
    "HUNTER_ABUSEIPDB_API_KEY=...<br/>"
    "HUNTER_VIRUSTOTAL_API_KEY=...",
    styles["Mono"]
))

story.append(H3("Optional: API key (authentication)"))
story.append(P(
    "The server binds to all interfaces (0.0.0.0) by default, so it is "
    "reachable from anywhere on the network it runs on -- fine for a single "
    "trusted network, not fine once it is reachable more broadly. Setting "
    "<font face=\"Courier\">HUNTER_API_KEY</font> makes every JSON endpoint "
    "(not the console's own HTML pages) require a matching "
    "<font face=\"Courier\">X-API-Key</font> header; see "
    "<font face=\"Courier\">backend/api/auth.py</font>."
))
story.append(P("Generate a random secret with whichever tool is on hand:"))
story.append(Paragraph(
    "python -c \"import secrets; print(secrets.token_hex(32))\"&nbsp;&nbsp;# any platform<br/>"
    "openssl rand -hex 32&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# Linux / macOS",
    styles["Mono"]
))
story.append(P("Then set it in .env:"))
story.append(Paragraph(
    "HUNTER_API_KEY=&lt;paste the generated string here&gt;",
    styles["Mono"]
))
story.append(P(
    "The console detects a 401 on its own and prompts once for the key, "
    "then remembers it in the browser -- no other setup needed. Treat the "
    "key like a password: do not commit it, and prefer HTTPS (e.g. behind a "
    "reverse proxy) if the server is reachable outside a trusted network."
))

story.append(H1("9.&nbsp;&nbsp;Testing"))
story.append(Paragraph(
    "pip install pytest pytest-asyncio<br/>"
    "python -m pytest&nbsp;&nbsp;&nbsp;&nbsp;# 690 tests",
    styles["Mono"]
))
story.append(P(
    "The test suite doubles as documentation: each design decision named in "
    "Section 11 has a test named after it, and every shipped detection rule "
    "is validated against a true positive it must catch and a true negative "
    "it must ignore."
))

story.append(H1("10.&nbsp;&nbsp;Docker Deployment"))
story.append(Paragraph("docker compose up --build", styles["Mono"]))
story.append(P(
    "A multi-stage build keeps the runtime image to the application and its "
    "virtual environment only -- the build tooling is discarded. The container "
    "runs as an unprivileged user, applies database migrations automatically "
    "on start, and exposes a health check at "
    "<font face=\"Courier\">/health</font>."
))

story.append(H1("11.&nbsp;&nbsp;Design Decisions"))
story.append(P(
    "The choices below are what separate this engine from a pattern match "
    "over a log file. Each is enforced by an automated test named after it."
))

design_points = [
    ("Correlation keys on ProcessGuid, never PID.",
     "Windows recycles process IDs aggressively; a PID-keyed tree would graft a malicious "
     "child onto whatever unrelated process later inherits its parent's PID. ProcessGuid is "
     "unique across reboots and PID reuse."),
    ("The process tree observes everything, not just detections.",
     "A malicious process's ancestors are usually entirely benign, so the process that never "
     "triggers a rule on its own must still be recorded, or it can never appear as the root "
     "of a phishing chain."),
    ("Incident scoring is non-linear.",
     "One critical LSASS access outweighs three medium-severity suspicious-path executions. "
     "Two high-severity detections read as critical together. An incident can be worse than "
     "any single rule that composes it."),
    ("Beaconing uses median and median absolute deviation, not mean and standard deviation.",
     "A live C2 session produces outliers constantly. One unusually long gap in an otherwise "
     "60-second beacon wrecks a standard-deviation-based score and loses the channel; the "
     "median barely notices. Jitter up to Cobalt Strike's default 37% is still caught."),
    ("Discovery counts distinct techniques, not raw execution counts.",
     "A script re-running one command in a loop is volume without variety. An operator "
     "running several different reconnaissance commands in quick succession is variety, and "
     "only the second pattern is flagged."),
    ("Enrichment works with no API keys, and never leaks internal data.",
     "Every provider degrades to “unavailable” without a key rather than failing the request. "
     "Private IP ranges are never sent to a third party. The strongest available hash is "
     "always preferred over a weaker one."),
    ("A missing optional data file degrades the ATT&amp;CK coverage report, never crashes it.",
     "Without the full technique index the coverage report and its Navigator export still run "
     "-- they just say so, falling back to ranking only the techniques this project already "
     "covers instead of refusing to answer at all."),
]
for title, body in design_points:
    story.append(KeepTogether([
        Paragraph(f"<b>{title}</b>", styles["H3"]),
        P(body),
    ]))

story.append(H1("12.&nbsp;&nbsp;Project Layout"))
layout_text = (
    "sysmon-hunter/<br/>"
    "+-- backend/<br/>"
    "|&nbsp;&nbsp;+-- main.py&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;FastAPI app, lifespan, background sweep, /metrics<br/>"
    "|&nbsp;&nbsp;+-- config.py&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;all tunables<br/>"
    "|&nbsp;&nbsp;+-- logging_setup.py&nbsp;text/JSON log formatting<br/>"
    "|&nbsp;&nbsp;+-- api/&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;ingest, detections, incidents, attack, enrich,<br/>"
    "|&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;report, search, notes, admin, ws, serializers,<br/>"
    "|&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;rate_limit, stats<br/>"
    "|&nbsp;&nbsp;+-- engine/&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;normalizer, rule_loader, matcher, correlator,<br/>"
    "|&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;beacon, discovery, scan, attack, coverage, enrichment,<br/>"
    "|&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;search, report, profile, pipeline, sigma_import,<br/>"
    "|&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;stix_export, noise, metrics, stats<br/>"
    "|&nbsp;&nbsp;+-- models/&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;schemas, db<br/>"
    "|&nbsp;&nbsp;`-- data/&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;attack_data.json (ATT&amp;CK technique lookup),<br/>"
    "|&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;attack_index.json (full catalog, coverage gaps)<br/>"
    "+-- rules/&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;149 YAML detection rules, by Event ID, plus<br/>"
    "|&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;imported_sigma/ for runtime Sigma imports<br/>"
    "+-- frontend/&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.html, incident.html, tree.html,<br/>"
    "|&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;dashboard.html, static/{css,js}<br/>"
    "+-- migrations/&nbsp;&nbsp;&nbsp;&nbsp;Alembic<br/>"
    "+-- scripts/&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;seed_apt, seed_demo, seed_rw, seed_full_coverage,<br/>"
    "|&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;replay_evtx, fetch_attack<br/>"
    "+-- docs/&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;screenshots<br/>"
    "`-- tests/&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;690 tests"
)
story.append(Paragraph(layout_text, ParagraphStyle(
    "Layout", parent=styles["Mono"], fontSize=7.8, leading=11.5)))

story.append(Spacer(1, 14))
story += rule(space_before=4, space_after=6)
story.append(Paragraph(
    "Built as a hands-on threat-detection research project. The engine "
    "targets a single collector; scaling to many would mean moving the "
    "queue to Redis and the store to Postgres, both isolated behind small "
    "interfaces so that change touches one file each.",
    styles["Caption"]
))


doc = BaseDocTemplate(
    OUT_PATH,
    pagesize=A4,
    leftMargin=MARGIN_L, rightMargin=MARGIN_R,
    topMargin=MARGIN_T, bottomMargin=MARGIN_B,
    title=DOC_TITLE, author="Sysmon Hunter",
    subject="Detection engineering and analyst console user manual",
)

cover_frame = Frame(0, 0, PAGE_W, PAGE_H, leftPadding=0, rightPadding=0,
                     topPadding=0, bottomPadding=0, id="cover")
body_frame = Frame(MARGIN_L, MARGIN_B, PAGE_W - MARGIN_L - MARGIN_R,
                    PAGE_H - MARGIN_T - MARGIN_B, id="body")

doc.addPageTemplates([
    PageTemplate(id="Cover", frames=[cover_frame], onPage=draw_cover),
    PageTemplate(id="Body", frames=[body_frame], onPage=draw_header_footer),
])

full_story = [NextPageTemplate("Body"), PageBreak()] + story
full_story = [Spacer(1, 0)] + full_story

doc.build(full_story)
print("Wrote", OUT_PATH)
