
import sys, os, base64, json, requests
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QColor, QPalette
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QHBoxLayout, QLabel, QPushButton, QLineEdit, QTextEdit,
    QFrame, QScrollArea, QMessageBox, QComboBox)


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.append(ROOT)
    

from shared.models import CampusMessage, serialize_campus_message
from shared.crypto_utils import (
    load_public_key, rsa_encrypt_oaep, generate_aes_key_iv,
    aes_cbc_encrypt, hmac_sha256, b64e
)

# Pre-Filled Lists

# Abington Campus Directory (Academic Departments) - https://www.abington.psu.edu/campus-directory
DEPARTMENTS = [ "American Studies", "Art", "Biology", "Business", "Chemistry",
               "Computer Science", "Corporate Communication", "Criminal Justice",
               "Cybersecurity Analytics and Operations", "Criminal Justice", "Cybersecurity Analytics and Operations",
               "Data Sciences", "Early Childhood/Elementary Education", "Engineering", "English",
               "Health Humanities", "History", "Information Technology", "Integrative Arts",
               "Multidisciplinary Studies", "Mathematics", "Nursing", "Physics", "Psychological and Social Sciences",
               "Race and Ethnic Studies", "Recreation, Park and Tourism Management", "Rehabilitation and Human Services",
               "Writing Program"
    
]

# Supporting Courses for Abington Programs
COURSES_BY_DEPARTMENT = {
    "Computer Science": ["CMPSC 131", "CMPSC 132", "CMPSC 221", "CMPSC 312", "CMPSC 330",
                         "CMPSC 360", "CMPSC 430", "CMPSC 441", "CMPSC 445", "CMPSC 446",
                         "CMPSC 463", "CMPSC 469", "CMPSC 487W", "CMPSC 448"],
    
    "Mathematics": ["MATH 140", "MATH 141", "MATH 220"],
    "English": ["ENGL 202C"],
    "Biology":[],
    "Business:":[],
    "Chemistry":[],
    "Corporate Communication":[],
    "Criminal Justice":[],
    "Cybersecurity Analytics and Operations":[],
    "Data Sciences":[],
    "Early Childhood/Elementary Education":[],
    "Engineering":[],
    "Health Humanities":[],
    "History":[],
    "Information Technology":[],
    "Integrative Arts":[],
    "Multidisciplinary Studies":[],
    "Nursing":[],
    "Physics":[],
    "Psychological and Social Sciences":[],
    "Race and Ethnic Studies":[],
    "Recreation, Park and Tourism Management":[],
    "Rehabilitation and Human Services":[],
    "Writing Program":[]
}

ROLES = ["Professor", "Program Chair", "Staff", "Advisor", "Admin"]
SEMESTERS = ["Fall 2024", "Spring 2025", "Summer 2025", 
             "Fall 2025", "Spring 2026", "Summer 2026", 
             "Fall 2026", "Spring 2027", "Summer 2027",
             "Fall 2027", "Spring 2028", "Summer 2028",
             "Fall 2028", "Spring 2029", "Summer 2029",
             "Fall 2029", "Spring 2030", "Summer 2030",
             "Fall 2030", "Spring 2031", "Summer 2031"]



class GlassCard(QFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName("GlassCard")
        self.setStyleSheet("""
            #GlassCard {
                background: rgba(17,24,39,0.85);
                border: 1px solid rgba(255,255,255,0.06);
                border-radius: 16px;
            }
        """)


class MessageBubble(QFrame):
    def __init__(self, text: str, outgoing: bool):
        super().__init__()
        self.setObjectName("Bubble")
        self.setStyleSheet(f"""
            #Bubble {{
                background: {'rgba(31,41,55,0.85)' if outgoing else 'rgba(17,24,39,0.85)'};
                border-radius: 14px;
                border: 1px solid {'#7C3AED' if outgoing else '#22D3EE'};
                color: #E5E7EB;
            }}
            QLabel {{ color: #E5E7EB; }}
        """)
        layout = QVBoxLayout(self); layout.setContentsMargins(12,10,12,10)
        lbl = QLabel(text); lbl.setWordWrap(True); layout.addWidget(lbl)

class Tag(QLabel):
    def __init__(self, text, color="#22D3EE"):
        super().__init__(text)
        self.setAlignment(Qt.AlignCenter)
        self.setStyleSheet(f"""
            QLabel {{
                background-color: {color};
                color: #0F172A;
                padding: 4px 10px;
                border-radius: 999px;
                font-weight: 600;
            }}
        """)

class ChatWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Campus Messenger")
        self.setMinimumSize(1020, 680)
        pal = self.palette(); pal.setColor(QPalette.Window, QColor("#0F172A")); self.setPalette(pal)

        root = QWidget(); self.setCentralWidget(root)
        root_layout = QHBoxLayout(root); root_layout.setContentsMargins(16,16,16,16); root_layout.setSpacing(16)

        # Sidebar
        sidebar = GlassCard()
        sb = QVBoxLayout(sidebar); sb.setContentsMargins(14,14,14,14); sb.setSpacing(10)

        title = QLabel("Server"); title.setStyleSheet("color:#F8FAFC; font-size:18px; font-weight:700;")
        self.server_edit = QLineEdit("http://127.0.0.1:8000")
        self.server_edit.setStyleSheet("QLineEdit { background:#0B1220; color:#E5E7EB; border-radius:10px; padding:8px; }")
        self.fetch_btn = QPushButton("Fetch Public Key")
        self.fetch_btn.setStyleSheet(self._primary_btn("#7C3AED", "#F472B6"))
        self.fetch_btn.clicked.connect(self.fetch_public_key)
        self.status_lbl = QLabel("Key: (not fetched)"); self.status_lbl.setStyleSheet("color:#93C5FD;")

        sb.addWidget(title); sb.addWidget(self.server_edit); sb.addWidget(self.fetch_btn)
        sb.addSpacing(8); sb.addWidget(Tag("RSA-OAEP", "#7C3AED")); sb.addWidget(Tag("AES-256-CBC", "#22D3EE")); sb.addWidget(Tag("HMAC-SHA256", "#F472B6"))
        sb.addSpacing(8); sb.addWidget(self.status_lbl); sb.addStretch()

        # Chat Card
        chat_card = GlassCard()
        cc = QVBoxLayout(chat_card); cc.setContentsMargins(14,14,14,14); cc.setSpacing(10)
        header = QLabel("Secure Chat"); header.setStyleSheet("color:#F8FAFC; font-size:20px; font-weight:800;")
        sub = QLabel("Encrypted via AES, integrity protected with HMAC, session-keyed using RSA.")
        sub.setStyleSheet("color:#94A3B8;")
        cc.addWidget(header); cc.addWidget(sub)

        # Context row (dept/role/semester/course/sender)
        row = QHBoxLayout()
        self.dept = QComboBox(); self.dept.addItems(DEPARTMENTS)
        self.dept.currentTextChanged.connect(self._on_dept_change)
        self.dept.setStyleSheet("QComboBox { background:#0B1220; color:#E5E7EB; border-radius:10px; padding:6px; }")

        self.role = QComboBox(); self.role.addItems(ROLES)
        self.role.setStyleSheet("QComboBox { background:#0B1220; color:#E5E7EB; border-radius:10px; padding:6px; }")

        self.semester = QComboBox(); self.semester.addItems(SEMESTERS)
        self.semester.setStyleSheet("QComboBox { background:#0B1220; color:#E5E7EB; border-radius:10px; padding:6px; }")

        self.course = QComboBox(); self.course.setStyleSheet("QComboBox { background:#0B1220; color:#E5E7EB; border-radius:10px; padding:6px; }")

        self.sender_name = QLineEdit(); self.sender_name.setPlaceholderText("Sender name (e.g., Dr. Elangovan)")
        self.sender_name.setStyleSheet("QLineEdit { background:#0B1220; color:#E5E7EB; border-radius:10px; padding:8px; }")

        row.addWidget(QLabel("Dept")); row.addWidget(self.dept)
        row.addWidget(QLabel("Role")); row.addWidget(self.role)
        row.addWidget(QLabel("Semester")); row.addWidget(self.semester)
        row.addWidget(QLabel("Course")); row.addWidget(self.course)
        row.addWidget(QLabel("Sender")); row.addWidget(self.sender_name)
        for i in range(row.count()):
            w = row.itemAt(i).widget()
            if isinstance(w, QLabel): w.setStyleSheet("color:#CBD5E1;")

        cc.addLayout(row)
        self._on_dept_change(self.dept.currentText())

        # Messages Area
        self.scroll_area = QScrollArea(); self.scroll_area.setWidgetResizable(True)
        self.messages_widget = QWidget(); self.messages_layout = QVBoxLayout(self.messages_widget)
        self.messages_layout.setContentsMargins(0,0,0,0); self.messages_layout.setSpacing(8)
        self.messages_layout.addStretch()
        self.scroll_area.setWidget(self.messages_widget)
        cc.addWidget(self.scroll_area)

        # Composer
        composer = QHBoxLayout()
        self.input = QTextEdit(); self.input.setPlaceholderText("Type a secure campus message…")
        self.input.setStyleSheet("QTextEdit { background:#0B1220; color:#E5E7EB; border-radius:10px; padding:8px; }")
        send_btn = QPushButton("Send Secure")
        send_btn.setStyleSheet(self._primary_btn("#22D3EE", "#7C3AED"))
        send_btn.clicked.connect(self.send_secure_message)
        composer.addWidget(self.input, 4); composer.addWidget(send_btn, 1)
        cc.addLayout(composer)

        self.footer = QLabel("Ready."); self.footer.setStyleSheet("color:#A7F3D0;")
        cc.addWidget(self.footer)

        root_layout.addWidget(sidebar, 1)
        root_layout.addWidget(chat_card, 3)

        self.public_key_pem: bytes | None = None

    def _primary_btn(self, start_hex, end_hex):
        return f"""
        QPushButton {{
            color: #0F172A; font-weight:700; border:none; border-radius:10px; padding:10px 14px;
            background-color: {start_hex};
        }}
        QPushButton:hover {{ background-color: {end_hex}; }}
        QPushButton:pressed {{ background-color: #10B981; color:#062e0d; }}
        """

    def _on_dept_change(self, dept: str):
        self.course.clear()
        options = COURSES_BY_DEPARTMENT.get(dept, [])
        if options:
            self.course.addItems(options)
        else:
            self.course.addItem("(No course / N/A)")

    # --- Networking ---
    def fetch_public_key(self):
        base = self.server_edit.text().strip()
        try:
            r = requests.get(f"{base}/public-key", timeout=8)
            r.raise_for_status()
            self.public_key_pem = r.json()["public_key_pem"].encode("ascii")
            self.status_lbl.setText("Key: fetched ✅")
            self.footer.setText("Public key loaded.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to fetch public key:\n{e}")
            self.footer.setText("Fetch public key failed.")

    def send_secure_message(self):
        text = self.input.toPlainText().strip()
        if not text:
            return
        if not self.public_key_pem:
            QMessageBox.warning(self, "Not ready", "Fetch the server public key first.")
            return
        base = self.server_edit.text().strip()

        msg = CampusMessage(
            department=self.dept.currentText(),
            role=self.role.currentText(),
            sender_name=self.sender_name.text().strip() or "Anonymous",
            semester=self.semester.currentText(),
            course_code=(self.course.currentText() if self.course.currentText() != "(No course / N/A)" else None),
            message=text
        )
        plaintext_json = serialize_campus_message(msg, client_id="gui-client")

        # Build secure payload (AES + HMAC + RSA-OAEP)
        try:
            pub = load_public_key(self.public_key_pem)
            aes_key, iv = generate_aes_key_iv()
            ciphertext = aes_cbc_encrypt(aes_key, iv, plaintext_json.encode("utf-8"))
            mac = hmac_sha256(aes_key, iv + ciphertext)
            enc_key = rsa_encrypt_oaep(pub, aes_key)
            payload = {
                "client_id": "gui-client",
                "encrypted_key_b64": b64e(enc_key),
                "iv_b64": b64e(iv),
                "ciphertext_b64": b64e(ciphertext),
                "hmac_b64": b64e(mac),
                "alg": {"rsa":"RSA-OAEP-SHA256","aes":"AES-256-CBC","hmac":"HMAC-SHA256"}
            }
        except Exception as e:
            QMessageBox.critical(self, "Crypto error", f"Failed to prepare secure payload:\n{e}")
            return

        # POST
        try:
            r = requests.post(f"{base}/messages", json=payload, timeout=10)
            r.raise_for_status()
            resp = r.json()
            self._add_bubble(text, outgoing=True)
            score = resp.get("anomaly_score", 0)
            flagged = resp.get("flagged", False)
            self.footer.setText(f"HMAC ✔  |  AES ✔  |  Anomaly score: {score}  {'⚠️' if flagged else '✅'}")
            self.input.clear()
        except Exception as e:
            QMessageBox.critical(self, "Network error", f"Failed to send:\n{e}")
            self.footer.setText("Send failed.")

    def _add_bubble(self, text: str, outgoing: bool):
        bubble = MessageBubble(text, outgoing)
        self.messages_layout.insertWidget(self.messages_layout.count()-1, bubble)

def main():
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))
    win = ChatWindow(); win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()

