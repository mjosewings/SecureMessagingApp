
import sys, os, base64, json, requests
from datetime import datetime

# ---- PySide6 (GUI) ----
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QColor, QPalette
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QHBoxLayout, QLabel, QPushButton, QLineEdit, QTextEdit,
    QFrame, QScrollArea, QMessageBox, QComboBox, QListWidget,
    QListWidgetItem, QAbstractItemView, QDialog, QTabWidget
)

# ---- Matplotlib for charts ----
import matplotlib
matplotlib.use("QtAgg")  # Use QtAgg backend for embedding
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.backends.backend_pdf import PdfPages

# ---- pandas for quick aggregation ----
import pandas as pd

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.append(ROOT)

from shared.models import CampusMessage, serialize_campus_message
from shared.crypto_utils import (
    load_public_key, rsa_encrypt_oaep, generate_aes_key_iv,
    aes_cbc_encrypt, hmac_sha256, b64e
)

# -----------------------------------------------------------------------------
# Pre-Filled Lists (cleaned up — removed duplicates / typos)
# -----------------------------------------------------------------------------
DEPARTMENTS = [
    "American Studies", "Art", "Biology", "Business", "Chemistry",
    "Computer Science", "Corporate Communication", "Criminal Justice",
    "Cybersecurity Analytics and Operations",
    "Data Sciences", "Early Childhood/Elementary Education", "Engineering", "English",
    "Health Humanities", "History", "Information Technology", "Integrative Arts",
    "Integrative Science", "Multidisciplinary Studies", "Mathematics", "Nursing",
    "Physics", "Psychological and Social Sciences", "Race and Ethnic Studies",
    "Recreation, Park and Tourism Management", "Rehabilitation and Human Services",
    "Writing Program"
]

COURSES_BY_DEPARTMENT = {
    "Computer Science": ["CMPSC 131", "CMPSC 132", "CMPSC 221", "CMPSC 312", "CMPSC 330",
                         "CMPSC 360", "CMPSC 430", "CMPSC 441", "CMPSC 445", "CMPSC 446",
                         "CMPSC 463", "CMPSC 469", "CMPSC 487W", "CMPSC 488"],
    "Mathematics": ["MATH 140", "MATH 141", "MATH 220"],
    "English": ["ENGL 202C"],
    "Biology": [], "Business": [], "Chemistry": [], "Corporate Communication": [],
    "Criminal Justice": [], "Cybersecurity Analytics and Operations": [], "Data Sciences": [],
    "Early Childhood/Elementary Education": [], "Engineering": [], "Health Humanities": [],
    "History": [], "Information Technology": [], "Integrative Arts": [], "Integrative Science": [],
    "Multidisciplinary Studies": [], "Nursing": [], "Physics": [], "Psychological and Social Sciences": [],
    "Race and Ethnic Studies": [], "Recreation, Park and Tourism Management": [],
    "Rehabilitation and Human Services": [], "Writing Program": []
}

ROLES = ["Professor", "Program Chair", "Staff", "Advisor", "Admin"]
SEMESTERS = ["Fall 2024", "Spring 2025", "Summer 2025",
             "Fall 2025", "Spring 2026", "Summer 2026",
             "Fall 2026", "Spring 2027", "Summer 2027",
             "Fall 2027", "Spring 2028", "Summer 2028",
             "Fall 2028", "Spring 2029", "Summer 2029",
             "Fall 2029", "Spring 2030", "Summer 2030",
             "Fall 2030", "Spring 2031", "Summer 2031"]

# -----------------------------------------------------------------------------
# Styled UI components
# -----------------------------------------------------------------------------
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

# -----------------------------------------------------------------------------
# Analytics dialog (Tabs + Export PNG/PDF) — pulls from /messages and filters
# -----------------------------------------------------------------------------
class AnalyticsDialog(QDialog):
    def __init__(self, parent, base_url: str,
                 selected_departments: list[str],
                 selected_semesters: list[str],
                 selected_roles: list[str],
                 days_window: int):
        super().__init__(parent)
        self.setWindowTitle("Analytics Dashboard")
        self.resize(1000, 720)
        self.base_url = base_url
        self.selected_departments = selected_departments
        self.selected_semesters = selected_semesters
        self.selected_roles = selected_roles
        self.days_window = days_window

        self.tabs = QTabWidget(self)
        self.layout = QVBoxLayout(self)
        self.layout.addWidget(self.tabs)

        # Footer row
        btn_row = QHBoxLayout()
        self.export_btn = QPushButton("Export PNG + PDF")
        self.export_btn.setStyleSheet(parent._primary_btn("#7C3AED", "#F472B6"))
        self.export_btn.clicked.connect(self._export_reports)
        btn_row.addWidget(self.export_btn)

        self.status = QLabel("Ready.")
        self.status.setStyleSheet("color:#A7F3D0;")
        btn_row.addWidget(self.status)
        self.layout.addLayout(btn_row)

        # Build and render tabs
        try:
            df = self._load_dataframe()
            self._build_tabs(df)
        except Exception as e:
            QMessageBox.critical(self, "Analytics error", f"Failed to load dashboard:\n{e}")
            self.status.setText("Failed to load dashboard.")

    def _fetch_messages(self) -> list[dict]:
        r = requests.get(f"{self.base_url}/messages", timeout=12)
        r.raise_for_status()
        return r.json()

    def _load_dataframe(self) -> pd.DataFrame:
        data = self._fetch_messages()
        df = pd.DataFrame(data) if data else pd.DataFrame()
        if df.empty:
            return df

        # Normalize date/time
        if "created_at" in df.columns:
            df["created_at"] = pd.to_datetime(df["created_at"])
        else:
            df["created_at"] = pd.Timestamp.utcnow()
        df["date"] = df["created_at"].dt.date
        df["week"] = df["created_at"].dt.isocalendar().week

        # Apply filters (departments, semesters, roles)
        if self.selected_departments:
            df = df[df["department"].isin(self.selected_departments)]
        if self.selected_semesters:
            df = df[df["semester"].isin(self.selected_semesters)]
        if self.selected_roles:
            df = df[df["role"].isin(self.selected_roles)]

        # Apply time window to daily chart (we still use full df for weekly aggregation)
        self._df_for_daily = df.copy()
        if not df.empty and self.days_window in (7, 30, 90):
            cutoff = pd.Timestamp.utcnow().date() - pd.Timedelta(days=self.days_window)
            self._df_for_daily = df[df["date"] >= cutoff]

        return df

    # ---------------- Plot helpers (return Figure) ----------------
    def _fig_top10_courses(self, df: pd.DataFrame) -> plt.Figure:
        fig, ax = plt.subplots(figsize=(9, 5))
        if df.empty:
            ax.text(0.5, 0.5, "No data yet", ha="center", va="center"); ax.axis("off")
        else:
            s = (df.groupby("course_code")["id"].count()
                   .sort_values(ascending=False).head(10))
            s.plot(kind="bar", ax=ax, color="#7C3AED")
            ax.set_title("Top 10 Courses by Message Count")
            ax.set_xlabel("Course Code"); ax.set_ylabel("Messages")
            ax.tick_params(axis="x", rotation=45, ha="right")
        fig.tight_layout(); return fig

    def _fig_daily_volume(self) -> plt.Figure:
        fig, ax = plt.subplots(figsize=(9, 5))
        df = self._df_for_daily
        if df.empty:
            ax.text(0.5, 0.5, "No daily data", ha="center", va="center"); ax.axis("off")
        else:
            s = df.groupby("date")["id"].count()
            if s.empty:
                ax.text(0.5, 0.5, "No daily data", ha="center", va="center"); ax.axis("off")
            else:
                s.plot(kind="line", marker="o", ax=ax, color="#22D3EE")
                ax.set_title(f"Daily Message Volume (Last {self.days_window} Days)")
                ax.set_xlabel("Date"); ax.set_ylabel("Messages")
        fig.tight_layout(); return fig

    def _fig_weekly_volume(self, df: pd.DataFrame) -> plt.Figure:
        fig, ax = plt.subplots(figsize=(11, 5))
        if df.empty:
            ax.text(0.5, 0.5, "No weekly data", ha="center", va="center"); ax.axis("off")
        else:
            g = df.groupby(["semester", "week"])["id"].count().reset_index()
            if g.empty:
                ax.text(0.5, 0.5, "No weekly data", ha="center", va="center"); ax.axis("off")
            else:
                g["sem_week"] = g["semester"].astype(str) + " - W" + g["week"].astype(str)
                g.set_index("sem_week")["id"].plot(kind="bar", ax=ax, color="#10B981")
                ax.set_title("Weekly Message Volume (Semester / ISO Week)")
                ax.set_xlabel("Semester - Week"); ax.set_ylabel("Messages")
                ax.tick_params(axis="x", rotation=45, ha="right")
        fig.tight_layout(); return fig

    def _fig_flagged_by_course(self, df: pd.DataFrame) -> plt.Figure:
        fig, ax = plt.subplots(figsize=(9, 5))
        if df.empty or "flagged" not in df.columns:
            ax.text(0.5, 0.5, "No data yet", ha="center", va="center"); ax.axis("off")
        else:
            f = (df.groupby(["course_code", "flagged"])["id"].count()
                   .unstack(fill_value=0)
                   .rename(columns={False: "Normal", True: "Flagged"}))
            if f.empty:
                ax.text(0.5, 0.5, "No course data", ha="center", va="center"); ax.axis("off")
            else:
                f["Total"] = f.sum(axis=1)
                top = f.sort_values("Total", ascending=False).head(10)[["Normal", "Flagged"]]
                top.plot(kind="bar", stacked=True, ax=ax, color=["#22D3EE", "#F59E0B"])
                ax.set_title("Flagged vs Normal by Course (Top 10)")
                ax.set_xlabel("Course Code"); ax.set_ylabel("Messages")
                ax.legend(loc="upper right")
                ax.tick_params(axis="x", rotation=45, ha="right")
        fig.tight_layout(); return fig

    def _fig_roles(self, df: pd.DataFrame) -> plt.Figure:
        fig, ax = plt.subplots(figsize=(7, 6))
        if df.empty or "role" not in df.columns:
            ax.text(0.5, 0.5, "No data yet", ha="center", va="center"); ax.axis("off")
        else:
            s = df["role"].value_counts()
            if s.empty:
                ax.text(0.5, 0.5, "No role data", ha="center", va="center"); ax.axis("off")
            else:
                s.plot(kind="pie", ax=ax, autopct="%1.1f%%", startangle=90,
                       colors=["#7C3AED", "#22D3EE", "#10B981", "#F472B6", "#F59E0B"])
                ax.set_ylabel("")
                ax.set_title("Role Distribution")
        fig.tight_layout(); return fig

    def _fig_top10_departments(self, df: pd.DataFrame) -> plt.Figure:
        fig, ax = plt.subplots(figsize=(9, 5))
        if df.empty or "department" not in df.columns:
            ax.text(0.5, 0.5, "No data yet", ha="center", va="center"); ax.axis("off")
        else:
            s = (df.groupby("department")["id"].count()
                   .sort_values(ascending=False).head(10))
            if s.empty:
                ax.text(0.5, 0.5, "No department data", ha="center", va="center"); ax.axis("off")
            else:
                s.plot(kind="bar", ax=ax, color="#F472B6")
                ax.set_title("Top 10 Departments by Message Count")
                ax.set_xlabel("Department"); ax.set_ylabel("Messages")
                ax.tick_params(axis="x", rotation=45, ha="right")
        fig.tight_layout(); return fig

    def _add_tab(self, title: str, fig: plt.Figure):
        canvas = FigureCanvas(fig)
        tab = QWidget()
        lay = QVBoxLayout(tab)
        lay.addWidget(canvas)
        self.tabs.addTab(tab, title)

    def _build_tabs(self, df: pd.DataFrame):
        # Always show these tabs
        self._add_tab("Top 10 Courses", self._fig_top10_courses(df))
        self._add_tab("Daily Volume", self._fig_daily_volume())
        self._add_tab("Weekly Volume", self._fig_weekly_volume(df))
        self._add_tab("Flagged vs Normal", self._fig_flagged_by_course(df))
        self._add_tab("Roles", self._fig_roles(df))
        # Show Top 10 Departments only when no departments are selected
        if not self.selected_departments:
            self._add_tab("Top 10 Departments", self._fig_top10_departments(df))

    def _export_reports(self):
        try:
            df = self._load_dataframe()
            timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
            report_dir = os.path.join(os.getcwd(), "reports")
            os.makedirs(report_dir, exist_ok=True)
            png_path = os.path.join(report_dir, f"dashboard-{timestamp}.png")
            pdf_path = os.path.join(report_dir, f"dashboard-{timestamp}.pdf")

            # Build figures (same as tabs)
            figs = [
                ("Top 10 Courses", self._fig_top10_courses(df)),
                ("Daily Volume", self._fig_daily_volume()),
                ("Weekly Volume", self._fig_weekly_volume(df)),
                ("Flagged vs Normal", self._fig_flagged_by_course(df)),
                ("Roles", self._fig_roles(df))
            ]
            if not self.selected_departments:
                figs.append(("Top 10 Departments", self._fig_top10_departments(df)))

            # PNG — composite grid
            grid = plt.figure(figsize=(16, 12))
            gs = grid.add_gridspec(3, 2)
            axes = [grid.add_subplot(gs[0,0]), grid.add_subplot(gs[0,1]),
                    grid.add_subplot(gs[1,:]), grid.add_subplot(gs[2,0]), grid.add_subplot(gs[2,1])]
            for ax, (_, fig) in zip(axes, figs[:5]):  # first five in grid
                canvas = fig.canvas
                canvas.draw()
                buf = canvas.buffer_rgba()
                ax.imshow(buf)
                ax.axis("off")
            grid.suptitle("Secure Campus Messenger – Analytics Dashboard", fontsize=18, fontweight="bold")
            grid.tight_layout(rect=[0, 0.03, 1, 0.97])
            grid.savefig(png_path, dpi=200)
            plt.close(grid)

            # PDF — one page per figure
            with PdfPages(pdf_path) as pdf:
                for _, fig in figs:
                    pdf.savefig(fig)
                    plt.close(fig)

            self.status.setText(f"Exported ✔\nPNG: {png_path}\nPDF: {pdf_path}")
        except Exception as e:
            QMessageBox.critical(self, "Export error", f"Failed to export:\n{e}")
            self.status.setText("Export failed.")


# -----------------------------------------------------------------------------
# Main Chat Window
# -----------------------------------------------------------------------------
class ChatWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Campus Messenger")
        self.setMinimumSize(1200, 740)

        pal = self.palette()
        pal.setColor(QPalette.Window, QColor("#0F172A"))
        self.setPalette(pal)

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

        sb.addWidget(title)
        sb.addWidget(self.server_edit)
        sb.addWidget(self.fetch_btn)
        sb.addSpacing(8)
        sb.addWidget(Tag("RSA-OAEP", "#7C3AED"))
        sb.addWidget(Tag("AES-256-CBC", "#22D3EE"))
        sb.addWidget(Tag("HMAC-SHA256", "#F472B6"))
        sb.addSpacing(8)
        sb.addWidget(self.status_lbl)

        # --- Departments multi-select ---
        dept_header = QLabel("Departments (select none for campus-wide)")
        dept_header.setStyleSheet("color:#F8FAFC; font-weight:700;")
        sb.addWidget(dept_header)

        self.dept_list = QListWidget()
        self.dept_list.setSelectionMode(QAbstractItemView.MultiSelection)
        self.dept_list.setStyleSheet("QListWidget { background:#0B1220; color:#E5E7EB; border-radius:10px; }")
        for name in DEPARTMENTS:
            self.dept_list.addItem(QListWidgetItem(name))
        sb.addWidget(self.dept_list)

        # --- Semesters multi-select ---
        sem_header = QLabel("Semesters (select none for all)")
        sem_header.setStyleSheet("color:#F8FAFC; font-weight:700;")
        sb.addWidget(sem_header)

        self.sem_list = QListWidget()
        self.sem_list.setSelectionMode(QAbstractItemView.MultiSelection)
        self.sem_list.setStyleSheet("QListWidget { background:#0B1220; color:#E5E7EB; border-radius:10px; }")
        for s in SEMESTERS:
            self.sem_list.addItem(QListWidgetItem(s))
        sb.addWidget(self.sem_list)

        # --- Roles multi-select ---
        role_header = QLabel("Roles (select none for all)")
        role_header.setStyleSheet("color:#F8FAFC; font-weight:700;")
        sb.addWidget(role_header)

        self.role_list = QListWidget()
        self.role_list.setSelectionMode(QAbstractItemView.MultiSelection)
        self.role_list.setStyleSheet("QListWidget { background:#0B1220; color:#E5E7EB; border-radius:10px; }")
        for r in ROLES:
            self.role_list.addItem(QListWidgetItem(r))
        sb.addWidget(self.role_list)

        # --- Time window (daily chart) ---
        tw_header = QLabel("Time Window (daily)")
        tw_header.setStyleSheet("color:#F8FAFC; font-weight:700;")
        sb.addWidget(tw_header)

        self.time_window = QComboBox()
        self.time_window.addItems(["7 days", "30 days", "90 days"])
        self.time_window.setCurrentIndex(1)  # default 30 days
        self.time_window.setStyleSheet("QComboBox { background:#0B1220; color:#E5E7EB; border-radius:10px; padding:6px; }")
        sb.addWidget(self.time_window)

        # Dashboard button
        self.dashboard_btn = QPushButton("Open Dashboard")
        self.dashboard_btn.setStyleSheet(self._primary_btn("#10B981", "#22D3EE"))
        self.dashboard_btn.clicked.connect(self.open_dashboard)
        sb.addWidget(self.dashboard_btn)

        sb.addStretch()

        # Chat Card
        chat_card = GlassCard()
        cc = QVBoxLayout(chat_card); cc.setContentsMargins(14,14,14,14); cc.setSpacing(10)
        header = QLabel("Secure Chat"); header.setStyleSheet("color:#F8FAFC; font-size:20px; font-weight:800;")
        sub = QLabel("Encrypted via AES, integrity protected with HMAC, session-keyed using RSA.")
        sub.setStyleSheet("color:#94A3B8;")
        cc.addWidget(header); cc.addWidget(sub)

        # Context row (single selects for composing a message)
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

    # --- Dashboard ---
    def open_dashboard(self):
        base_url = self.server_edit.text().strip()

        selected_departments = [
            self.dept_list.item(i).text()
            for i in range(self.dept_list.count())
            if self.dept_list.item(i).isSelected()
        ]
        selected_semesters = [
            self.sem_list.item(i).text()
            for i in range(self.sem_list.count())
            if self.sem_list.item(i).isSelected()
        ]
        selected_roles = [
            self.role_list.item(i).text()
            for i in range(self.role_list.count())
            if self.role_list.item(i).isSelected()
        ]
        tw_text = self.time_window.currentText()
        days_window = 30
        if "7" in tw_text: days_window = 7
        elif "90" in tw_text: days_window = 90

        dlg = AnalyticsDialog(self, base_url,
                              selected_departments,
                              selected_semesters,
                              selected_roles,
                              days_window)
        dlg.exec()


def main():
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))
    win = ChatWindow(); win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
