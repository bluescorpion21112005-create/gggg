"""
Cybrix AI - Autonomous Multi-Agent Pentesting Platform (PySide6 client)
=========================================================================
Desktop client for the Cybrix AI FastAPI backend (`backend/main.py`).

- AI Chat streams tokens live from POST /api/v1/chat (Server-Sent Events)
  via QNetworkAccessManager — fully asynchronous, never blocks the GUI
  thread. Default provider is Fireworks AI, whose models (Qwen 2.5 Coder,
  DeepSeek-R1) run serverless on AMD Instinct(TM) MI300X GPU clusters
  through the ROCm runtime; Ollama remains available as a local runtime.
- Security Agents page drives POST /api/v1/pipeline: ten tool agents
  (Nmap, OWASP ZAP, sqlmap, Metasploit, Burp Suite, Wireshark, Gobuster,
  Hydra, John the Ripper, OpenVAS) run server-side with dynamic
  Agent-to-Agent (A2A) context routing — a finding from one agent (e.g.
  Nmap's open ports) becomes the trigger condition for the next. Every
  step streams back over SSE and is rendered as structured, typed logs.
- No local mock/offline fallback: chat and agent execution are fully
  backend-driven. If the backend is unreachable, the UI surfaces a clear,
  non-blocking error instead of fabricating a response.
"""
import sys
import os
import re
import math
import hashlib
import ipaddress
import json
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from urllib.parse import urlparse

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QListWidget, QListWidgetItem, QStackedWidget, QLabel, QPushButton,
    QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QFileDialog, QGroupBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox, QScrollArea,
    QFrame, QSizePolicy, QSplitter, QCheckBox
)
from PySide6.QtCore import Qt, Signal, QDateTime, QTimer, QUrl, QByteArray, QObject
from PySide6.QtGui import QFont, QColor, QTextCursor
from PySide6.QtNetwork import QNetworkAccessManager, QNetworkRequest, QNetworkReply

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    import validators
    HAS_VALIDATORS = True
except ImportError:
    HAS_VALIDATORS = False


# ============================================================================
# BACKEND CONNECTION
# ============================================================================

BACKEND_HOST = os.environ.get("CYBRIX_BACKEND_HOST", "127.0.0.1")
BACKEND_PORT = os.environ.get("CYBRIX_BACKEND_PORT", "8000")
BACKEND_BASE_URL = f"http://{BACKEND_HOST}:{BACKEND_PORT}/api/v1"

DEFAULT_FIREWORKS_MODEL = "accounts/fireworks/models/qwen2p5-coder-32b-instruct"
DEFAULT_OLLAMA_MODEL = "llama3"


# ============================================================================
# DOMAIN / SHARED STATE
# ============================================================================

@dataclass
class AnalysisRecord:
    kind: str
    summary: str
    detail: str
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


class SessionStore:
    def __init__(self):
        self.records: List[AnalysisRecord] = []

    def add(self, kind: str, summary: str, detail: str):
        self.records.append(AnalysisRecord(kind, summary, detail))


SESSION = SessionStore()


# ============================================================================
# IOC VALIDATOR
# ============================================================================

SUSPICIOUS_TLDS = {'.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.info', '.cc'}


class IOCValidator:
    @staticmethod
    def validate(ioc_type: str, value: str) -> Dict:
        ioc_type = ioc_type.lower()
        result = {'risk_score': 0, 'notes': [], 'is_private': False}
        try:
            if ioc_type == 'ip':
                result.update(IOCValidator._check_ip(value))
            elif ioc_type == 'domain':
                result.update(IOCValidator._check_domain(value))
            elif ioc_type == 'url':
                result.update(IOCValidator._check_url(value))
            elif ioc_type == 'hash':
                result.update(IOCValidator._check_hash(value))
            elif ioc_type == 'email':
                result.update(IOCValidator._check_email(value))
            elif ioc_type == 'filename':
                result.update(IOCValidator._check_filename(value))
        except Exception as e:
            result['notes'].append(f"Tekshirishda xatolik: {e}")
        return result

    @staticmethod
    def _check_ip(ip: str) -> Dict:
        notes, risk, is_private = [], 0, False
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                is_private = True
                notes.append("Bu shaxsiy (private) IP manzil (RFC 1918). Tashqi tarmoqdan yo'nalmaydi.")
                risk = max(risk, 1)
            if ip_obj.is_multicast:
                notes.append("Multicast IP - C2 uchun odatiy emas.")
                risk += 1
            if ip_obj.is_loopback:
                notes.append("Loopback manzil - ehtimol xato signal (false positive).")
                risk = 0
        except ValueError:
            notes.append("IP format noto'g'ri.")
            risk = 5
        return {'risk_score': risk, 'notes': notes, 'is_private': is_private}

    @staticmethod
    def _check_domain(domain: str) -> Dict:
        notes, risk = [], 0
        if HAS_VALIDATORS and not validators.domain(domain):
            notes.append("Domen formati noto'g'ri.")
            return {'risk_score': 5, 'notes': notes}
        tld = '.' + domain.split('.')[-1] if '.' in domain else ''
        if tld.lower() in SUSPICIOUS_TLDS:
            notes.append(f"'{tld}' domeni ko'pincha zararli dastur/fishingda ishlatiladi.")
            risk += 3
        subdomain = domain.split('.')[0] if domain.count('.') >= 2 else ''
        if len(subdomain) > 20 and re.search(r'[a-zA-Z]{3,}\d{3,}', subdomain):
            notes.append("Tasodifiy ko'rinishdagi subdomen - DGA (Domain Generation Algorithm) belgisi bo'lishi mumkin.")
            risk += 3
        if risk == 0:
            notes.append("Shubhali belgi topilmadi.")
        return {'risk_score': min(risk, 10), 'notes': notes}

    @staticmethod
    def _check_url(url: str) -> Dict:
        notes, risk = [], 0
        if HAS_VALIDATORS and not validators.url(url):
            notes.append("URL formati noto'g'ri.")
            return {'risk_score': 5, 'notes': notes}
        if any(kw in url.lower() for kw in ['/admin', '/login', '/cpanel', '/wp-admin', 'cmd=', 'exec=']):
            notes.append("URL tarkibida ko'pincha nishonga olinadigan yo'l/parametrlar bor.")
            risk += 2
        domain = urlparse(url).netloc
        if domain:
            domain_result = IOCValidator._check_domain(domain)
            risk += domain_result['risk_score'] // 2
            notes.extend([n for n in domain_result['notes'] if "topilmadi" not in n])
        return {'risk_score': min(risk, 10), 'notes': notes or ["Shubhali belgi topilmadi."]}

    @staticmethod
    def _check_hash(hash_str: str) -> Dict:
        notes, risk = [], 0
        if len(hash_str) not in (32, 40, 64):
            notes.append("Xesh uzunligi MD5/SHA1/SHA256 ga mos kelmaydi.")
            risk += 2
        elif all(c == '0' for c in hash_str):
            notes.append("Xesh butunlay noldan iborat - ehtimol yolg'on signal.")
        else:
            length_map = {32: "MD5", 40: "SHA1", 64: "SHA256"}
            notes.append(f"Format: {length_map[len(hash_str)]} sifatida aniqlandi.")
        return {'risk_score': risk, 'notes': notes}

    @staticmethod
    def _check_email(email: str) -> Dict:
        notes, risk = [], 0
        if HAS_VALIDATORS and not validators.email(email):
            notes.append("Email formati noto'g'ri.")
            return {'risk_score': 2, 'notes': notes}
        domain = email.split('@')[-1].lower()
        if domain in ('gmail.com', 'yahoo.com', 'outlook.com', 'mail.ru'):
            notes.append(f"Bepul email provayder ({domain}) - fishing kampaniyalarida keng tarqalgan.")
            risk += 2
        if 'rnicrosoft' in domain or 'micr0soft' in domain:
            notes.append("Domen taqlid qilingan (typosquat) - yuqori xavf.")
            risk = 10
        if risk == 0:
            notes.append("Shubhali belgi topilmadi.")
        return {'risk_score': min(risk, 10), 'notes': notes}

    @staticmethod
    def _check_filename(filename: str) -> Dict:
        notes, risk = [], 0
        suspicious_exts = {'.exe', '.scr', '.bat', '.ps1', '.vbs', '.js', '.jar', '.docm', '.xlsm'}
        ext = '.' + filename.rsplit('.', 1)[-1] if '.' in filename else ''
        if ext.lower() in suspicious_exts:
            notes.append(f"Bajariladigan/shubhali kengaytma: {ext}")
            risk += 3
        if filename.count('.') > 1 and ext.lower() in ('.pdf', '.docx', '.xlsx', '.zip'):
            notes.append("Ikkita kengaytma - fayl niqoblangan (masquerading) bo'lishi mumkin.")
            risk += 4
        if any(name in filename.lower() for name in ('invoice', 'payment', 'order', 'shipping', 'dhl')):
            notes.append("Fayl nomi odatiy fishing hiylasiga o'xshaydi.")
            risk += 2
        if risk == 0:
            notes.append("Shubhali belgi topilmadi.")
        return {'risk_score': min(risk, 10), 'notes': notes}


# ============================================================================
# MALWARE (PE) ANALYZER
# ============================================================================

SUSPICIOUS_APIS = {
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "WriteProcessMemory",
    "CreateRemoteThread", "NtCreateThreadEx", "RtlCreateUserThread",
    "QueueUserAPC", "SetWindowsHookEx", "OpenProcess", "ReadProcessMemory",
    "CreateProcess", "WinExec", "ShellExecute", "URLDownloadToFile",
    "GetProcAddress", "LoadLibrary", "CryptAcquireContext", "CryptEncrypt",
    "WSASocket", "connect", "send", "recv", "InternetOpen", "InternetConnect",
    "RegCreateKey", "RegSetValue", "RegDeleteKey", "CreateService",
    "StartService", "ControlService"
}


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    for f in freq:
        if f:
            p = f / length
            entropy -= p * math.log2(p)
    return round(entropy, 2)


def analyze_file(path: str) -> Dict:
    with open(path, 'rb') as f:
        data = f.read()

    result = {
        'file_path': path,
        'file_size': len(data),
        'md5': hashlib.md5(data).hexdigest(),
        'sha1': hashlib.sha1(data).hexdigest(),
        'sha256': hashlib.sha256(data).hexdigest(),
        'entropy': calculate_entropy(data),
        'is_pe': data[:2] == b'MZ',
        'sections': [],
        'imports': [],
        'suspicious_apis': [],
        'packer_indicators': [],
        'pe_error': None,
    }

    if result['is_pe'] and HAS_PEFILE:
        try:
            pe = pefile.PE(data=data)
            result['machine'] = hex(pe.FILE_HEADER.Machine)
            result['subsystem'] = pe.OPTIONAL_HEADER.Subsystem
            for section in pe.sections:
                result['sections'].append({
                    'name': section.Name.decode(errors='ignore').strip('\x00'),
                    'raw_size': section.SizeOfRawData,
                    'entropy': calculate_entropy(section.get_data()),
                })
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode(errors='ignore') if entry.dll else ''
                    for imp in entry.imports:
                        if imp.name:
                            fn = imp.name.decode(errors='ignore')
                            result['imports'].append(f"{dll}.{fn}")
                            if fn in SUSPICIOUS_APIS:
                                result['suspicious_apis'].append(f"{dll}.{fn}")
            indicators = []
            if any(s['entropy'] > 7.0 for s in result['sections']):
                indicators.append("Yuqori entropiyali seksiya(lar) - siqilgan/shifrlangan bo'lishi mumkin.")
            if result['entropy'] > 7.5:
                indicators.append("Umumiy fayl entropiyasi yuqori (packer belgisi).")
            if len(result['imports']) < 5:
                indicators.append("Juda kam import - packing belgisi bo'lishi mumkin.")
            result['packer_indicators'] = indicators
        except Exception as e:
            result['pe_error'] = str(e)
    elif result['is_pe'] and not HAS_PEFILE:
        result['pe_error'] = "'pefile' kutubxonasi o'rnatilmagan - faqat hash/entropiya ko'rsatilyapti."

    return result


# ============================================================================
# LOG ANALYZER
# ============================================================================

IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
LEVEL_RE = re.compile(r'\b(ERROR|CRITICAL|FATAL|WARNING|WARN|FAILED?)\b', re.IGNORECASE)


def analyze_log_text(text: str) -> Dict:
    lines = text.splitlines()
    ips = IP_RE.findall(text)
    ip_counts: Dict[str, int] = {}
    for ip in ips:
        ip_counts[ip] = ip_counts.get(ip, 0) + 1

    flagged_lines = []
    for i, line in enumerate(lines, start=1):
        if LEVEL_RE.search(line):
            flagged_lines.append((i, line.strip()))

    return {
        'total_lines': len(lines),
        'unique_ips': len(ip_counts),
        'top_ips': sorted(ip_counts.items(), key=lambda x: -x[1])[:10],
        'flagged_count': len(flagged_lines),
        'flagged_lines': flagged_lines[:200],
    }


# ============================================================================
# SSE NETWORK CLIENT (async, non-blocking) — shared by Chat and Agents pages
# ============================================================================

class SSEStreamClient(QObject):
    """Streams a Server-Sent-Events POST response from the FastAPI backend.

    Fully asynchronous (QNetworkAccessManager never blocks the Qt event
    loop). Distinguishes three failure modes so the UI can react correctly:
      - transport-level errors (backend down, connection refused/timeout)
      - HTTP-level errors returned before the stream opens (400/404/500)
      - "error" events emitted mid-stream by the backend itself
    """
    event_received = Signal(dict)
    stream_finished = Signal()
    error_occurred = Signal(str, int)  # message, http_status (0 = transport-level)

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._nam = QNetworkAccessManager(self)
        self._reply: Optional[QNetworkReply] = None
        self._buffer = b""
        self._status_code: Optional[int] = None
        self._transport_error: Optional[str] = None

    def is_busy(self) -> bool:
        return self._reply is not None

    def post(self, url: str, payload: dict, timeout_ms: int = 60000):
        if self._reply is not None:
            return  # a request is already in flight; caller should disable the trigger control
        self._buffer = b""
        self._status_code = None
        self._transport_error = None
        request = QNetworkRequest(QUrl(url))
        request.setHeader(QNetworkRequest.ContentTypeHeader, "application/json")
        request.setTransferTimeout(timeout_ms)
        body = QByteArray(json.dumps(payload).encode("utf-8"))
        self._reply = self._nam.post(request, body)
        self._reply.readyRead.connect(self._on_ready_read)
        self._reply.finished.connect(self._on_finished)
        self._reply.errorOccurred.connect(self._on_network_error)

    def _on_ready_read(self):
        if self._reply is None:
            return
        if self._status_code is None:
            code = self._reply.attribute(QNetworkRequest.HttpStatusCodeAttribute)
            if code:
                self._status_code = int(code)
        self._buffer += bytes(self._reply.readAll())
        if self._status_code == 200:
            self._drain_sse_frames()

    def _drain_sse_frames(self):
        while b"\n\n" in self._buffer:
            frame, self._buffer = self._buffer.split(b"\n\n", 1)
            for line in frame.split(b"\n"):
                if not line.startswith(b"data:"):
                    continue
                raw = line[len(b"data:"):].strip()
                if not raw:
                    continue
                try:
                    payload = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                self.event_received.emit(payload)

    def _on_network_error(self, _code):
        # errorOccurred vs. readyRead ordering is not guaranteed by Qt, so this
        # handler only records the transport-level message — _on_finished is the
        # single place that decides what (if anything) to report, once the HTTP
        # status (if any) is reliably known.
        if self._reply is None or self._reply.error() == QNetworkReply.NoError:
            return
        self._transport_error = self._reply.errorString()

    def _on_finished(self):
        reply = self._reply
        if reply is None:
            return
        if self._status_code is None:
            code = reply.attribute(QNetworkRequest.HttpStatusCodeAttribute)
            if code:
                self._status_code = int(code)

        if self._status_code and self._status_code != 200:
            try:
                body = json.loads(self._buffer.decode("utf-8"))
                detail = body.get("detail", str(body))
            except Exception:
                detail = self._buffer.decode("utf-8", errors="ignore") or f"HTTP {self._status_code}"
            self.error_occurred.emit(detail, self._status_code)
        elif self._transport_error:
            self.error_occurred.emit(self._transport_error, 0)
        self._reply = None
        self.stream_finished.emit()
        reply.deleteLater()


# ============================================================================
# UI: AI CHAT PAGE (streams from FastAPI backend -> Fireworks / Ollama)
# ============================================================================

class ChatPage(QWidget):
    def __init__(self):
        super().__init__()
        self.sse = SSEStreamClient(self)
        self.sse.event_received.connect(self._on_event)
        self.sse.error_occurred.connect(self._on_error)
        self.sse.stream_finished.connect(self._on_stream_finished)

        self._stream_start: Optional[QDateTime] = None
        self._stream_tokens = 0
        self._response_cursor: Optional[QTextCursor] = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)

        title = QLabel("AI Chat — Fireworks AI (AMD Instinct MI300X / ROCm) yoki Ollama")
        title.setFont(QFont("Segoe UI", 18, QFont.Bold))
        layout.addWidget(title)

        provider_layout = QHBoxLayout()
        provider_layout.addWidget(QLabel("Provayder:"))
        self.provider_combo = QComboBox()
        self.provider_combo.addItems(["Fireworks", "Ollama"])
        self.provider_combo.currentTextChanged.connect(self._on_provider_changed)
        provider_layout.addWidget(self.provider_combo)

        provider_layout.addWidget(QLabel("Model:"))
        self.model_edit = QLineEdit()
        self.model_edit.setPlaceholderText(f"bo'sh qoldirsangiz: {DEFAULT_FIREWORKS_MODEL}")
        provider_layout.addWidget(self.model_edit, 1)
        layout.addLayout(provider_layout)

        self.history = QTextEdit()
        self.history.setReadOnly(True)
        layout.addWidget(self.history, 1)

        input_row = QHBoxLayout()
        self.input = QLineEdit()
        self.input.setPlaceholderText("Xabaringizni yozing...")
        self.input.returnPressed.connect(self._send)
        self.send_btn = QPushButton("Yuborish")
        self.send_btn.clicked.connect(self._send)
        input_row.addWidget(self.input, 1)
        input_row.addWidget(self.send_btn)
        layout.addLayout(input_row)

        self.status_label = QLabel(f"Provayder: Fireworks · {BACKEND_BASE_URL}/chat")
        self.status_label.setStyleSheet("color: #9aa4b2;")
        layout.addWidget(self.status_label)

    def _on_provider_changed(self, provider_name: str):
        if provider_name == "Fireworks":
            self.status_label.setText(f"Provayder: Fireworks (AMD Instinct MI300X / ROCm) · {BACKEND_BASE_URL}/chat")
        else:
            self.status_label.setText(f"Provayder: Ollama (local runtime) · {BACKEND_BASE_URL}/chat")
        self.status_label.setStyleSheet("color: #9aa4b2;")

    def _append(self, who: str, text: str):
        color = "#2f6fed" if who != "Siz" else "#9aa4b2"
        self.history.append(f'<b style="color:{color}">{who}:</b> {text}<br>')

    def _send(self):
        if self.sse.is_busy():
            return
        text = self.input.text().strip()
        if not text:
            return
        self._append("Siz", text)
        self.input.clear()
        self.input.setEnabled(False)
        self.send_btn.setEnabled(False)

        provider = "fireworks" if self.provider_combo.currentText() == "Fireworks" else "ollama"
        model = self.model_edit.text().strip()

        self._stream_start = QDateTime.currentDateTime()
        self._stream_tokens = 0
        self.history.append('<b style="color:#2f6fed">Cybrix AI:</b> ')
        self._response_cursor = self.history.textCursor()
        self._response_cursor.movePosition(QTextCursor.End)

        self.sse.post(f"{BACKEND_BASE_URL}/chat", {
            "message": text,
            "provider": provider,
            "model": model,
        })

    def _on_event(self, payload: dict):
        event = payload.get("event")
        if event == "token":
            self._stream_tokens += 1
            cursor = self.history.textCursor()
            cursor.movePosition(QTextCursor.End)
            cursor.insertText(payload.get("data", ""))
            self.history.setTextCursor(cursor)
            self.history.ensureCursorVisible()
            elapsed = max(self._stream_start.msecsTo(QDateTime.currentDateTime()) / 1000.0, 1e-6)
            self.status_label.setText(
                f"⚡ oqib kelmoqda... {self._stream_tokens} token · {self._stream_tokens / elapsed:.1f} tok/s"
            )
            self.status_label.setStyleSheet("color: #3ac96a;")
        elif event == "done":
            meta = payload.get("meta", {})
            self.history.append("")
            self.status_label.setText(
                f"✅ {meta.get('provider', '?')} ({meta.get('model', '?')}) · "
                f"{meta.get('tokens_generated', 0)} token · {meta.get('elapsed_ms', 0):.0f} ms · "
                f"{meta.get('tokens_per_second', 0):.1f} tok/s · {meta.get('compute_backend', '')}"
            )
            self.status_label.setStyleSheet("color: #9aa4b2;")
        elif event == "notice":
            self.history.append(f"<i style='color:#e0a63a;'>ℹ {payload.get('detail', '')}</i><br>")
        elif event == "error":
            self._append_stream_error(payload.get("detail", "Noma'lum xatolik"))

    def _append_stream_error(self, message: str):
        self.history.append(f"<i style='color:#e05a4e;'>⚠ Xatolik: {message}</i><br>")
        self.status_label.setText("❌ Chat xatolik bilan yakunlandi")
        self.status_label.setStyleSheet("color: #e05a4e;")

    def _on_error(self, message: str, status_code: int):
        if status_code == 0:
            self._append_stream_error(f"Backend serverga ulanib bo'lmadi ({message}).")
            QMessageBox.critical(
                self, "Backend ulanish xatosi",
                "FastAPI backend bilan bog'lanib bo'lmadi.\n\n"
                f"Manzil: {BACKEND_BASE_URL}/chat\n"
                f"Sabab: {message}\n\n"
                "Backendni ishga tushiring:\n"
                "  uvicorn backend.main:app --host 127.0.0.1 --port 8000"
            )
        else:
            self._append_stream_error(f"HTTP {status_code}: {message}")

    def _on_stream_finished(self):
        self.input.setEnabled(True)
        self.send_btn.setEnabled(True)
        self.input.setFocus()


# ============================================================================
# UI: SECURITY AGENTS PAGE (A2A pentest pipeline via FastAPI backend)
# ============================================================================

class AgentsPage(QWidget):
    def __init__(self, refresh_dashboard=None):
        super().__init__()
        self._refresh_dashboard = refresh_dashboard
        self._agents_meta: List[dict] = []

        self.pipeline_sse = SSEStreamClient(self)
        self.pipeline_sse.event_received.connect(self._on_pipeline_event)
        self.pipeline_sse.error_occurred.connect(self._on_pipeline_error)
        self.pipeline_sse.stream_finished.connect(self._on_pipeline_finished)

        self._agents_nam = QNetworkAccessManager(self)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)

        title = QLabel("Security Tool Agents — A2A Pentesting Pipeline")
        title.setFont(QFont("Segoe UI", 18, QFont.Bold))
        layout.addWidget(title)

        disclaimer = QLabel(
            "Faqat ruxsat etilgan (o'zingizga tegishli / lab / CTF) maqsadlar uchun ishlating. "
            "Natijalar strukturalangan simulyatsiya bo'lib, backend orqali (dynamic A2A context routing) generatsiya qilinadi."
        )
        disclaimer.setStyleSheet("color: #9aa4b2;")
        disclaimer.setWordWrap(True)
        layout.addWidget(disclaimer)

        control_row = QHBoxLayout()
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("Target (IP, domain, or URL)")
        self.run_btn = QPushButton("Run Selected Agent(s)")
        self.run_btn.clicked.connect(self._run_selected)
        self.chain_btn = QPushButton("Run A2A Chain (Nmap → ...)")
        self.chain_btn.clicked.connect(self._run_chain)
        self.reload_btn = QPushButton("⟳ Agentlarni qayta yuklash")
        self.reload_btn.clicked.connect(self._load_agents)
        control_row.addWidget(QLabel("Target:"))
        control_row.addWidget(self.target_edit, 2)
        control_row.addWidget(self.run_btn)
        control_row.addWidget(self.chain_btn)
        control_row.addWidget(self.reload_btn)
        layout.addLayout(control_row)

        splitter = QSplitter(Qt.Horizontal)
        agent_group = QGroupBox("Agents")
        agent_layout = QVBoxLayout(agent_group)
        self.agent_list = QListWidget()
        self.agent_list.setSelectionMode(QListWidget.MultiSelection)
        agent_layout.addWidget(self.agent_list)
        splitter.addWidget(agent_group)

        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        output_group = QGroupBox("Execution Results")
        output_layout = QVBoxLayout(output_group)
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        output_layout.addWidget(self.output_text)
        right_layout.addWidget(output_group, 2)

        event_group = QGroupBox("A2A Event Log")
        event_layout = QVBoxLayout(event_group)
        self.event_log = QTextEdit()
        self.event_log.setReadOnly(True)
        event_layout.addWidget(self.event_log)
        right_layout.addWidget(event_group, 1)

        splitter.addWidget(right_widget)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 3)
        layout.addWidget(splitter, 1)

        self._load_agents()

    # -- Agent catalogue (GET /api/v1/agents) --------------------------------

    def _load_agents(self):
        self.agent_list.clear()
        self.agent_list.addItem("Yuklanmoqda...")
        request = QNetworkRequest(QUrl(f"{BACKEND_BASE_URL}/agents"))
        reply = self._agents_nam.get(request)
        reply.finished.connect(lambda: self._on_agents_loaded(reply))

    def _on_agents_loaded(self, reply: QNetworkReply):
        self.agent_list.clear()
        if reply.error() != QNetworkReply.NoError:
            self.agent_list.addItem("⚠ Backend bilan bog'lanib bo'lmadi")
            self._append_event_line(f"Backend ulanish xatosi: {reply.errorString()}")
            reply.deleteLater()
            return
        try:
            self._agents_meta = json.loads(bytes(reply.readAll()).decode("utf-8"))
        except json.JSONDecodeError as exc:
            self.agent_list.addItem("⚠ Javobni tahlil qilib bo'lmadi")
            self._append_event_line(f"JSON xatosi: {exc}")
            reply.deleteLater()
            return
        for agent in self._agents_meta:
            item = QListWidgetItem(f"{agent['name']}\n{agent['description']}")
            item.setData(Qt.UserRole, agent["name"])
            self.agent_list.addItem(item)
        reply.deleteLater()

    # -- Pipeline execution (POST /api/v1/pipeline, SSE) ---------------------

    def _set_running(self, running: bool):
        self.run_btn.setEnabled(not running)
        self.chain_btn.setEnabled(not running)
        self.target_edit.setEnabled(not running)

    def _run_selected(self):
        target = self.target_edit.text().strip()
        if not target:
            QMessageBox.warning(self, "Warning", "Target bo'sh bo'lishi mumkin emas.")
            return
        selected = [item.data(Qt.UserRole) for item in self.agent_list.selectedItems() if item.data(Qt.UserRole)]
        if not selected:
            QMessageBox.warning(self, "Warning", "Kamida bitta agentni tanlang.")
            return
        self._start_pipeline(target, mode="manual", agents=selected)

    def _run_chain(self):
        target = self.target_edit.text().strip()
        if not target:
            QMessageBox.warning(self, "Warning", "Target bo'sh bo'lishi mumkin emas.")
            return
        self._start_pipeline(target, mode="chain", agents=[])

    def _start_pipeline(self, target: str, mode: str, agents: List[str]):
        if self.pipeline_sse.is_busy():
            return
        self.output_text.clear()
        self.event_log.clear()
        self._set_running(True)
        self.output_text.append(f"=== A2A pipeline started: target={target} mode={mode} ===\n")
        self.pipeline_sse.post(f"{BACKEND_BASE_URL}/pipeline", {
            "target": target, "mode": mode, "agents": agents,
        })

    def _append_event_line(self, text: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.event_log.append(f"[{timestamp}] {text}")

    def _on_pipeline_event(self, payload: dict):
        event = payload.get("event")
        if event == "pipeline_started":
            self._append_event_line(f"Pipeline boshlandi → target={payload.get('target')} mode={payload.get('mode')}")
        elif event == "agent_started":
            agent = payload.get("agent")
            self.output_text.append(f"▶ {agent} [{payload.get('tool_type')}] ishga tushirildi")
            self._append_event_line(f"{agent} STARTED — sabab: {payload.get('reason')}")
        elif event == "agent_completed":
            self._render_agent_result(payload)
            self._append_event_line(
                f"{payload.get('agent')} → COMPLETED ({payload.get('duration_ms'):.0f} ms) — {payload.get('routing_reason')}"
            )
        elif event == "pipeline_completed":
            self._render_final_context(payload.get("context", {}))
        elif event == "error":
            self._render_error(payload.get("detail", "Noma'lum xatolik"))

    def _render_agent_result(self, payload: dict):
        agent = payload.get("agent")
        result = payload.get("result", {})
        summary = result.get("summary", "")
        lines = [f"=== {agent} ({payload.get('duration_ms'):.0f} ms) ==="]
        if summary:
            lines.append(summary)
        for key, value in result.items():
            if key == "summary":
                continue
            lines.append(f"  {key}: {json.dumps(value, ensure_ascii=False)}")
        lines.append("")
        self.output_text.append("\n".join(lines))

    def _render_final_context(self, ctx: dict):
        lines = ["=== Yakuniy hisobot (shared A2A context) ===",
                 f"Target: {ctx.get('target')}",
                 f"Ochiq portlar: {ctx.get('open_ports')}",
                 f"Zaifliklar: {len(ctx.get('vulnerabilities', []))} ta",
                 f"Aniqlangan credential(lar): {len(ctx.get('credentials', []))} ta",
                 f"Kraklangan parollar: {len(ctx.get('cracked', []))} ta",
                 f"Ochilgan sessiyalar: {len(ctx.get('sessions', []))} ta",
                 f"Ishga tushirilgan agentlar: {', '.join(ctx.get('ran_agents', []))}"]
        self.output_text.append("\n".join(lines))
        SESSION.add(
            "agents",
            f"A2A pipeline on {ctx.get('target')} ({len(ctx.get('ran_agents', []))} agent)",
            json.dumps(ctx, ensure_ascii=False, indent=2),
        )
        if self._refresh_dashboard:
            self._refresh_dashboard()

    def _render_error(self, detail: str):
        self.output_text.append(f'<span style="color:#e05a4e;">⚠ Xatolik: {detail}</span>')
        self._append_event_line(f"ERROR — {detail}")

    def _on_pipeline_error(self, message: str, status_code: int):
        if status_code == 0:
            self._render_error(f"Backend serverga ulanib bo'lmadi ({message}).")
            QMessageBox.critical(
                self, "Backend ulanish xatosi",
                "FastAPI backend bilan bog'lanib bo'lmadi.\n\n"
                f"Manzil: {BACKEND_BASE_URL}/pipeline\n"
                f"Sabab: {message}\n\n"
                "Backendni ishga tushiring:\n"
                "  uvicorn backend.main:app --host 127.0.0.1 --port 8000"
            )
        else:
            self._render_error(f"HTTP {status_code}: {message}")

    def _on_pipeline_finished(self):
        self._set_running(False)


# ============================================================================
# DASHBOARD PAGE
# ============================================================================

class DashboardPage(QWidget):
    def __init__(self, goto_callback):
        super().__init__()
        self._goto = goto_callback
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)

        title = QLabel("Cybrix AI — Xavfsizlik boshqaruv paneli")
        title.setFont(QFont("Segoe UI", 20, QFont.Bold))
        layout.addWidget(title)

        subtitle = QLabel(
            "Autonomous Multi-Agent Pentesting Platform · FastAPI backend + A2A orchestration · "
            "Fireworks AI on AMD Instinct MI300X (ROCm)."
        )
        subtitle.setStyleSheet("color: #9aa4b2;")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        stats_row = QHBoxLayout()
        self.stat_labels = {}
        for key, label in [("ioc", "IOC tekshiruvlari"), ("malware", "Fayl tahlillari"),
                            ("log", "Log tahlillari"), ("agents", "Agent ishga tushirish"),
                            ("total", "Jami tahlillar")]:
            box = QGroupBox(label)
            v = QVBoxLayout(box)
            val = QLabel("0")
            val.setFont(QFont("Segoe UI", 22, QFont.Bold))
            val.setStyleSheet("color: #2f6fed;")
            v.addWidget(val)
            self.stat_labels[key] = val
            stats_row.addWidget(box)
        layout.addLayout(stats_row)

        qa_box = QGroupBox("Tezkor amallar")
        qa_layout = QHBoxLayout(qa_box)
        actions = [
            ("IOC tekshirish", "ioc"),
            ("Fayl tahlil qilish", "malware"),
            ("Log yuklash", "log"),
            ("AI Chat", "chat"),
            ("Hisobot yaratish", "report"),
            ("Security Agents", "agents"),
        ]
        for label, key in actions:
            btn = QPushButton(label)
            btn.clicked.connect(lambda _, k=key: self._goto(k))
            qa_layout.addWidget(btn)
        layout.addWidget(qa_box)

        recent_box = QGroupBox("So'nggi tahlillar")
        recent_layout = QVBoxLayout(recent_box)
        self.recent_list = QListWidget()
        recent_layout.addWidget(self.recent_list)
        layout.addWidget(recent_box, 1)

        layout.addStretch()

    def refresh(self):
        counts = {"ioc": 0, "malware": 0, "log": 0, "agents": 0}
        for r in SESSION.records:
            if r.kind in counts:
                counts[r.kind] += 1
        for k in counts:
            self.stat_labels[k].setText(str(counts[k]))
        self.stat_labels["total"].setText(str(len(SESSION.records)))

        self.recent_list.clear()
        for r in reversed(SESSION.records[-15:]):
            self.recent_list.addItem(f"[{r.timestamp}] ({r.kind}) {r.summary}")


# ============================================================================
# OTHER PAGES (Log, Malware, IOC, Reports)
# ============================================================================

class LogAnalyzerPage(QWidget):
    def __init__(self, refresh_dashboard):
        super().__init__()
        self._refresh_dashboard = refresh_dashboard
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)

        title = QLabel("Log Analyzer")
        title.setFont(QFont("Segoe UI", 18, QFont.Bold))
        layout.addWidget(title)

        row = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setReadOnly(True)
        self.path_edit.setPlaceholderText("Log fayl tanlanmagan...")
        browse_btn = QPushButton("Fayl tanlash")
        browse_btn.clicked.connect(self._browse)
        row.addWidget(self.path_edit, 1)
        row.addWidget(browse_btn)
        layout.addLayout(row)

        summary_box = QGroupBox("Xulosa")
        summary_layout = QGridLayout(summary_box)
        self.lbl_lines = QLabel("-")
        self.lbl_ips = QLabel("-")
        self.lbl_flagged = QLabel("-")
        summary_layout.addWidget(QLabel("Jami qatorlar:"), 0, 0)
        summary_layout.addWidget(self.lbl_lines, 0, 1)
        summary_layout.addWidget(QLabel("Unikal IP manzillar:"), 1, 0)
        summary_layout.addWidget(self.lbl_ips, 1, 1)
        summary_layout.addWidget(QLabel("Xato/ogohlantirish qatorlari:"), 2, 0)
        summary_layout.addWidget(self.lbl_flagged, 2, 1)
        layout.addWidget(summary_box)

        tables_row = QHBoxLayout()

        ip_box = QGroupBox("Eng ko'p uchragan IP manzillar")
        ip_layout = QVBoxLayout(ip_box)
        self.ip_table = QTableWidget(0, 2)
        self.ip_table.setHorizontalHeaderLabels(["IP manzil", "Soni"])
        self.ip_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        ip_layout.addWidget(self.ip_table)
        tables_row.addWidget(ip_box, 1)

        flag_box = QGroupBox("Xato/ogohlantirish qatorlari")
        flag_layout = QVBoxLayout(flag_box)
        self.flag_list = QTextEdit()
        self.flag_list.setReadOnly(True)
        flag_layout.addWidget(self.flag_list)
        tables_row.addWidget(flag_box, 2)

        layout.addLayout(tables_row, 1)

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(self, "Log faylni tanlang", "", "Log/Text fayllar (*.log *.txt *.csv);;Barcha fayllar (*)")
        if not path:
            return
        self.path_edit.setText(path)
        try:
            with open(path, 'r', errors='ignore') as f:
                text = f.read()
        except Exception as e:
            QMessageBox.critical(self, "Xatolik", f"Faylni o'qib bo'lmadi: {e}")
            return

        result = analyze_log_text(text)
        self.lbl_lines.setText(str(result['total_lines']))
        self.lbl_ips.setText(str(result['unique_ips']))
        self.lbl_flagged.setText(str(result['flagged_count']))

        self.ip_table.setRowCount(0)
        for ip, count in result['top_ips']:
            r = self.ip_table.rowCount()
            self.ip_table.insertRow(r)
            self.ip_table.setItem(r, 0, QTableWidgetItem(ip))
            self.ip_table.setItem(r, 1, QTableWidgetItem(str(count)))

        self.flag_list.setPlainText(
            "\n".join(f"{ln}: {content}" for ln, content in result['flagged_lines']) or "Topilmadi."
        )

        SESSION.add(
            "log",
            f"{os.path.basename(path)} - {result['total_lines']} qator, {result['flagged_count']} ogohlantirish",
            f"Fayl: {path}\nUnikal IP: {result['unique_ips']}\nTop IP: {result['top_ips']}"
        )
        self._refresh_dashboard()


class MalwareAnalyzerPage(QWidget):
    def __init__(self, refresh_dashboard):
        super().__init__()
        self._refresh_dashboard = refresh_dashboard
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)

        title = QLabel("Malware Analyzer (statik tahlil)")
        title.setFont(QFont("Segoe UI", 18, QFont.Bold))
        layout.addWidget(title)

        if not HAS_PEFILE:
            warn = QLabel("Eslatma: 'pefile' kutubxonasi topilmadi - PE tahlili cheklangan bo'ladi (faqat hash/entropiya).")
            warn.setStyleSheet("color: #e0a63a;")
            layout.addWidget(warn)

        row = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setReadOnly(True)
        self.path_edit.setPlaceholderText("Tahlil qilinadigan fayl tanlanmagan...")
        browse_btn = QPushButton("Fayl tanlash")
        browse_btn.clicked.connect(self._browse)
        row.addWidget(self.path_edit, 1)
        row.addWidget(browse_btn)
        layout.addLayout(row)

        info_box = QGroupBox("Fayl ma'lumotlari")
        info_layout = QGridLayout(info_box)
        labels = ["Hajmi", "MD5", "SHA1", "SHA256", "Entropiya", "PE format"]
        self.info_values = {}
        for i, lbl in enumerate(labels):
            info_layout.addWidget(QLabel(f"{lbl}:"), i, 0)
            val = QLabel("-")
            val.setTextInteractionFlags(Qt.TextSelectableByMouse)
            info_layout.addWidget(val, i, 1)
            self.info_values[lbl] = val
        layout.addWidget(info_box)

        details_row = QHBoxLayout()

        api_box = QGroupBox("Shubhali API chaqiruvlari")
        api_layout = QVBoxLayout(api_box)
        self.api_list = QTextEdit()
        self.api_list.setReadOnly(True)
        api_layout.addWidget(self.api_list)
        details_row.addWidget(api_box, 1)

        packer_box = QGroupBox("Packer/shubha belgilari")
        packer_layout = QVBoxLayout(packer_box)
        self.packer_list = QTextEdit()
        self.packer_list.setReadOnly(True)
        packer_layout.addWidget(self.packer_list)
        details_row.addWidget(packer_box, 1)

        layout.addLayout(details_row, 1)

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(self, "Faylni tanlang", "", "Barcha fayllar (*)")
        if not path:
            return
        self.path_edit.setText(path)
        try:
            result = analyze_file(path)
        except Exception as e:
            QMessageBox.critical(self, "Xatolik", f"Faylni tahlil qilib bo'lmadi: {e}")
            return

        self.info_values["Hajmi"].setText(f"{result['file_size']:,} bayt")
        self.info_values["MD5"].setText(result['md5'])
        self.info_values["SHA1"].setText(result['sha1'])
        self.info_values["SHA256"].setText(result['sha256'])
        self.info_values["Entropiya"].setText(str(result['entropy']))
        pe_status = "Ha" if result['is_pe'] else "Yo'q"
        if result.get('pe_error'):
            pe_status += f" ({result['pe_error']})"
        self.info_values["PE format"].setText(pe_status)

        self.api_list.setPlainText("\n".join(result['suspicious_apis']) or "Topilmadi.")
        self.packer_list.setPlainText("\n".join(result['packer_indicators']) or "Topilmadi.")

        risk_note = "YUQORI XAVF" if (result['suspicious_apis'] or result['entropy'] > 7.5) else "past/o'rtacha xavf"
        SESSION.add(
            "malware",
            f"{os.path.basename(path)} - {risk_note}",
            f"SHA256: {result['sha256']}\nEntropiya: {result['entropy']}\n"
            f"Shubhali API: {len(result['suspicious_apis'])} ta\n"
            f"Packer belgilari: {result['packer_indicators']}"
        )
        self._refresh_dashboard()


class IOCAnalyzerPage(QWidget):
    def __init__(self, refresh_dashboard):
        super().__init__()
        self._refresh_dashboard = refresh_dashboard
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)

        title = QLabel("IOC Analyzer")
        title.setFont(QFont("Segoe UI", 18, QFont.Bold))
        layout.addWidget(title)

        form_box = QGroupBox("Tekshirish")
        form_layout = QHBoxLayout(form_box)
        self.type_combo = QComboBox()
        self.type_combo.addItems(["ip", "domain", "url", "hash", "email", "filename"])
        self.value_edit = QLineEdit()
        self.value_edit.setPlaceholderText("Masalan: 185.220.101.5 yoki example.xyz")
        self.value_edit.returnPressed.connect(self._analyze)
        analyze_btn = QPushButton("Tahlil qilish")
        analyze_btn.clicked.connect(self._analyze)
        form_layout.addWidget(self.type_combo)
        form_layout.addWidget(self.value_edit, 1)
        form_layout.addWidget(analyze_btn)
        layout.addWidget(form_box)

        result_box = QGroupBox("Natija")
        result_layout = QVBoxLayout(result_box)
        self.risk_label = QLabel("Xavf darajasi: -")
        self.risk_label.setFont(QFont("Segoe UI", 14, QFont.Bold))
        result_layout.addWidget(self.risk_label)
        self.notes_view = QTextEdit()
        self.notes_view.setReadOnly(True)
        result_layout.addWidget(self.notes_view)
        layout.addWidget(result_box, 1)

        history_box = QGroupBox("Tekshiruv tarixi (joriy sessiya)")
        history_layout = QVBoxLayout(history_box)
        self.history_table = QTableWidget(0, 3)
        self.history_table.setHorizontalHeaderLabels(["Tur", "Qiymat", "Xavf (0-10)"])
        self.history_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        history_layout.addWidget(self.history_table)
        layout.addWidget(history_box, 1)

    def _analyze(self):
        ioc_type = self.type_combo.currentText()
        value = self.value_edit.text().strip()
        if not value:
            return
        result = IOCValidator.validate(ioc_type, value)
        risk = result['risk_score']
        color = "#3ac96a" if risk <= 2 else ("#e0a63a" if risk <= 6 else "#e05a4e")
        self.risk_label.setText(f"Xavf darajasi: {risk}/10")
        self.risk_label.setStyleSheet(f"color: {color};")
        self.notes_view.setPlainText("\n".join(f"- {n}" for n in result['notes']))

        r = self.history_table.rowCount()
        self.history_table.insertRow(r)
        self.history_table.setItem(r, 0, QTableWidgetItem(ioc_type))
        self.history_table.setItem(r, 1, QTableWidgetItem(value))
        self.history_table.setItem(r, 2, QTableWidgetItem(str(risk)))

        SESSION.add("ioc", f"{ioc_type}: {value} (xavf {risk}/10)", "\n".join(result['notes']))
        self._refresh_dashboard()


class ReportsPage(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)

        title = QLabel("Reports")
        title.setFont(QFont("Segoe UI", 18, QFont.Bold))
        layout.addWidget(title)

        btn_row = QHBoxLayout()
        gen_btn = QPushButton("Hisobotni yangilash")
        gen_btn.clicked.connect(self._generate)
        save_btn = QPushButton("Markdown sifatida saqlash")
        save_btn.clicked.connect(self._save)
        btn_row.addWidget(gen_btn)
        btn_row.addWidget(save_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        self.preview = QTextEdit()
        self.preview.setReadOnly(True)
        layout.addWidget(self.preview, 1)

        self._generate()

    def _build_markdown(self) -> str:
        lines = [f"# Cybrix AI - Xavfsizlik hisoboti",
                 f"_Yaratilgan sana: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_",
                 "", f"Jami tahlillar soni: **{len(SESSION.records)}**", ""]
        if not SESSION.records:
            lines.append("Hozircha hech qanday tahlil bajarilmagan.")
        for r in SESSION.records:
            lines.append(f"## [{r.kind.upper()}] {r.summary}")
            lines.append(f"_{r.timestamp}_")
            lines.append("")
            lines.append("```")
            lines.append(r.detail)
            lines.append("```")
            lines.append("")
        return "\n".join(lines)

    def _generate(self):
        self.preview.setPlainText(self._build_markdown())

    def _save(self):
        self._generate()
        path, _ = QFileDialog.getSaveFileName(self, "Hisobotni saqlash", "cybrix_report.md", "Markdown (*.md)")
        if not path:
            return
        with open(path, 'w', encoding='utf-8') as f:
            f.write(self.preview.toPlainText())
        QMessageBox.information(self, "Saqlandi", f"Hisobot saqlandi:\n{path}")


# ============================================================================
# MAIN WINDOW & ENTRY POINT
# ============================================================================

STYLE_SHEET = """
QMainWindow, QWidget { background-color: #1e2228; color: #e6e6e6; font-size: 13px; }
QListWidget#navList {
    background-color: #171a1f; border: none; padding-top: 10px; outline: none;
}
QListWidget#navList::item { padding: 12px 16px; border-radius: 6px; margin: 2px 8px; }
QListWidget#navList::item:selected { background-color: #2f6fed; color: white; }
QListWidget#navList::item:hover:!selected { background-color: #232830; }
QGroupBox {
    border: 1px solid #333944; border-radius: 8px; margin-top: 12px; padding-top: 14px;
    font-weight: bold;
}
QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; color: #9fb4ff; }
QPushButton {
    background-color: #2f6fed; color: white; border: none; border-radius: 6px;
    padding: 8px 14px; font-weight: 600;
}
QPushButton:hover { background-color: #4a83f0; }
QPushButton:pressed { background-color: #245bcc; }
QPushButton:disabled { background-color: #3a4048; color: #7c8390; }
QLineEdit, QComboBox, QPlainTextEdit, QTextEdit {
    background-color: #262b33; border: 1px solid #3a4048; border-radius: 6px; padding: 6px;
    color: #e6e6e6;
}
QTableWidget { background-color: #21252c; gridline-color: #333944; border: 1px solid #333944; }
QHeaderView::section { background-color: #262b33; padding: 6px; border: none; color: #9fb4ff; }
QCheckBox { color: #e6e6e6; }
"""


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cybrix AI — Autonomous Multi-Agent Pentesting Platform")
        self.resize(1500, 950)

        central = QWidget()
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)

        self.nav_list = QListWidget()
        self.nav_list.setObjectName("navList")
        self.nav_list.setFixedWidth(210)
        nav_items = [
            ("Dashboard", "dashboard"),
            ("AI Chat", "chat"),
            ("Log Analyzer", "log"),
            ("Malware Analyzer", "malware"),
            ("IOC Analyzer", "ioc"),
            ("Security Agents", "agents"),
            ("Reports", "report"),
        ]
        for label, key in nav_items:
            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, key)
            self.nav_list.addItem(item)
        self.nav_list.currentItemChanged.connect(self._on_nav_changed)
        main_layout.addWidget(self.nav_list)

        self.stack = QStackedWidget()
        main_layout.addWidget(self.stack, 1)
        self.setCentralWidget(central)

        self.status_bar = self.statusBar()
        self.status_bar.showMessage(f"Tayyor — backend: {BACKEND_BASE_URL} (fireworks/AMD MI300X default, A2A pipeline)")

        self._pages: Dict[str, QWidget] = {}
        self._build_pages()

        self.nav_list.setCurrentRow(0)

    def _build_pages(self):
        self._pages["dashboard"] = DashboardPage(self._goto)
        self._pages["chat"] = ChatPage()
        self._pages["log"] = LogAnalyzerPage(self._refresh_dashboard)
        self._pages["malware"] = MalwareAnalyzerPage(self._refresh_dashboard)
        self._pages["ioc"] = IOCAnalyzerPage(self._refresh_dashboard)
        self._pages["agents"] = AgentsPage(self._refresh_dashboard)
        self._pages["report"] = ReportsPage()
        for page in self._pages.values():
            self.stack.addWidget(page)

    def _goto(self, key: str):
        for i in range(self.nav_list.count()):
            item = self.nav_list.item(i)
            if item.data(Qt.UserRole) == key:
                self.nav_list.setCurrentRow(i)
                break

    def _on_nav_changed(self, current, previous):
        if not current:
            return
        key = current.data(Qt.UserRole)
        page = self._pages.get(key)
        if page:
            self.stack.setCurrentWidget(page)
            if key == "dashboard":
                page.refresh()
            if key == "report":
                page._generate()
            self.status_bar.showMessage(f"Bo'lim: {current.text()}")

    def _refresh_dashboard(self):
        self._pages["dashboard"].refresh()


def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLE_SHEET)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
