#!/usr/bin/env python3
"""
Landull Toolkit - a desktop app for Landull's 18 security tools
(forensickit, auditkit, scankit). Pick a tool, fill in the form, press Run.

Run from source:   python3 landull_toolkit.py      (needs: pip install PySide6)
The tools themselves live in ./tools and only need the Python standard library.

Internally, each tool runs in its own process: the app re-launches itself with
"--run-tool <name> <args...>", which imports that tool and calls its main().
That keeps the window responsive and works the same inside a packaged app.
"""

import codecs
import importlib
import os
import re
import sys
import time
import traceback

APP_NAME = "Landull Toolkit"
VERSION = "1.0.0"
GITHUB = "https://github.com/Landull"


def base_dir():
    return getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))


def asset(name):
    return os.path.join(base_dir(), "assets", name)


# ============================================================== tool runner
def _fix_stdio():
    """Windowed builds on Windows can start with sys.stdout = None."""
    for name, fd in (("stdout", 1), ("stderr", 2)):
        if getattr(sys, name) is None:
            try:
                setattr(sys, name, os.fdopen(fd, "w", encoding="utf-8", errors="replace", buffering=1))
            except OSError:
                setattr(sys, name, open(os.devnull, "w"))
    if sys.stdin is None:
        try:
            sys.stdin = os.fdopen(0, "r", encoding="utf-8")
        except OSError:
            sys.stdin = open(os.devnull)
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
        except Exception:
            pass


def run_tool_mode(argv):
    name, args = argv[0], argv[1:]
    from toolspecs import TOOL_BY_NAME  # noqa: only allow known tools
    if name not in TOOL_BY_NAME:
        print(f"Unknown tool: {name}", file=sys.stderr)
        return 2
    tools_dir = os.path.join(base_dir(), "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    _fix_stdio()
    sys.argv = [name] + args
    mod = importlib.import_module(name)
    try:
        rc = mod.main(args)
    except KeyboardInterrupt:
        rc = 130
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception:
        pass
    return rc if isinstance(rc, int) else 0


def tool_command(name, args):
    """Program + arguments that run one tool through this app."""
    if getattr(sys, "frozen", False):
        return sys.executable, ["--run-tool", name] + args
    return sys.executable, [os.path.abspath(__file__), "--run-tool", name] + args


def log_path():
    if not getattr(sys, "frozen", False):
        return os.path.join(base_dir(), "landull_toolkit.log")
    if sys.platform == "darwin":
        return os.path.expanduser("~/Library/Logs/LandullToolkit.log")
    return os.path.join(os.path.expanduser("~"), ".landull_toolkit.log")


def log(msg):
    try:
        with open(log_path(), "a", encoding="utf-8") as fh:
            fh.write(time.strftime("%Y-%m-%d %H:%M:%S ") + msg.rstrip() + "\n")
    except OSError:
        pass


# ============================================================== GUI
def gui_main():
    from PySide6.QtCore import (QElapsedTimer, QProcess, QProcessEnvironment, QSize, Qt, QTimer, QUrl,
                                Signal)
    from PySide6.QtGui import (QAction, QColor, QDesktopServices, QFont, QFontDatabase, QIcon, QKeySequence,
                               QPixmap, QShortcut, QSyntaxHighlighter, QTextCharFormat, QTextCursor)
    from PySide6.QtWidgets import (QAbstractItemView, QApplication, QBoxLayout, QCheckBox, QComboBox, QFileDialog, QFrame,
                                   QGridLayout, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem,
                                   QMainWindow, QMessageBox, QPlainTextEdit, QPushButton, QScrollArea, QSizePolicy,
                                   QSplitter, QStackedWidget, QToolButton, QVBoxLayout, QWidget)

    import toolspecs
    from toolspecs import KITS, TOOLS, build_argv, command_preview, validate

    KIT = {k[0]: {"title": k[1], "desc": k[2], "color": k[3]} for k in KITS}
    BG, PANEL, SURFACE, BORDER = "#141414", "#101010", "#1c1c1c", "#2c2c2c"
    TEXT, MUTED, DIM, BONE = "#e6e3dd", "#9a968f", "#6b6862", "#e6e3dd"
    RED, AMBER, GREEN = "#e06a6a", "#e0b25a", "#86c98a"

    def rgba(hexcolor, a):
        c = QColor(hexcolor)
        return f"rgba({c.red()},{c.green()},{c.blue()},{a})"

    def qss():
        chk = asset("check.svg").replace("\\", "/")
        chev = asset("chevron.svg").replace("\\", "/")
        return f"""
        * {{ color: {TEXT}; font-size: 13px; }}
        QMainWindow, #root, #page, #home {{ background: {BG}; }}
        QToolTip {{ background: #232323; color: {TEXT}; border: 1px solid #3a3a3a; padding: 6px; }}
        #sidebar {{ background: {PANEL}; border-right: 1px solid #222; }}
        #brand {{ font-size: 15px; font-weight: 700; letter-spacing: 3px; }}
        #brandSub {{ color: {DIM}; font-size: 11px; letter-spacing: 2px; }}
        #nav {{ background: transparent; border: none; outline: none; }}
        #nav::item {{ padding: 5px 10px; border-radius: 6px; margin: 1px 6px; }}
        #nav::item:hover {{ background: #1b1b1b; }}
        #nav::item:selected {{ background: #262626; color: #ffffff; }}
        QLineEdit, QPlainTextEdit, QComboBox, QListWidget#pathList {{
            background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 6px; padding: 6px 8px;
            selection-background-color: #4a4a4a; }}
        QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus {{ border-color: #6a675f; }}
        QLineEdit[invalid="true"] {{ border-color: {RED}; }}
        #search {{ background: #181818; margin: 0 8px; }}
        QComboBox::drop-down {{ border: none; width: 22px; }}
        QComboBox::down-arrow {{ image: url({chev}); width: 12px; height: 12px; }}
        QComboBox QAbstractItemView {{ background: #202020; border: 1px solid {BORDER}; selection-background-color: #333; }}
        QPushButton, QToolButton {{ background: #232323; border: 1px solid #343434; border-radius: 6px; padding: 6px 12px; }}
        QPushButton:hover, QToolButton:hover {{ background: #2c2c2c; border-color: #444; }}
        QPushButton:pressed {{ background: #1a1a1a; }}
        QPushButton:disabled {{ color: #5a5a5a; background: #1b1b1b; border-color: #262626; }}
        #runButton {{ background: {BONE}; color: #141414; font-weight: 700; font-size: 14px; border: none; padding: 10px 18px; }}
        #runButton:hover {{ background: #ffffff; }}
        #runButton:disabled {{ background: #3a3a3a; color: #777; }}
        #stopButton {{ background: #3a1616; border-color: #6e2a2a; color: #ff9b9b; font-weight: 600; padding: 10px 16px; }}
        #stopButton:hover {{ background: #4a1c1c; }}
        #linkButton {{ background: transparent; border: none; color: {MUTED}; padding: 4px 6px; }}
        #linkButton:hover {{ color: {TEXT}; }}
        #advToggle {{ background: transparent; border: none; color: {MUTED}; padding: 6px 0; text-align: left; font-weight: 600; }}
        #advToggle:hover {{ color: {TEXT}; }}
        QCheckBox {{ spacing: 8px; }}
        QCheckBox::indicator {{ width: 16px; height: 16px; border-radius: 4px; border: 1px solid #555; background: {SURFACE}; }}
        QCheckBox::indicator:hover {{ border-color: #888; }}
        QCheckBox::indicator:checked {{ background: {BONE}; border-color: {BONE}; image: url({chk}); }}
        #fieldLabel {{ font-weight: 600; color: #d8d5cf; }}
        #help {{ color: {DIM}; font-size: 12px; }}
        #sectionTitle {{ color: {MUTED}; font-size: 11px; font-weight: 700; letter-spacing: 2px; }}
        #toolTitle {{ font-family: Menlo, Consolas, "DejaVu Sans Mono", monospace; font-size: 26px; font-weight: 700; }}
        #tagline {{ color: #cfcbc4; font-size: 15px; }}
        #desc {{ color: {MUTED}; font-size: 13px; }}
        #warning {{ background: {rgba(AMBER, 0.08)}; border: 1px solid {rgba(AMBER, 0.35)}; color: {AMBER};
                    border-radius: 6px; padding: 7px 10px; }}
        #errors {{ background: {rgba(RED, 0.08)}; border: 1px solid {rgba(RED, 0.4)}; color: {RED};
                   border-radius: 6px; padding: 7px 10px; }}
        #formCard, #outCard {{ background: #181818; border: 1px solid #252525; border-radius: 10px; }}
        #output {{ background: #0d0d0d; border: 1px solid #222; border-radius: 8px; padding: 8px;
                   font-family: Menlo, Consolas, "DejaVu Sans Mono", monospace; font-size: 12px; }}
        #cmd {{ background: #0d0d0d; border: 1px solid #222; color: {MUTED};
                font-family: Menlo, Consolas, "DejaVu Sans Mono", monospace; font-size: 11px; }}
        #status {{ font-weight: 600; }}
        #elapsed {{ color: {DIM}; }}
        #homeTitle {{ font-size: 30px; font-weight: 800; letter-spacing: 6px; }}
        #homeSub {{ color: {MUTED}; font-size: 14px; }}
        #kitCard {{ background: #181818; border: 1px solid #252525; border-radius: 12px; }}
        #kitDesc {{ color: {MUTED}; font-size: 12px; }}
        #toolCard {{ background: #1e1e1e; border: 1px solid #282828; border-radius: 8px; }}
        #toolCard:hover {{ background: #252525; border-color: #3a3a3a; }}
        #toolCardName {{ font-family: Menlo, Consolas, "DejaVu Sans Mono", monospace; font-weight: 700; font-size: 13px; }}
        #toolCardTag {{ color: {MUTED}; font-size: 12px; }}
        #footer {{ color: {DIM}; font-size: 11px; }}
        QScrollArea {{ border: none; background: transparent; }}
        QScrollArea > QWidget > QWidget {{ background: transparent; }}
        QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
        QScrollBar::handle:vertical {{ background: #333; border-radius: 4px; min-height: 30px; }}
        QScrollBar::handle:vertical:hover {{ background: #444; }}
        QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
        QScrollBar::handle:horizontal {{ background: #333; border-radius: 4px; min-width: 30px; }}
        QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
        QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
        QSplitter::handle {{ background: transparent; }}
        QMenuBar {{ background: {PANEL}; }}
        QMenu {{ background: #1e1e1e; border: 1px solid #333; }}
        QMenu::item:selected {{ background: #333; }}
        """

    mono = QFontDatabase.systemFont(QFontDatabase.FixedFont)

    def label(text, obj=None, wrap=False, sel=False):
        lab = QLabel(text)
        if obj:
            lab.setObjectName(obj)
        lab.setWordWrap(wrap)
        if sel:
            lab.setTextInteractionFlags(Qt.TextSelectableByMouse)
        return lab

    def kit_chip(kit):
        c = KIT[kit]["color"]
        chip = QLabel(kit)
        chip.setStyleSheet(f"background:{rgba(c, 0.13)}; color:{c}; border:1px solid {rgba(c, 0.35)};"
                           "border-radius:9px; padding:2px 9px; font-size:11px; font-weight:700;")
        chip.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        return chip

    def local_paths(mime):
        return [u.toLocalFile() for u in mime.urls() if u.isLocalFile()] if mime.hasUrls() else []

    # ------------------------------------------------------------ field widgets
    class DropLineEdit(QLineEdit):
        def __init__(self):
            super().__init__()
            self.setAcceptDrops(True)

        def dragEnterEvent(self, e):
            if local_paths(e.mimeData()):
                e.acceptProposedAction()
            else:
                super().dragEnterEvent(e)

        def dropEvent(self, e):
            paths = local_paths(e.mimeData())
            if paths:
                self.setText(paths[0])
                e.acceptProposedAction()
            else:
                super().dropEvent(e)

    class FieldWidget(QWidget):
        changed = Signal()

        def __init__(self, f):
            super().__init__()
            self.f = f
            self.lay = QHBoxLayout(self)
            self.lay.setContentsMargins(0, 0, 0, 0)
            self.lay.setSpacing(6)

        def value(self):
            return None

        def reset(self):
            pass

        def set_invalid(self, bad):
            pass

    class TextField(FieldWidget):
        def __init__(self, f, password=False, number=False):
            super().__init__(f)
            self.edit = QLineEdit()
            ph = f.get("placeholder", "")
            if number:
                ph = f"default: {ph}" if ph else ""
            self.edit.setPlaceholderText(ph)
            self.edit.textChanged.connect(self.changed)
            self.lay.addWidget(self.edit)
            if password:
                self.edit.setEchoMode(QLineEdit.Password)
                self.edit.setPlaceholderText("never shown, saved or sent anywhere")
                eye = QToolButton()
                eye.setText("Show")
                eye.setCheckable(True)
                eye.toggled.connect(lambda on: (self.edit.setEchoMode(QLineEdit.Normal if on else QLineEdit.Password),
                                                eye.setText("Hide" if on else "Show")))
                self.lay.addWidget(eye)
            if number:
                self.edit.setMaximumWidth(170)
                self.lay.addStretch(1)

        def value(self):
            return self.edit.text()

        def reset(self):
            self.edit.clear()

        def set_invalid(self, bad):
            self.edit.setProperty("invalid", bad)
            self.edit.style().unpolish(self.edit)
            self.edit.style().polish(self.edit)

    class PathField(FieldWidget):
        def __init__(self, f):
            super().__init__(f)
            self.edit = DropLineEdit()
            mode = f.get("mode", "any")
            self.edit.setPlaceholderText({"save": "choose where to save...", "dir": "drop a folder here",
                                          "file": "drop a file here"}.get(mode, "drop a file or folder here"))
            self.edit.textChanged.connect(self.changed)
            self.lay.addWidget(self.edit, 1)
            if mode in ("file", "any"):
                self._btn("File..." if mode == "any" else "Browse...", self.pick_file)
            if mode in ("dir", "any"):
                self._btn("Folder...", self.pick_dir)
            if mode == "save":
                self._btn("Save as...", self.pick_save)

        def _btn(self, text, fn):
            b = QPushButton(text)
            b.clicked.connect(fn)
            self.lay.addWidget(b)

        def pick_file(self):
            p, _ = QFileDialog.getOpenFileName(self, self.f["label"], self.edit.text() or os.path.expanduser("~"))
            if p:
                self.edit.setText(p)

        def pick_dir(self):
            p = QFileDialog.getExistingDirectory(self, self.f["label"], self.edit.text() or os.path.expanduser("~"))
            if p:
                self.edit.setText(p)

        def pick_save(self):
            p, _ = QFileDialog.getSaveFileName(self, self.f["label"], self.edit.text() or os.path.expanduser("~"),
                                               self.f.get("save_filter", ""))
            if p:
                self.edit.setText(p)

        def value(self):
            t = self.edit.text().strip().strip('"').strip("'")
            return os.path.expanduser(t) if t else ""

        def reset(self):
            self.edit.clear()

        def set_invalid(self, bad):
            TextField.set_invalid(self, bad)

    class PathsField(FieldWidget):
        def __init__(self, f):
            super().__init__(f)
            self.lay.setDirection(QBoxLayout.Direction.TopToBottom)
            self.list = QListWidget()
            self.list.setObjectName("pathList")
            self.list.setSelectionMode(QAbstractItemView.ExtendedSelection)
            self.list.setFixedHeight(92)
            self.list.setToolTip("Drag files or folders here")
            self.setAcceptDrops(True)
            self.list.setAcceptDrops(False)
            self.hint = QLabel("Drop files or folders here", self.list)
            self.hint.setObjectName("help")
            self.hint.setAlignment(Qt.AlignCenter)
            self.hint.setAttribute(Qt.WA_TransparentForMouseEvents)
            self.lay.addWidget(self.list)
            self.entry = DropLineEdit()
            self.entry.setPlaceholderText("...or type / paste a path and press Enter")
            self.entry.returnPressed.connect(self.add_typed)
            self.entry.textChanged.connect(self.changed)
            self.edit = self.entry
            self.lay.addWidget(self.entry)
            row = QHBoxLayout()
            row.setSpacing(6)
            mode = f.get("mode", "any")
            if mode in ("file", "any"):
                self._btn(row, "Add files...", self.add_files)
            if mode in ("dir", "any"):
                self._btn(row, "Add folder...", self.add_dir)
            row.addStretch(1)
            self._btn(row, "Remove", self.remove, link=True)
            self._btn(row, "Clear", self.reset, link=True)
            self.lay.addLayout(row)
            self._sync()

        def _btn(self, row, text, fn, link=False):
            b = QPushButton(text)
            if link:
                b.setObjectName("linkButton")
            b.clicked.connect(fn)
            row.addWidget(b)

        def resizeEvent(self, e):
            super().resizeEvent(e)
            self.hint.setGeometry(self.list.rect())

        def _sync(self):
            self.hint.setVisible(self.list.count() == 0)
            self.hint.setGeometry(self.list.rect())
            self.changed.emit()

        def add(self, paths):
            have = {self.list.item(i).text() for i in range(self.list.count())}
            for p in paths:
                if p and p not in have:
                    self.list.addItem(p)
                    have.add(p)
            self._sync()

        def add_typed(self):
            raw = self.entry.text().strip().strip('"').strip("'")
            if not raw:
                return
            p = os.path.abspath(os.path.expanduser(raw))
            if not os.path.exists(p):
                TextField.set_invalid(self, True)
                self.entry.setToolTip("That path doesn't exist")
                return
            TextField.set_invalid(self, False)
            self.entry.clear()
            self.add([p])

        def add_files(self):
            ps, _ = QFileDialog.getOpenFileNames(self, self.f["label"], os.path.expanduser("~"))
            self.add(ps)

        def add_dir(self):
            p = QFileDialog.getExistingDirectory(self, self.f["label"], os.path.expanduser("~"))
            self.add([p])

        def remove(self):
            for it in self.list.selectedItems():
                self.list.takeItem(self.list.row(it))
            self._sync()

        def reset(self):
            self.list.clear()
            self._sync()

        def dragEnterEvent(self, e):
            if local_paths(e.mimeData()):
                e.acceptProposedAction()

        def dropEvent(self, e):
            self.add(local_paths(e.mimeData()))
            e.acceptProposedAction()

        def value(self):
            vals = [self.list.item(i).text() for i in range(self.list.count())]
            pending = self.entry.text().strip().strip('"').strip("'")
            if pending:
                p = os.path.abspath(os.path.expanduser(pending))
                if p not in vals:
                    vals.append(p)
            return vals

        def set_invalid(self, bad):
            self.list.setStyleSheet(f"border-color: {RED};" if bad else "")

    class ChoiceField(FieldWidget):
        def __init__(self, f):
            super().__init__(f)
            self.combo = QComboBox()
            for c in f["choices"]:
                self.combo.addItem(c if c else "(any)", c)
            self.combo.setMinimumWidth(140)
            self.reset()
            self.combo.currentIndexChanged.connect(self.changed)
            self.lay.addWidget(self.combo)
            self.lay.addStretch(1)

        def value(self):
            return self.combo.currentData()

        def reset(self):
            i = self.combo.findData(self.f.get("default", self.f["choices"][0]))
            self.combo.setCurrentIndex(max(i, 0))

    class MultiField(FieldWidget):
        def __init__(self, f):
            super().__init__(f)
            grid = QGridLayout()
            grid.setHorizontalSpacing(16)
            grid.setVerticalSpacing(6)
            self.boxes = []
            cols = 4 if len(f["choices"]) > 6 else 3
            for i, c in enumerate(f["choices"]):
                b = QCheckBox(c)
                b.toggled.connect(self.changed)
                grid.addWidget(b, i // cols, i % cols)
                self.boxes.append(b)
            self.lay.addLayout(grid)
            self.lay.addStretch(1)

        def value(self):
            return [b.text() for b in self.boxes if b.isChecked()]

        def reset(self):
            for b in self.boxes:
                b.setChecked(False)

    class CheckField(FieldWidget):
        def __init__(self, f):
            super().__init__(f)
            self.box = QCheckBox(f["label"])
            self.box.toggled.connect(self.changed)
            self.lay.addWidget(self.box)
            self.lay.addStretch(1)

        def value(self):
            return self.box.isChecked()

        def reset(self):
            self.box.setChecked(False)

    def make_field(f):
        k = f["kind"]
        if k == "path":
            return PathField(f)
        if k == "paths":
            return PathsField(f)
        if k == "choice":
            return ChoiceField(f)
        if k == "multi":
            return MultiField(f)
        if k == "check":
            return CheckField(f)
        if k == "password":
            return TextField(f, password=True)
        if k == "number":
            return TextField(f, number=True)
        return TextField(f)

    # ------------------------------------------------------------ output highlighting
    class Highlighter(QSyntaxHighlighter):
        RULES = [
            (re.compile(r"\b(FAIL(ED)?|CRITICAL|HIGH|BAD|BREACHED|PWNED|MISMATCH|EXPIRED|OPEN NETWORK|DANGER|"
                        r"ERROR|INSECURE|MISSING|WEAK)\b|\[!\]|\[x\]|<--+|(?<![\w!])!(?![\w!=])"), RED),
            (re.compile(r"\b(WARN(ING)?|MEDIUM|STALE|LEGACY|EXPIRING|NEW)\b|\[\?\]|\[~\]"), AMBER),
            (re.compile(r"\b(PASS(ED)?|OK|GOOD|STRONG|MATCH(ED)?|VALID|SECURE|LOW)\b|\[\+\]|✓"), GREEN),
            (re.compile(r"^\[\*\].*$|^(=|-|─|━|═){3,}.*$"), DIM),
        ]

        def __init__(self, doc):
            super().__init__(doc)
            self.formats = []
            for rx, color in self.RULES:
                fm = QTextCharFormat()
                fm.setForeground(QColor(color))
                if color != DIM:
                    fm.setFontWeight(QFont.Bold)
                self.formats.append((rx, fm))

        def highlightBlock(self, text):
            for rx, fm in self.formats:
                for m in rx.finditer(text):
                    self.setFormat(m.start(), m.end() - m.start(), fm)

    ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07")

    # ------------------------------------------------------------ tool page
    class ToolPage(QWidget):
        def __init__(self, spec):
            super().__init__()
            self.setObjectName("page")
            self.spec = spec
            self.proc = None
            self.fields = {}
            self.rows = {}
            self.timer = QTimer(self)
            self.timer.setInterval(200)
            self.timer.timeout.connect(self._tick)
            self.clock = QElapsedTimer()
            self.out_file = None

            outer = QVBoxLayout(self)
            outer.setContentsMargins(26, 22, 26, 18)
            outer.setSpacing(10)

            # header
            top = QHBoxLayout()
            top.setSpacing(12)
            title = label(spec["name"], "toolTitle")
            top.addWidget(title)
            top.addWidget(kit_chip(spec["kit"]), 0, Qt.AlignVCenter)
            top.addStretch(1)
            outer.addLayout(top)
            outer.addWidget(label(spec["tagline"], "tagline"))
            d = label(spec["desc"], "desc", wrap=True)
            outer.addWidget(d)
            if spec.get("warning"):
                outer.addWidget(label("⚠  " + spec["warning"], "warning", wrap=True))

            split = QSplitter(Qt.Horizontal)
            split.setHandleWidth(14)
            split.setChildrenCollapsible(False)
            outer.addWidget(split, 1)

            # ---- form (left)
            card = QFrame()
            card.setObjectName("formCard")
            cl = QVBoxLayout(card)
            cl.setContentsMargins(0, 0, 0, 0)
            cl.setSpacing(0)
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
            inner = QWidget()
            form = QVBoxLayout(inner)
            form.setContentsMargins(18, 16, 18, 16)
            form.setSpacing(12)

            main_fields = [f for f in spec["fields"] if not f.get("adv") and f.get("group") != "output"]
            adv_fields = [f for f in spec["fields"] if f.get("adv") and f.get("group") != "output"]
            out_fields = [f for f in spec["fields"] if f.get("group") == "output"]

            form.addWidget(label("INPUTS", "sectionTitle"))
            for f in main_fields:
                form.addWidget(self._row(f))
            if not main_fields:
                form.addWidget(label("Nothing to fill in - this tool checks the computer it runs on. Just press Run.",
                                     "help", wrap=True))

            if adv_fields:
                self.adv_btn = QPushButton(f"▸  More options ({len(adv_fields)})")
                self.adv_btn.setObjectName("advToggle")
                self.adv_btn.setCursor(Qt.PointingHandCursor)
                form.addWidget(self.adv_btn)
                self.adv_box = QWidget()
                al = QVBoxLayout(self.adv_box)
                al.setContentsMargins(0, 0, 0, 0)
                al.setSpacing(12)
                for f in adv_fields:
                    al.addWidget(self._row(f))
                self.adv_box.setVisible(False)
                form.addWidget(self.adv_box)
                self.adv_btn.clicked.connect(self._toggle_adv)
                self._adv_count = len(adv_fields)

            form.addSpacing(4)
            form.addWidget(label("RESULTS", "sectionTitle"))
            for f in out_fields:
                form.addWidget(self._row(f))
            form.addStretch(1)
            scroll.setWidget(inner)
            cl.addWidget(scroll, 1)

            # run bar
            bar = QFrame()
            bl = QVBoxLayout(bar)
            bl.setContentsMargins(18, 10, 18, 14)
            bl.setSpacing(8)
            self.errors = label("", "errors", wrap=True)
            self.errors.hide()
            bl.addWidget(self.errors)
            br = QHBoxLayout()
            self.run_btn = QPushButton(f"Run {spec['name']}")
            self.run_btn.setObjectName("runButton")
            self.run_btn.setCursor(Qt.PointingHandCursor)
            self.run_btn.setToolTip("Ctrl/Cmd + Enter")
            self.run_btn.clicked.connect(self.run)
            self.stop_btn = QPushButton("Stop")
            self.stop_btn.setObjectName("stopButton")
            self.stop_btn.clicked.connect(self.stop)
            self.stop_btn.hide()
            reset = QPushButton("Reset form")
            reset.setObjectName("linkButton")
            reset.clicked.connect(self.reset_form)
            br.addWidget(self.run_btn, 1)
            br.addWidget(self.stop_btn)
            br.addWidget(reset)
            bl.addLayout(br)
            cl.addWidget(bar)
            card.setMinimumWidth(360)
            split.addWidget(card)

            # ---- output (right)
            oc = QFrame()
            oc.setObjectName("outCard")
            ol = QVBoxLayout(oc)
            ol.setContentsMargins(14, 12, 14, 12)
            ol.setSpacing(8)
            sr = QHBoxLayout()
            sr.setSpacing(8)
            self.status = label("●  Ready", "status")
            self.status.setStyleSheet(f"color:{MUTED};")
            self.elapsed = label("", "elapsed")
            sr.addWidget(self.status)
            sr.addWidget(self.elapsed)
            sr.addStretch(1)
            self.find = QLineEdit()
            self.find.setPlaceholderText("Find in results")
            self.find.setMaximumWidth(200)
            self.find.returnPressed.connect(self.find_next)
            sr.addWidget(self.find)
            self.wrap = QCheckBox("Wrap")
            self.wrap.setToolTip("Wrap long lines instead of scrolling sideways")
            self.wrap.toggled.connect(lambda on: self.output.setLineWrapMode(
                QPlainTextEdit.WidgetWidth if on else QPlainTextEdit.NoWrap))
            sr.addWidget(self.wrap)
            for text, fn, tip in (("Copy", self.copy_output, "Copy all results"),
                                  ("Save...", self.save_output, "Save results as a text file"),
                                  ("Clear", self.clear_output, "")):
                b = QPushButton(text)
                b.setToolTip(tip)
                b.clicked.connect(fn)
                sr.addWidget(b)
            ol.addLayout(sr)

            self.output = QPlainTextEdit()
            self.output.setObjectName("output")
            self.output.setReadOnly(True)
            self.output.setLineWrapMode(QPlainTextEdit.NoWrap)
            self.output.setMaximumBlockCount(250000)
            f = QFont(mono)
            f.setPointSize(max(f.pointSize(), 11))
            self.output.setFont(f)
            self.output.setPlaceholderText("Results will appear here.\n\nFill in the form on the left and press Run.")
            self.hl = Highlighter(self.output.document())
            ol.addWidget(self.output, 1)

            self.result_row = QHBoxLayout()
            self.result_lbl = label("", "help")
            self.open_btn = QPushButton("Open result file")
            self.open_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(self.out_file)))
            self.reveal_btn = QPushButton("Show in folder")
            self.reveal_btn.clicked.connect(self.reveal)
            self.result_row.addWidget(self.result_lbl, 1)
            self.result_row.addWidget(self.open_btn)
            self.result_row.addWidget(self.reveal_btn)
            self.result_wrap = QWidget()
            self.result_wrap.setLayout(self.result_row)
            self.result_row.setContentsMargins(0, 0, 0, 0)
            self.result_wrap.hide()
            ol.addWidget(self.result_wrap)

            cr = QHBoxLayout()
            cr.setSpacing(6)
            cmd_lbl = label("Terminal equivalent", "help")
            cmd_lbl.setToolTip("The same run, as a command for the standalone script from GitHub.")
            self.cmd = QLineEdit()
            self.cmd.setObjectName("cmd")
            self.cmd.setReadOnly(True)
            cb = QPushButton("Copy")
            cb.clicked.connect(lambda: QApplication.clipboard().setText(self.cmd.text()))
            cr.addWidget(cmd_lbl)
            cr.addWidget(self.cmd, 1)
            cr.addWidget(cb)
            ol.addLayout(cr)
            split.addWidget(oc)
            split.setStretchFactor(0, 0)
            split.setStretchFactor(1, 1)
            split.setSizes([400, 1000])

            for w in self.fields.values():
                w.changed.connect(self.update_preview)
            self.update_preview()

        def _row(self, f):
            w = QWidget()
            l = QVBoxLayout(w)
            l.setContentsMargins(0, 0, 0, 0)
            l.setSpacing(5)
            fw = make_field(f)
            if f["kind"] != "check":
                lab = label(f["label"] + ("  *" if f.get("required") else ""), "fieldLabel")
                l.addWidget(lab)
            l.addWidget(fw)
            if f.get("help"):
                h = label(f["help"], "help", wrap=True)
                if f["kind"] == "check":
                    h.setContentsMargins(26, 0, 0, 0)
                l.addWidget(h)
            self.fields[f["key"]] = fw
            self.rows[f["key"]] = w
            return w

        def _toggle_adv(self):
            vis = not self.adv_box.isVisible()
            self.adv_box.setVisible(vis)
            self.adv_btn.setText(("▾  Fewer options" if vis else f"▸  More options ({self._adv_count})"))

        # ---- values / preview
        def values(self):
            return {k: w.value() for k, w in self.fields.items()}

        def update_preview(self):
            argv, stdin = build_argv(self.spec, self.values())
            text = command_preview(self.spec, argv)
            if stdin is not None:
                text += "     # password typed at the prompt"
            self.cmd.setText(text)
            self.cmd.setCursorPosition(0)
            if self.errors.isVisible():
                self._show_problems(validate(self.spec, self.values()), quiet=True)

        def _show_problems(self, problems, quiet=False):
            bad_keys = set()
            for f in self.spec["fields"]:
                if f.get("required") and toolspecs.is_empty(f, self.values().get(f["key"])):
                    bad_keys.add(f["key"])
            roo = self.spec.get("require_one_of")
            if roo and roo[1] in problems:
                bad_keys.update(roo[0])
            for k, w in self.fields.items():
                w.set_invalid(k in bad_keys)
            if problems:
                self.errors.setText("\n".join("•  " + p for p in problems))
                self.errors.show()
            else:
                self.errors.hide()

        def reset_form(self):
            for w in self.fields.values():
                w.reset()
            self.errors.hide()
            for w in self.fields.values():
                w.set_invalid(False)

        # ---- running
        def is_running(self):
            return self.proc is not None and self.proc.state() != QProcess.NotRunning

        def run(self):
            if self.is_running():
                return
            vals = self.values()
            problems = validate(self.spec, vals)
            self._show_problems(problems)
            if problems:
                return
            argv, stdin_text = build_argv(self.spec, vals)
            out_key = vals.get("output") or ""
            self.out_file = out_key or None
            fmt_choice = vals.get("format")
            if self.spec["name"] == "sysaudit" and fmt_choice == "html" and not out_key:
                self._show_problems(["The html format needs a 'Save report to a file' location."])
                return

            self.output.clear()
            self.result_wrap.hide()
            self._got_stdout = False
            self._decoders = {k: codecs.getincrementaldecoder("utf-8")(errors="replace") for k in ("out", "err")}
            prog, args = tool_command(self.spec["name"], argv)
            self.proc = QProcess(self)
            env = QProcessEnvironment.systemEnvironment()
            env.insert("PYTHONUNBUFFERED", "1")
            env.insert("PYTHONIOENCODING", "utf-8")
            env.insert("NO_COLOR", "1")
            extra = ["/usr/local/bin", "/opt/homebrew/bin", "/usr/sbin", "/sbin", "/usr/bin", "/bin"]
            if sys.platform != "win32":
                path = env.value("PATH", "")
                env.insert("PATH", os.pathsep.join([path] + [p for p in extra if p not in path.split(os.pathsep)]))
            self.proc.setProcessEnvironment(env)
            self.proc.setWorkingDirectory(os.path.expanduser("~"))
            self.proc.readyReadStandardOutput.connect(lambda: self._read("out"))
            self.proc.readyReadStandardError.connect(lambda: self._read("err"))
            self.proc.finished.connect(self._finished)
            self.proc.errorOccurred.connect(self._error)
            log(f"run {self.spec['name']} {argv}")
            self.proc.start(prog, args)
            if stdin_text is not None:
                self.proc.write(stdin_text.encode("utf-8"))
            self.proc.closeWriteChannel()
            self.clock.start()
            self.timer.start()
            self._tick()
            self._set_status("●  Running...", AMBER)
            self.run_btn.setEnabled(False)
            self.run_btn.setText("Running...")
            self.stop_btn.show()

        def _read(self, which):
            if not self.proc:
                return
            data = bytes(self.proc.readAllStandardOutput() if which == "out" else self.proc.readAllStandardError())
            text = self._decoders[which].decode(data)
            if which == "out" and text.strip():
                self._got_stdout = True
            if text:
                self.append(ANSI.sub("", text.replace("\r\n", "\n")), err=(which == "err"))

        def append(self, text, err=False):
            sb = self.output.verticalScrollBar()
            at_bottom = sb.value() >= sb.maximum() - 4
            cur = QTextCursor(self.output.document())
            cur.movePosition(QTextCursor.End)
            fmt = QTextCharFormat()
            fmt.setForeground(QColor("#b0aca5" if err else TEXT))
            if err:
                fmt.setFontItalic(True)
            # carriage-return progress lines: keep only the last segment
            if "\r" in text:
                text = "\n".join(seg.split("\r")[-1] for seg in text.split("\n"))
            cur.insertText(text, fmt)
            if at_bottom:
                sb.setValue(sb.maximum())

        def _tick(self):
            s = self.clock.elapsed() / 1000 if self.clock.isValid() else 0
            self.elapsed.setText(f"{s:.1f}s" if s < 60 else f"{int(s // 60)}m {int(s % 60):02d}s")

        def _set_status(self, text, color):
            self.status.setText(text)
            self.status.setStyleSheet(f"color:{color};")

        def _done_ui(self):
            self.timer.stop()
            self._tick()
            self.run_btn.setEnabled(True)
            self.run_btn.setText(f"Run {self.spec['name']}")
            self.stop_btn.hide()

        def _finished(self, code, status):
            for w in ("out", "err"):
                self._read(w)
            self._done_ui()
            log(f"done {self.spec['name']} code={code} status={status}")
            if getattr(self, "_stopped", False):
                self._stopped = False
                self._set_status("●  Stopped", MUTED)
                self.append("\n[stopped by user]\n", err=True)
                return
            if status == QProcess.CrashExit:
                self._set_status("●  Crashed", RED)
            elif code == 0:
                self._set_status("●  Finished", GREEN)
            elif code == 1:
                self._set_status("●  Finished - findings flagged", AMBER)
            else:
                self._set_status(f"●  Finished with errors (code {code})", RED)
            shown = False
            if (not self._got_stdout and self.out_file and os.path.isfile(self.out_file)
                    and os.path.getsize(self.out_file) < 3_000_000
                    and os.path.splitext(self.out_file)[1].lower() in (".json", ".csv", ".txt", ".kml", ".tsv")):
                try:
                    with open(self.out_file, encoding="utf-8", errors="replace") as fh:
                        body = fh.read()
                    self.append(f"\n── saved file: {os.path.basename(self.out_file)} ──\n", err=True)
                    self.append(body if body.endswith("\n") else body + "\n")
                    shown = True
                except OSError:
                    pass
            if not shown and not self.output.toPlainText().strip():
                self.append("(no output)\n", err=True)
            if self.out_file and os.path.exists(self.out_file):
                self.result_lbl.setText("Saved: " + self.out_file)
                self.result_wrap.show()

        def _error(self, err):
            if err == QProcess.FailedToStart:
                self._done_ui()
                self._set_status("●  Couldn't start the tool", RED)
                self.append(f"Failed to start: {self.proc.errorString()}\n", err=True)

        def stop(self):
            if not self.is_running():
                return
            self._stopped = True
            if sys.platform == "win32":
                self.proc.kill()
            else:
                self.proc.terminate()
                QTimer.singleShot(1500, lambda: self.is_running() and self.proc.kill())

        def kill(self):
            if self.is_running():
                self.proc.kill()
                self.proc.waitForFinished(1000)

        # ---- output actions
        def copy_output(self):
            QApplication.clipboard().setText(self.output.toPlainText())

        def save_output(self):
            default = os.path.join(os.path.expanduser("~"), f"{self.spec['name']}-results.txt")
            p, _ = QFileDialog.getSaveFileName(self, "Save results", default, "Text (*.txt);;All files (*)")
            if p:
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write(self.output.toPlainText())

        def clear_output(self):
            self.output.clear()
            self.result_wrap.hide()
            if not self.is_running():
                self._set_status("●  Ready", MUTED)
                self.elapsed.setText("")

        def find_next(self):
            t = self.find.text()
            if t and not self.output.find(t):
                self.output.moveCursor(QTextCursor.Start)
                self.output.find(t)

        def reveal(self):
            p = self.out_file
            if sys.platform == "darwin":
                QProcess.startDetached("open", ["-R", p])
            elif sys.platform == "win32":
                QProcess.startDetached("explorer", ["/select,", os.path.normpath(p)])
            else:
                QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.dirname(p)))

    # ------------------------------------------------------------ home page
    class ToolCard(QFrame):
        clicked = Signal(str)

        def __init__(self, spec):
            super().__init__()
            self.setObjectName("toolCard")
            self.name = spec["name"]
            self.setCursor(Qt.PointingHandCursor)
            l = QVBoxLayout(self)
            l.setContentsMargins(12, 9, 12, 9)
            l.setSpacing(2)
            l.addWidget(label(spec["name"], "toolCardName"))
            l.addWidget(label(spec["tagline"], "toolCardTag", wrap=True))
            self.setToolTip(spec["desc"])

        def mouseReleaseEvent(self, e):
            if e.button() == Qt.LeftButton and self.rect().contains(e.position().toPoint()):
                self.clicked.emit(self.name)

    class HomePage(QScrollArea):
        open_tool = Signal(str)

        def __init__(self):
            super().__init__()
            self.setObjectName("home")
            self.setWidgetResizable(True)
            w = QWidget()
            w.setObjectName("home")
            v = QVBoxLayout(w)
            v.setContentsMargins(40, 30, 40, 24)
            v.setSpacing(6)
            logo = QLabel()
            pm = QPixmap(asset("skull.png"))
            dpr = self.devicePixelRatioF()
            pm = pm.scaledToHeight(int(170 * dpr), Qt.SmoothTransformation)
            pm.setDevicePixelRatio(dpr)
            logo.setPixmap(pm)
            logo.setAlignment(Qt.AlignCenter)
            v.addWidget(logo)
            t = label("LANDULL TOOLKIT", "homeTitle")
            t.setAlignment(Qt.AlignCenter)
            v.addWidget(t)
            s = label("18 forensic, audit and scan tools. Pick one, fill in the blanks, press Run.", "homeSub")
            s.setAlignment(Qt.AlignCenter)
            v.addWidget(s)
            v.addSpacing(22)
            cols = QHBoxLayout()
            cols.setSpacing(16)
            for kit_id, title, desc, color in KITS:
                card = QFrame()
                card.setObjectName("kitCard")
                cl = QVBoxLayout(card)
                cl.setContentsMargins(16, 16, 16, 16)
                cl.setSpacing(8)
                head = QLabel(kit_id)
                head.setStyleSheet(f"color:{color}; font-size:18px; font-weight:800; letter-spacing:1px;"
                                   "font-family: Menlo, Consolas, 'DejaVu Sans Mono', monospace;")
                cl.addWidget(head)
                cl.addWidget(label(desc, "kitDesc", wrap=True))
                cl.addSpacing(4)
                for spec in [t for t in TOOLS if t["kit"] == kit_id]:
                    tc = ToolCard(spec)
                    tc.setStyleSheet(f"#toolCard:hover {{ border-color: {rgba(color, 0.6)}; }}")
                    tc.clicked.connect(self.open_tool)
                    cl.addWidget(tc)
                cl.addStretch(1)
                cols.addWidget(card, 1)
            v.addLayout(cols)
            v.addSpacing(16)
            foot = label(f"v{VERSION}  ·  github.com/Landull  ·  Everything runs on this computer - "
                         "your files are never uploaded.", "footer")
            foot.setAlignment(Qt.AlignCenter)
            v.addWidget(foot)
            v.addStretch(1)
            self.setWidget(w)

    # ------------------------------------------------------------ main window
    class Main(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle(APP_NAME)
            geo = QApplication.primaryScreen().availableGeometry()
            self.resize(min(1520, int(geo.width() * 0.9)), min(960, int(geo.height() * 0.9)))
            self.setMinimumSize(1060, 680)
            root = QWidget()
            root.setObjectName("root")
            h = QHBoxLayout(root)
            h.setContentsMargins(0, 0, 0, 0)
            h.setSpacing(0)

            side = QFrame()
            side.setObjectName("sidebar")
            side.setFixedWidth(236)
            sl = QVBoxLayout(side)
            sl.setContentsMargins(0, 16, 0, 12)
            sl.setSpacing(10)
            brand = QHBoxLayout()
            brand.setContentsMargins(16, 0, 12, 4)
            brand.setSpacing(10)
            ic = QLabel()
            dpr = self.devicePixelRatioF()
            pm = QPixmap(asset("skull.png")).scaledToHeight(int(40 * dpr), Qt.SmoothTransformation)
            pm.setDevicePixelRatio(dpr)
            ic.setPixmap(pm)
            ic.setCursor(Qt.PointingHandCursor)
            ic.mousePressEvent = lambda e: self.show_home()
            brand.addWidget(ic)
            bt = QVBoxLayout()
            bt.setSpacing(0)
            bt.addWidget(label("LANDULL", "brand"))
            bt.addWidget(label("TOOLKIT", "brandSub"))
            brand.addLayout(bt)
            brand.addStretch(1)
            sl.addLayout(brand)

            self.search = QLineEdit()
            self.search.setObjectName("search")
            self.search.setPlaceholderText("Search tools...")
            self.search.setClearButtonEnabled(True)
            self.search.textChanged.connect(self.filter_nav)
            sl.addWidget(self.search)

            self.nav = QListWidget()
            self.nav.setObjectName("nav")
            self.nav.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
            self.nav.setFocusPolicy(Qt.NoFocus)
            home = QListWidgetItem("⌂   Home")
            home.setData(Qt.UserRole, "__home__")
            self.nav.addItem(home)
            for kit_id, title, desc, color in KITS:
                hdr = QListWidgetItem(kit_id.upper())
                hdr.setFlags(Qt.NoItemFlags)
                hdr.setData(Qt.UserRole, None)
                hdr.setData(Qt.UserRole + 1, kit_id)
                hf = QFont()
                hf.setBold(True)
                hf.setPointSize(max(hf.pointSize() - 2, 9))
                hf.setLetterSpacing(QFont.AbsoluteSpacing, 1.5)
                hdr.setFont(hf)
                hdr.setForeground(QColor(color))
                hdr.setSizeHint(QSize(200, 34))
                self.nav.addItem(hdr)
                for spec in [t for t in TOOLS if t["kit"] == kit_id]:
                    it = QListWidgetItem(spec["name"])
                    it.setData(Qt.UserRole, spec["name"])
                    it.setData(Qt.UserRole + 1, kit_id)
                    it.setToolTip(spec["tagline"])
                    f = QFont(mono)
                    f.setPointSize(max(QFont().pointSize(), 12))
                    it.setFont(f)
                    self.nav.addItem(it)
            self.nav.currentItemChanged.connect(self.nav_changed)
            sl.addWidget(self.nav, 1)
            ver = label(f"v{VERSION}", "footer")
            ver.setContentsMargins(18, 0, 0, 0)
            sl.addWidget(ver)
            h.addWidget(side)

            self.stack = QStackedWidget()
            self.home = HomePage()
            self.home.open_tool.connect(self.open_tool)
            self.stack.addWidget(self.home)
            self.pages = {}
            h.addWidget(self.stack, 1)
            self.setCentralWidget(root)

            m = self.menuBar()
            fm = m.addMenu("File")
            a = QAction("Home", self)
            a.setShortcut(QKeySequence("Ctrl+H" if sys.platform != "darwin" else "Ctrl+Shift+H"))
            a.triggered.connect(self.show_home)
            fm.addAction(a)
            q = QAction("Quit", self)
            q.setShortcut(QKeySequence.Quit)
            q.setMenuRole(QAction.QuitRole)
            q.triggered.connect(self.close)
            fm.addAction(q)
            hm = m.addMenu("Help")
            ab = QAction(f"About {APP_NAME}", self)
            ab.setMenuRole(QAction.AboutRole)
            ab.triggered.connect(self.about)
            hm.addAction(ab)
            gh = QAction("Landull on GitHub", self)
            gh.triggered.connect(lambda: QDesktopServices.openUrl(QUrl(GITHUB)))
            hm.addAction(gh)
            lg = QAction("Show log file", self)
            lg.triggered.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(log_path())))
            hm.addAction(lg)

            QShortcut(QKeySequence("Ctrl+Return"), self, activated=self.run_current)
            QShortcut(QKeySequence("Ctrl+Enter"), self, activated=self.run_current)
            QShortcut(QKeySequence.Find, self, activated=lambda: self.search.setFocus())
            self.nav.setCurrentRow(0)

        def page(self, name):
            if name not in self.pages:
                p = ToolPage(toolspecs.TOOL_BY_NAME[name])
                self.pages[name] = p
                self.stack.addWidget(p)
            return self.pages[name]

        def nav_changed(self, cur, prev):
            if cur is None:
                return
            key = cur.data(Qt.UserRole)
            if key == "__home__":
                self.stack.setCurrentWidget(self.home)
            elif key:
                self.stack.setCurrentWidget(self.page(key))

        def open_tool(self, name):
            for i in range(self.nav.count()):
                if self.nav.item(i).data(Qt.UserRole) == name:
                    self.nav.setCurrentRow(i)
                    return

        def show_home(self):
            self.search.clear()
            self.nav.setCurrentRow(0)

        def filter_nav(self, text):
            t = text.strip().lower()
            kits_visible = set()
            for i in range(self.nav.count()):
                it = self.nav.item(i)
                key = it.data(Qt.UserRole)
                if key and key != "__home__":
                    spec = toolspecs.TOOL_BY_NAME[key]
                    hit = not t or t in (spec["name"] + " " + spec["tagline"] + " " + spec["desc"] + " " +
                                         spec["kit"]).lower()
                    it.setHidden(not hit)
                    if hit:
                        kits_visible.add(it.data(Qt.UserRole + 1))
            for i in range(self.nav.count()):
                it = self.nav.item(i)
                if it.data(Qt.UserRole) is None:
                    it.setHidden(it.data(Qt.UserRole + 1) not in kits_visible)
            if t:
                for i in range(self.nav.count()):
                    it = self.nav.item(i)
                    if not it.isHidden() and it.data(Qt.UserRole) not in (None, "__home__"):
                        self.nav.setCurrentItem(it)
                        break

        def run_current(self):
            w = self.stack.currentWidget()
            if isinstance(w, ToolPage):
                w.run()

        def about(self):
            QMessageBox.about(self, APP_NAME,
                              f"<b>{APP_NAME}</b> v{VERSION}<br><br>"
                              "A desktop front end for Landull's forensickit, auditkit and scankit: "
                              "18 dependency-free Python security tools.<br><br>"
                              f"<a style='color:#e6e3dd' href='{GITHUB}'>github.com/Landull</a><br><br>"
                              "MIT License. Only scan or test systems you own or have permission to test.")

        def closeEvent(self, e):
            running = [p for p in self.pages.values() if p.is_running()]
            if running:
                r = QMessageBox.question(self, "Tools still running",
                                         f"{len(running)} tool(s) are still running. Stop them and quit?")
                if r != QMessageBox.Yes:
                    e.ignore()
                    return
            for p in running:
                p.kill()
            e.accept()

    # ------------------------------------------------------------ start
    QApplication.setApplicationName(APP_NAME)
    QApplication.setOrganizationName("Landull")
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setWindowIcon(QIcon(asset("icon.png")))
    app.setStyleSheet(qss())

    def excepthook(t, v, tb):
        msg = "".join(traceback.format_exception(t, v, tb))
        log("ERROR " + msg)
        sys.__stderr__ and sys.__stderr__.write(msg)
        try:
            QMessageBox.critical(None, APP_NAME, f"Something went wrong:\n\n{v}\n\nDetails were written to:\n{log_path()}")
        except Exception:
            pass
    sys.excepthook = excepthook

    win = Main()
    win.show()
    if os.environ.get("LANDULL_SCREENSHOT"):          # used for automated visual checks
        target = os.environ["LANDULL_SCREENSHOT"]
        tool = os.environ.get("LANDULL_SCREENSHOT_TOOL")

        def snap():
            if tool:
                win.open_tool(tool)
            QTimer.singleShot(400, lambda: (win.grab().save(target), app.quit()))
        QTimer.singleShot(600, snap)
    log(f"start v{VERSION} frozen={getattr(sys, 'frozen', False)}")
    return app.exec()


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--run-tool":
        sys.path.insert(0, base_dir())
        sys.exit(run_tool_mode(sys.argv[2:]))
    sys.path.insert(0, base_dir())
    sys.exit(gui_main())
