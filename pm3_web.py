#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PM3一键工具 webUI
=================

Python 只用标准库启动一个本地 HTTP 服务, 界面 (深色主题) 在浏览器中打开,
不依赖任何 GUI 库 (无 Tkinter), 彻底规避 macOS 系统 Tk 8.5 的白屏问题。

功能:
    - 获取卡片信息 / 智能获取密钥 / Dump / 复制卡片
    - 手机复制实体卡 (模拟 -> 手机复制UID -> 验证 -> 写入)
    - 魔术卡 / Ultralight / 低频 / 手动命令控制台
实时输出通过 SSE (Server-Sent Events) 推送到页面。

运行: python3 pm3_web.py   (会自动用浏览器打开 http://127.0.0.1:<port>/)
平台: macOS / Linux (pty) / Windows (管道, 实验性)。仅用于授权测试 / 本人卡片。

------------------------------------------------------------------------------
Copyright (C) 2026 windowsnoeditor

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
------------------------------------------------------------------------------
"""

import os
import re
import sys
import time
import json
import glob
import queue
import shutil
import signal
import threading
import subprocess
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

IS_WINDOWS = os.name == "nt"

try:
    import pty
    HAVE_PTY = True
except ImportError:
    HAVE_PTY = False


# --------------------------------------------------------------------------- #
# 常量与辅助
# --------------------------------------------------------------------------- #

CONFIG_PATH = os.path.expanduser("~/.pm3_gui_config.json")
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
PROMPT_RE = re.compile(r"\] pm3 -->\s*$")
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|[\x01\x02\x07]")

SIZE_FLAGS = {"auto": "", "mini": "--mini", "1k": "--1k", "2k": "--2k", "4k": "--4k"}
SAK_SIZE = {
    "09": ("Mini (320B)", "--mini"),
    "08": ("Classic 1K", "--1k"),
    "88": ("Classic 1K (Infineon)", "--1k"),
    "18": ("Classic 4K", "--4k"),
    "38": ("Classic 4K (smartMX)", "--4k"),
}


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def find_executable(saved: str = "") -> str:
    candidates = []
    if saved:
        candidates.append(saved)
    P = PROJECT_ROOT
    if IS_WINDOWS:
        candidates += [
            os.path.join(P, "proxmark3", "client", "proxmark3.exe"),
            os.path.join(P, "proxmark3", "proxmark3.exe"),
            os.path.join(P, "proxmark3.exe"),
        ]
        names = ("proxmark3.exe", "proxmark3")
    else:
        candidates += [
            os.path.join(P, "proxmark3", "pm3"),
            os.path.join(P, "proxmark3", "client", "proxmark3"),
            os.path.join(P, "proxmark3", "client", "build", "proxmark3"),
            os.path.join(P, "pm3"),
        ]
        names = ("pm3", "proxmark3")
    for c in candidates:
        if c and os.path.isfile(c) and (IS_WINDOWS or os.access(c, os.X_OK)):
            return c
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return saved or ""


def scan_ports():
    if IS_WINDOWS:
        ports = []
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r"HARDWARE\DEVICEMAP\SERIALCOMM")
            i = 0
            while True:
                try:
                    _, val, _ = winreg.EnumValue(key, i)
                    ports.append(val)        # 例如 COM3
                    i += 1
                except OSError:
                    break
        except Exception:
            pass
        return sorted(ports)
    patterns = [
        "/dev/tty.usbmodem*", "/dev/cu.usbmodem*",
        "/dev/ttyACM*", "/dev/ttyUSB*",
        "/dev/tty.usbserial*", "/dev/cu.usbserial*",
    ]
    ports = []
    for p in patterns:
        ports.extend(sorted(glob.glob(p)))
    return ports


def parse_uid(text: str) -> str:
    m = re.search(r"UID:\s*([0-9A-Fa-f](?:[0-9A-Fa-f ]*[0-9A-Fa-f])?)", text)
    return m.group(1) if m else ""


def normalize_uid(s: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", s or "").upper()


def load_config() -> dict:
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_config(cfg: dict):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def analyze_card(info_text: str) -> dict:
    """解析 `hf mf info` 输出, 自动判断卡型并选择合适的密钥恢复方法。"""
    t = info_text
    low = t.lower()
    res = {"family": "Classic", "size_name": "", "size_flag": "", "chip": "",
           "prng": "", "static": "", "magic": False, "backdoor": False,
           "method": "", "command": None, "timeout": 1800, "summary": ""}

    # 指纹识别 (hf mf info 的 "--- Fingerprint" 段, 如 "Fudan FM11RF08S 0590")
    mfud = re.search(r"Fudan\s+(FM11RF08S-7B|FM11RF08S|FM11RF08-7B|FM11RF08|FM11RF32N|FM11RF32)", t)
    if mfud:
        res["chip"] = "Fudan " + mfud.group(1)

    if "desfire detected" in low:
        res["family"] = "DESFire"
    elif "ultralight" in low or "ntag" in low:
        res["family"] = "Ultralight"
    elif "mifare plus detected" in low or "plus detected" in low:
        res["family"] = "Plus"

    m = re.search(r"SAK:\s*([0-9A-Fa-f]{2})", t)
    if m:
        sak = m.group(1).upper()
        if sak in SAK_SIZE:
            res["size_name"], res["size_flag"] = SAK_SIZE[sak]
    mt = re.search(r"MIFARE Classic\s*(Mini|1K|2K|4K)", t, re.I)
    if mt:
        kind = mt.group(1).upper()
        res["size_name"] = f"Classic {kind}"
        res["size_flag"] = {"MINI": "--mini", "1K": "--1k",
                            "2K": "--2k", "4K": "--4k"}.get(kind, res["size_flag"])

    if "backdoor key" in low and "detected but unknown" not in low:
        res["backdoor"] = True
    mseg = re.search(r"Magic Tag Information(.*?)(?:---|PRNG Information|$)", t, re.S)
    if mseg:
        seg = mseg.group(1)
        if "<n/a>" not in seg and ("gen" in seg.lower() or "magic" in seg.lower()
                                   or "backdoor" in seg.lower() or "cuid" in seg.lower()):
            res["magic"] = True
    if "magic capabilities" in low:
        res["magic"] = True
    if res["backdoor"]:
        res["magic"] = True

    if "static enc nonce" in low and re.search(r"static enc nonce[\.\s]*yes", low):
        res["static"] = "static_enc"
    elif re.search(r"static nonce[\.\s]*yes", low):
        res["static"] = "static"
    if re.search(r"prng[\.\s]*weak", low):
        res["prng"] = "weak"
    elif re.search(r"prng[\.\s]*hard", low):
        res["prng"] = "hard"
    elif re.search(r"prng[\.\s]*fail", low):
        res["prng"] = "fail"

    fam = res["family"]
    size = res["size_flag"]
    if fam == "Ultralight":
        res["method"] = "Ultralight/NTAG: 无 Crypto1 密钥概念"
        res["command"] = None
        res["summary"] = ("检测到 MIFARE Ultralight / NTAG。\n此类卡没有 Crypto1 扇区密钥。\n"
                          "→ 请改用「Ultralight」页的 信息 / Dump。")
    elif fam == "DESFire":
        res["method"] = "DESFire: AES/DES, 不支持本工具破解"
        res["command"] = None
        res["summary"] = "检测到 MIFARE DESFire (AES/3DES)。\n本工具的 Classic 破解方法不适用。"
    elif res["chip"].startswith("Fudan FM11RF08S"):
        # FM11RF08S 系列有专用后门, 优先用专用恢复脚本, 而非通用 autopwn
        res["method"] = f"检测到 {res['chip']} (带后门) → 专用脚本 fm11rf08s_recovery"
        res["command"] = "script run fm11rf08s_recovery"
        res["timeout"] = 2700
        res["summary"] = (
            f"芯片指纹: {res['chip']}\n"
            f"容量: {res['size_name'] or 'Classic 1K'}\n"
            "该芯片带后门, 走专用恢复脚本最快最稳:\n"
            "→ 执行命令: script run fm11rf08s_recovery\n"
            "(如需完整 dump 可用「脚本攻击」页的 fm11rf08s_full -r)")
    else:
        if res["static"] == "static_enc":
            res["method"] = "静态加密随机数 → staticnested (autopwn 自动处理)"
        elif res["static"] == "static":
            res["method"] = "静态随机数 → staticnested 攻击"
        elif res["prng"] == "weak":
            res["method"] = "弱 PRNG → 默认字典 + nested 攻击 (快)"
        elif res["prng"] == "hard":
            res["method"] = "加固卡 (hard PRNG) → 默认字典 + hardnested 攻击 (较慢)"
        elif res["prng"] == "fail":
            res["method"] = "PRNG 读取失败 → 仍尝试 autopwn (字典/darkside)"
        else:
            res["method"] = "未能判定 PRNG → 由 autopwn 自动选择攻击"
        res["command"] = f"hf mf autopwn {size}".strip()
        res["timeout"] = 3600 if res["prng"] == "hard" else 1800
        chip_note = f"\n芯片指纹: {res['chip']}" if res["chip"] else ""
        magic_note = "\n注意: 检测到魔术卡, 也可在「魔术卡」页直接读取(无需破解)。" if res["magic"] else ""
        res["summary"] = (
            f"卡片家族: MIFARE {fam}{chip_note}\n"
            f"容量: {res['size_name'] or '未知 (autopwn 自动检测)'}\n"
            f"PRNG: {res['prng'] or '未知'}    静态随机数: {res['static'] or '否'}\n"
            f"魔术卡: {'是' if res['magic'] else '否'}\n"
            f"→ 选用方法: {res['method']}\n"
            f"→ 执行命令: {res['command']}{magic_note}")
    return res


# --------------------------------------------------------------------------- #
# PM3 常驻会话引擎
#   - POSIX (macOS / Linux): 使用 pty, 输出实时流式, 体验最佳
#   - Windows: 使用管道 (无 stdlib pty); 输出按命令批次返回, 实验性
# --------------------------------------------------------------------------- #

class Pm3Session:
    def __init__(self, exec_path, port, cwd, on_output):
        self.exec_path = exec_path
        self.port = port
        self.cwd = cwd
        self.on_output = on_output
        self.proc = None
        self.master_fd = None     # pty 模式
        self.reader = None
        self.alive = False
        self._idle = threading.Event()
        self._cmd_lock = threading.Lock()
        self._cap = []
        self._capturing = False
        self._pbuf = ""

    # ---- 启动 ---- #
    def start(self):
        if not self.exec_path or not os.path.isfile(self.exec_path):
            raise RuntimeError("找不到 pm3 / proxmark3 可执行文件, 请检查路径")
        args = [self.exec_path]
        base = os.path.basename(self.exec_path).lower()
        is_script = base == "pm3"
        if self.port:
            args.append(self.port)
        elif not is_script:
            raise RuntimeError("直接使用 proxmark3 客户端时必须指定端口")
        if IS_WINDOWS:
            self._start_pipe(args)
        else:
            self._start_pty(args)
        self.alive = True
        self.reader = threading.Thread(target=self._read_loop, daemon=True)
        self.reader.start()

    def _start_pty(self, args):
        env = dict(os.environ)
        env["TERM"] = "dumb"
        self.master_fd, slave_fd = pty.openpty()
        try:
            self.proc = subprocess.Popen(
                args, stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
                cwd=self.cwd, env=env, preexec_fn=os.setsid, close_fds=True)
        finally:
            os.close(slave_fd)

    def _start_pipe(self, args):
        flags = 0
        if IS_WINDOWS:
            flags = subprocess.CREATE_NEW_PROCESS_GROUP  # 便于发送 Ctrl-Break
        self.proc = subprocess.Popen(
            args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, cwd=self.cwd, bufsize=0, creationflags=flags)

    def wait_ready(self, timeout=30):
        return self._idle.wait(timeout)

    # ---- 关闭 ---- #
    def stop(self):
        self.alive = False
        try:
            if self.proc and self.proc.poll() is None:
                try:
                    self._write("quit\n")
                except Exception:
                    pass
                try:
                    self.proc.wait(timeout=2)
                except Exception:
                    pass
                if self.proc.poll() is None:
                    try:
                        if IS_WINDOWS:
                            self.proc.terminate()
                        else:
                            os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
                    except Exception:
                        self.proc.terminate()
        except Exception:
            pass
        finally:
            if self.master_fd is not None:
                try:
                    os.close(self.master_fd)
                except Exception:
                    pass
                self.master_fd = None

    # ---- 读取循环 (两种后端共用解析逻辑) ---- #
    def _read_chunk(self):
        if self.master_fd is not None:                 # pty
            return os.read(self.master_fd, 65536)
        if self.proc and self.proc.stdout:             # pipe: read1 返回当前可用字节
            return self.proc.stdout.read1(65536)
        return b""

    def _read_loop(self):
        while self.alive:
            try:
                data = self._read_chunk()
            except (OSError, ValueError):
                break
            if not data:
                break
            clean = strip_ansi(data.decode("utf-8", "replace"))
            try:
                self.on_output(clean)
            except Exception:
                pass
            if self._capturing:
                self._cap.append(clean)
            self._pbuf = (self._pbuf + clean)[-4096:]
            if PROMPT_RE.search(self._pbuf):
                self._idle.set()
        self.alive = False
        try:
            self.on_output("\n[会话已结束]\n")
        except Exception:
            pass

    def _write(self, s: str):
        data = s.encode("utf-8")
        if self.master_fd is not None:
            os.write(self.master_fd, data)
        elif self.proc and self.proc.stdin:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()
        else:
            raise RuntimeError("会话未连接")

    def run(self, cmd: str, timeout=900):
        if not self.alive:
            raise RuntimeError("会话未连接")
        with self._cmd_lock:
            self._idle.clear()
            self._cap = []
            self._capturing = True
            self._pbuf = ""
            self._write(cmd + "\n")
            ok = self._idle.wait(timeout)
            self._capturing = False
            return "".join(self._cap), ok

    def interrupt(self):
        try:
            if IS_WINDOWS and self.proc:
                self.proc.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                self._write("\x03")
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# 引擎: 会话 + 作业队列 + SSE 广播 + 业务编排
# --------------------------------------------------------------------------- #

class Engine:
    def __init__(self):
        self.session = None
        self.savedir = ""
        self.busy = False
        self.job_queue = queue.Queue()
        self.worker = None
        self.clients = set()          # SSE 客户端队列集合
        self.clients_lock = threading.Lock()
        # 源卡 / 手机复制状态
        self.source_uid = None
        self.source_dump = None
        self.source_keys = None
        self.cardinfo = {}            # 结构化卡片信息 (左下面板)
        self.phone = {"running": False, "uid": None, "dump": None,
                      "keys": None, "size": ""}

    # ----- SSE 广播 ----- #
    def add_client(self):
        q = queue.Queue(maxsize=10000)
        with self.clients_lock:
            self.clients.add(q)
        return q

    def remove_client(self, q):
        with self.clients_lock:
            self.clients.discard(q)

    def broadcast(self, ev, data):
        with self.clients_lock:
            targets = list(self.clients)
        for q in targets:
            try:
                q.put_nowait((ev, data))
            except queue.Full:
                pass

    def log(self, text):
        self.broadcast("log", text)

    def _on_output(self, text):
        self.broadcast("log", text)

    def state(self):
        return {
            "connected": bool(self.session and self.session.alive),
            "busy": self.busy,
            "queue": self.job_queue.qsize(),
            "savedir": self.savedir,
            "source": {"uid": self.source_uid, "dump": self.source_dump,
                       "keys": self.source_keys},
        }

    def push_state(self):
        self.broadcast("state", self.state())

    # ----- 连接 ----- #
    def connect(self, exec_path, port, savedir):
        if self.session and self.session.alive:
            return {"ok": True, "message": "已连接"}
        if savedir:
            os.makedirs(savedir, exist_ok=True)
        self.savedir = savedir
        save_config({"exec": exec_path, "port": port, "savedir": savedir})
        self.log(f"\n启动: {exec_path} {port or '(自动端口)'}  目录: {savedir}\n")
        try:
            self.session = Pm3Session(exec_path, port, savedir, self._on_output)
            self.session.start()
            ready = self.session.wait_ready(timeout=30)
            if not self.session.alive:
                msg = "会话已退出 (可能未编译客户端或未找到设备)"
                self.log(f"[错误] {msg}\n")
                self.session = None
                self.push_state()
                return {"ok": False, "message": msg}
        except Exception as e:
            self.log(f"[错误] {e}\n")
            self.session = None
            self.push_state()
            return {"ok": False, "message": str(e)}
        if not (self.worker and self.worker.is_alive()):
            self.worker = threading.Thread(target=self._job_loop, daemon=True)
            self.worker.start()
        self.push_state()
        return {"ok": True, "ready": bool(ready), "message": "已连接"}

    def disconnect(self):
        if self.session:
            self.session.stop()
            self.session = None
        self.busy = False
        self.push_state()
        return {"ok": True}

    # ----- 作业 ----- #
    def enqueue(self, label, fn):
        if not (self.session and self.session.alive):
            return {"ok": False, "message": "未连接"}
        self.job_queue.put((label, fn))
        self.push_state()
        return {"ok": True, "queued": True}

    def enqueue_cmd(self, label, command, timeout=900, capture=True):
        def job():
            self.log(f"\n===== [{label}] $ {command} =====\n")
            result, ok = self.session.run(command, timeout=timeout)
            if not ok:
                self.log(f"[提示] 命令超时或被中止 ({label})\n")
            if capture:
                self.capture_files(result)
        return self.enqueue(label, job)

    def _job_loop(self):
        while self.session and self.session.alive:
            try:
                label, fn = self.job_queue.get(timeout=0.3)
            except queue.Empty:
                continue
            self.busy = True
            self.broadcast("status", f"运行中: {label}")
            self.broadcast("task", {"label": label, "state": "start", "ts": time.strftime("%H:%M:%S")})
            self.push_state()
            err = None
            try:
                fn()
            except Exception as e:
                err = str(e)
                self.log(f"[执行错误] {e}\n")
            finally:
                self.busy = False
                self.broadcast("status", "空闲")
                self.broadcast("task", {"label": label, "state": "error" if err else "done",
                                        "ts": time.strftime("%H:%M:%S"), "err": err})
                self.push_state()

    def abort(self):
        if self.session and self.session.alive:
            self.session.interrupt()
            self.log("[已发送中止信号 Ctrl-C]\n")
        return {"ok": True}

    # ----- 文件解析 ----- #
    def capture_files(self, result):
        dump = keys = uid = None
        m = re.search(r"(hf-mf-[0-9A-Fa-f]+)-dump\.bin", result)
        if m:
            dump = m.group(0)
            uid = re.search(r"hf-mf-([0-9A-Fa-f]+)-dump", result).group(1)
        m2 = re.search(r"(hf-mf-[0-9A-Fa-f]+)-key\.bin", result)
        if m2:
            keys = m2.group(0)
            if not uid:
                uid = re.search(r"hf-mf-([0-9A-Fa-f]+)-key", result).group(1)
        if not uid:
            u = parse_uid(result)
            if u:
                uid = normalize_uid(u)
        if uid and not dump:
            cand = os.path.join(self.savedir, f"hf-mf-{uid}-dump.bin")
            if os.path.isfile(cand):
                dump = f"hf-mf-{uid}-dump.bin"
        if uid and not keys:
            cand = os.path.join(self.savedir, f"hf-mf-{uid}-key.bin")
            if os.path.isfile(cand):
                keys = f"hf-mf-{uid}-key.bin"
        if uid:
            self.source_uid = uid
        if dump:
            self.source_dump = dump
        if keys:
            self.source_keys = keys
        if uid or dump:
            self.push_state()
        self.update_cardinfo(result)
        if keys:
            self.push_keys()
        if dump:
            self.push_dump()

    def update_cardinfo(self, text):
        """从命令输出解析结构化卡片信息, 推送到左下面板。"""
        if "UID:" not in text and "SAK:" not in text:
            return
        a = analyze_card(text)
        uid = normalize_uid(parse_uid(text))
        info = {}
        if uid:
            info["uid"] = uid
        msak = re.search(r"SAK:\s*([0-9A-Fa-f]{2})", text)
        if msak:
            info["sak"] = msak.group(1).upper()
        matqa = re.search(r"ATQA:\s*([0-9A-Fa-f]{2}\s*[0-9A-Fa-f]{2})", text)
        if matqa:
            info["atqa"] = matqa.group(1).strip()
        if msak or uid:
            info["family"] = a["family"]
            if a["size_name"]:
                info["size"] = a["size_name"]
        if a["prng"]:
            info["prng"] = a["prng"]
        if a["static"]:
            info["static"] = a["static"]
        if a["magic"]:
            info["magic"] = True
        if a["chip"]:
            info["chip"] = a["chip"]
        if a["method"]:
            info["method"] = a["method"]
        changed = False
        for k, v in info.items():
            if v not in ("", None) and self.cardinfo.get(k) != v:
                self.cardinfo[k] = v
                changed = True
        if changed:
            self.broadcast("cardinfo", self.cardinfo)

    def read_keys(self):
        if not self.source_keys:
            return None
        path = self.source_keys
        if not os.path.isabs(path):
            path = os.path.join(self.savedir, path)
        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception:
            return None
        sectors = len(data) // 12
        if sectors == 0:
            return None
        out = []
        for i in range(sectors):
            a = data[i * 6:i * 6 + 6].hex().upper()
            b = data[6 * sectors + i * 6:6 * sectors + i * 6 + 6].hex().upper()
            out.append({"sector": i, "a": a, "b": b})
        return out

    def push_keys(self):
        k = self.read_keys()
        if k is not None:
            self.broadcast("keys", {"file": self.source_keys, "sectors": k})

    def read_dump(self):
        """读取 dump.bin, 返回按块解析的内容 (含所属扇区/是否扇区尾块)。"""
        if not self.source_dump or not self.source_dump.endswith(".bin"):
            return None
        path = self.source_dump
        if not os.path.isabs(path):
            path = os.path.join(self.savedir, path)
        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception:
            return None
        nblocks = len(data) // 16
        if nblocks == 0:
            return None
        blocks = []
        for b in range(nblocks):
            if b < 128:                       # 扇区 0-31, 每扇区 4 块
                sector = b // 4
                trailer = (b % 4 == 3)
            else:                              # 扇区 32-39, 每扇区 16 块
                sector = 32 + (b - 128) // 16
                trailer = ((b - 128) % 16 == 15)
            blocks.append({"block": b, "sector": sector, "trailer": trailer,
                           "hex": data[b * 16:b * 16 + 16].hex().upper()})
        return blocks

    def push_dump(self):
        d = self.read_dump()
        if d is not None:
            self.broadcast("dump", {"file": self.source_dump, "blocks": d})

    def list_dumps(self):
        out = []
        try:
            for f in sorted(os.listdir(self.savedir)):
                if f.endswith((".bin", ".eml", ".json")):
                    out.append(f)
        except Exception:
            pass
        return out

    # ----- 智能获取密钥 ----- #
    def smart_keys(self, size_flag=""):
        def job():
            self.log("\n========== [智能获取密钥] 步骤1: 识别卡片 ==========\n")
            info, _ = self.session.run("hf mf info", timeout=40)
            a = analyze_card(info)
            self.update_cardinfo(info)
            self.log("\n---------- 识别结论 ----------\n" + a["summary"] + "\n")
            self.broadcast("analysis", a)
            if not a["command"]:
                self.log("\n[结论] 此卡无需/不支持 Crypto1 破解, 见上方说明。\n")
                return
            cmd = a["command"]
            # 仅当推荐命令本身是 autopwn 时, 才用用户手选的卡型覆盖容量;
            # 若推荐的是 FM11RF08S 专用脚本等, 保持不变。
            if size_flag and cmd.startswith("hf mf autopwn"):
                cmd = f"hf mf autopwn {size_flag}"
            self.log(f"\n========== 步骤2: 执行 [{a['method']}] ==========\n$ {cmd}\n")
            result, _ = self.session.run(cmd, timeout=a["timeout"])
            self.capture_files(result)
            self.log("\n[完成] 密钥/数据已尝试保存, 见保存目录。\n")
        return self.enqueue("智能获取密钥", job)

    def clone_write(self, target, size_flag=""):
        if not self.source_dump:
            return {"ok": False, "message": "请先读取源卡或载入 dump"}
        dump, keys = self.source_dump, self.source_keys
        if target == "gen1a":
            cmd, label = f"hf mf cload -f {dump}", "克隆->Gen1a"
        else:
            cmd = f"hf mf restore {size_flag} -f {dump}".strip()
            if keys and target == "gen2":
                cmd += f" -k {keys} --ka"
            label = "克隆->" + ("Gen2" if target == "gen2" else "普通卡")
        return self.enqueue_cmd(label, cmd, timeout=300, capture=False)

    # ----- 手机复制 ----- #
    def phone_start(self, size_flag=""):
        if self.phone["running"]:
            return {"ok": False, "message": "手机复制流程进行中"}
        self.phone = {"running": True, "uid": None, "dump": None, "keys": None, "size": ""}
        self.broadcast("phone", {"stage": "reading"})

        def job():
            self.log("\n########## 手机复制 步骤1: 读取被复制卡片 ##########\n")
            info, _ = self.session.run("hf mf info", timeout=40)
            a = analyze_card(info)
            self.update_cardinfo(info)
            if a["family"] not in ("Classic", "Plus"):
                self.log(f"[终止] 手机复制仅支持 MIFARE Classic, 检测到: {a['family']}\n")
                self.phone["running"] = False
                self.broadcast("phone", {"stage": "fail",
                                         "msg": f"不支持的卡片: {a['family']} (仅支持 MIFARE Classic)"})
                return
            size = size_flag or a["size_flag"]
            # FM11RF08S 用专用后门脚本, 其余走 autopwn
            if a["chip"].startswith("Fudan FM11RF08S"):
                cmd = "script run fm11rf08s_recovery"
            else:
                cmd = f"hf mf autopwn {size}".strip()
            self.log(f"\n[{a['method']}]\n$ {cmd}\n")
            result, _ = self.session.run(cmd, timeout=a["timeout"])
            self.capture_files(result)
            if not self.source_dump:
                self.phone["running"] = False
                self.broadcast("phone", {"stage": "fail", "msg": "未能恢复密钥/生成 dump, 流程终止"})
                return
            self.phone.update(uid=self.source_uid, dump=self.source_dump,
                              keys=self.source_keys, size=size)
            # 模拟源卡
            self.log("\n########## 手机复制 步骤2: PM3 模拟源卡 ##########\n")
            self.log(f"$ hf mf eload -f {self.source_dump} {size}\n")
            self.session.run(f"hf mf eload -f {self.source_dump} {size}".strip(), timeout=60)
            self.log(f"$ hf mf sim {size} -u {self.source_uid}\n")
            self.session.run(f"hf mf sim {size} -u {self.source_uid}".strip(), timeout=30)
            self.broadcast("phone", {"stage": "awaiting_copy", "uid": self.source_uid,
                                     "dump": self.source_dump, "keys": self.source_keys})
        return self.enqueue("手机复制-读取+模拟", job)

    def phone_uid_copied(self):
        def job():
            self.log("\n[停止模拟]\n$ hw ping\n")
            self.session.run("hw ping", timeout=15)
            self.broadcast("phone", {"stage": "awaiting_place"})
        return self.enqueue("手机复制-停止模拟", job)

    def phone_placed(self, method="restore_default"):
        target = self.phone.get("uid")
        size = self.phone.get("size", "")
        dump = self.phone.get("dump")
        keys = self.phone.get("keys")

        def job():
            self.log("\n########## 手机复制 步骤4: 验证并写入 ##########\n")
            read_uid = ""
            for attempt in range(3):
                self.log(f"$ hf 14a info  (第{attempt + 1}次)\n")
                info, _ = self.session.run("hf 14a info", timeout=30)
                read_uid = normalize_uid(parse_uid(info))
                if read_uid:
                    break
                time.sleep(0.4)
            want = normalize_uid(target)
            self.log(f"[验证] 期望 UID={want}   读到 UID={read_uid or '(无)'}\n")
            if not read_uid:
                self.broadcast("phone", {"stage": "verify_failed",
                                         "msg": "未读到任何卡片, 请确认手机已正确放置"})
                return
            if read_uid != want:
                self.broadcast("phone", {"stage": "verify_failed",
                                         "msg": f"UID 不吻合! 期望 {want}, 读到 {read_uid}"})
                return
            if method == "cload":
                cmd = f"hf mf cload -f {dump}"
            elif method == "restore_ka" and keys:
                cmd = f"hf mf restore {size} -f {dump} -k {keys} --ka".strip()
            else:
                cmd = f"hf mf restore {size} -f {dump}".strip()
            self.log(f"\n[UID 吻合 ✓ 写入数据]\n$ {cmd}\n")
            result, ok = self.session.run(cmd, timeout=300)
            self.phone["running"] = False
            low = result.lower()
            bad = ("fail" in low or "error" in low or "can't" in low)
            self.broadcast("phone", {"stage": "done", "ok": bool(ok and not bad)})
        return self.enqueue("手机复制-验证写入", job)

    def phone_cancel(self):
        was = self.phone["running"]
        self.phone["running"] = False
        self.broadcast("phone", {"stage": "cancelled"})
        if was and self.session and self.session.alive:
            def job():
                self.log("\n[取消: 停止模拟]\n$ hw ping\n")
                try:
                    self.session.run("hw ping", timeout=10)
                except Exception:
                    pass
            return self.enqueue("手机复制-取消", job)
        return {"ok": True}


ENGINE = Engine()


# --------------------------------------------------------------------------- #
# 前端页面
# --------------------------------------------------------------------------- #

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PM3一键工具 webUI</title>
<style>
  :root { --bg:#0a0e14; --panel:#11161f; --panel2:#0d1219; --line:#222b38; --accent:#3b82f6;
          --accent2:#34d3e0; --ink:#cdd9e5; --muted:#6b7785; --ok:#2ec27e; --warn:#e0883b; --bad:#e5484d; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif; background:var(--bg); color:var(--ink); }
  header { background:#05080d; color:#fff; padding:8px 14px; display:flex; flex-wrap:wrap; gap:8px; align-items:center; border-bottom:1px solid var(--line); }
  header h1 { font-size:15px; margin:0 12px 0 0; font-weight:700; color:#fff; letter-spacing:.3px; }
  header h1 span { color:var(--accent2); }
  header input, header select { padding:5px 7px; border:1px solid var(--line); border-radius:6px; background:#0d131c; color:var(--ink); font-size:12px; }
  header input:focus, header select:focus, #cbar input:focus { outline:none; border-color:var(--accent); }
  header input.path { width:300px; } header input.dir { width:230px; }
  .dot { width:11px; height:11px; border-radius:50%; background:var(--bad); display:inline-block; margin-right:4px; box-shadow:0 0 6px currentColor; }
  .dot.on { background:var(--ok); } .dot.wait { background:var(--warn); }
  button { cursor:pointer; border:1px solid var(--line); background:#161d28; color:var(--ink); border-radius:7px; padding:7px 9px; font-size:13px; transition:.12s; }
  button:hover { border-color:var(--accent); background:#1b2433; }
  button.pri { background:linear-gradient(180deg,#3b82f6,#2563eb); color:#fff; border-color:#2563eb; }
  button.pri:hover { filter:brightness(1.1); }
  button.warn { background:var(--warn); color:#1a1208; border-color:var(--warn); }
  button:disabled { opacity:.4; cursor:not-allowed; }
  #main { display:flex; height:calc(100vh - 50px); }
  #left { width:46%; min-width:390px; display:flex; flex-direction:column; background:var(--bg); }
  #leftTop { flex:1; overflow:auto; padding:10px; }
  #right { flex:1; display:flex; flex-direction:column; border-left:1px solid var(--line); background:#05080d; }
  /* 左下: 卡片信息 / 密钥 / 扇区数据 / 任务 面板 */
  #statusPanel { flex:0 0 38%; min-height:180px; overflow:auto; border-top:2px solid var(--accent); background:var(--panel2); padding:6px 10px 10px; }
  #statusPanel h4 { margin:8px 0 4px; font-size:12px; color:var(--accent2); border-bottom:1px solid var(--line); padding-bottom:3px; }
  .kv { font-size:12px; line-height:1.7; color:var(--ink); }
  .kv b { color:#fff; }
  .kv .muted { color:var(--muted); }
  .pill { display:inline-block; padding:0 6px; border-radius:9px; font-size:11px; color:#fff; margin-left:4px; }
  .pill.weak{background:var(--ok)} .pill.hard{background:var(--bad)} .pill.magic{background:#9b59f6} .pill.static{background:var(--warn);color:#1a1208}
  .pill.chip{background:#0e6e78;color:#d7fbff}
  .dual { display:flex; gap:10px; align-items:flex-start; }
  .dual .col { flex:1; min-width:0; }
  #siKeys, #siDump { max-height:170px; overflow:auto; border:1px solid var(--line); border-radius:6px; }
  table.tbl { border-collapse:collapse; font-family:Menlo,monospace; font-size:11px; width:100%; }
  table.tbl th, table.tbl td { border:1px solid var(--line); padding:1px 5px; text-align:center; white-space:nowrap; }
  table.tbl th { background:#1a2230; color:var(--accent2); position:sticky; top:0; }
  table.tbl td.hex { text-align:left; color:#9fe7c4; letter-spacing:.5px; }
  table.tbl tr.trailer td { background:#1a1320; color:#e9b3ff; }
  table.tbl tr.trailer td.hex { color:#e9b3ff; }
  table.tbl td.ka { color:#7fd0ff; } table.tbl td.kb { color:#ffd27f; }
  table.tbl tr.secsep td { border-top:2px solid #2f3b4d; }
  #siTasks { font-size:11.5px; max-height:96px; overflow:auto; font-family:Menlo,monospace; }
  #siTasks .tk { padding:1px 0; }
  #siTasks .ok{color:var(--ok)} #siTasks .run{color:var(--warn)} #siTasks .err{color:var(--bad)}
  .tabs { display:flex; flex-wrap:wrap; gap:4px; margin-bottom:8px; }
  .tabs button { padding:6px 10px; font-size:12px; }
  .tabs button.active { background:var(--accent); color:#fff; border-color:var(--accent); }
  .panel { display:none; }
  .panel.active { display:block; }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:9px; padding:10px; margin-bottom:10px; }
  .card h3 { margin:0 0 8px; font-size:13px; color:var(--accent2); }
  .grid { display:flex; flex-direction:column; gap:6px; }
  .tip { color:var(--muted); font-size:11.5px; margin:1px 0 5px; line-height:1.45; }
  .info { color:var(--accent2); font-size:12px; white-space:pre-wrap; }
  .row { display:flex; gap:6px; align-items:center; flex-wrap:wrap; }
  label.radio { display:block; font-size:12.5px; padding:2px 0; color:var(--ink); }
  #console { flex:1; overflow:auto; padding:10px; color:#c7d4e1; font-family:Menlo,Consolas,monospace; font-size:12px; white-space:pre-wrap; }
  #cbar { display:flex; gap:6px; padding:8px; border-top:1px solid var(--line); background:#0a0e14; }
  #cbar input { flex:1; padding:6px 8px; background:#0d131c; color:var(--ink); border:1px solid var(--line); border-radius:6px; font-family:Menlo,monospace; }
  #status { color:var(--muted); font-size:12px; }
  .ctop { display:flex; align-items:center; gap:8px; padding:6px 10px; background:#0a0e14; color:#8b99a8; font-size:12px; border-bottom:1px solid var(--line); }
  .ctop .grow { flex:1; }
  /* modal */
  #overlay { display:none; position:fixed; inset:0; background:rgba(0,0,0,.6); align-items:center; justify-content:center; z-index:50; }
  #overlay.show { display:flex; }
  #modal { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:22px; width:460px; max-width:92vw; box-shadow:0 10px 40px rgba(0,0,0,.6); color:var(--ink); }
  #modal h2 { margin:0 0 12px; font-size:16px; color:#fff; }
  #modal p { white-space:pre-wrap; line-height:1.6; font-size:13.5px; }
  #modal .btns { margin-top:18px; display:flex; gap:10px; justify-content:flex-end; }
  .step { font-weight:600; color:var(--warn); }
  .legal { color:var(--muted); font-size:11px; margin-left:auto; }
  ::-webkit-scrollbar { width:10px; height:10px; }
  ::-webkit-scrollbar-thumb { background:#2a3340; border-radius:5px; }
  ::-webkit-scrollbar-track { background:transparent; }
</style>
</head>
<body>
<header>
  <h1>PM3一键工具<span>webUI</span></h1>
  <input id="exec" class="path" placeholder="客户端路径 pm3/proxmark3">
  <select id="port" title="串口"></select>
  <button onclick="scanPorts()">扫描</button>
  <input id="savedir" class="dir" placeholder="保存目录">
  <span><span id="dot" class="dot"></span><span id="connlbl">未连接</span></span>
  <button id="connbtn" class="pri" onclick="toggleConnect()">连接</button>
  <span class="legal">仅用于授权测试 / 本人卡片</span>
</header>

<div id="main">
  <div id="left">
    <div id="leftTop">
      <div class="row" style="margin-bottom:8px">
        <span style="font-size:12px;color:var(--muted)">MIFARE 卡型:</span>
        <select id="size">
          <option value="auto">自动检测</option><option value="mini">Mini</option>
          <option value="1k">1K</option><option value="2k">2K</option><option value="4k">4K</option>
        </select>
      </div>
      <div class="tabs" id="tabs"></div>
      <div id="panels"></div>
    </div>
    <div id="statusPanel">
      <h4>📇 卡片信息</h4>
      <div class="kv" id="siCard"><span class="muted">(尚未读取卡片)</span></div>
      <div class="dual">
        <div class="col">
          <h4>🔑 已恢复密钥 <span id="siKeyFile" class="muted" style="font-weight:normal"></span></h4>
          <div id="siKeys"><span class="kv muted">(暂无, 运行获取密钥后显示)</span></div>
        </div>
        <div class="col">
          <h4>🗂 扇区数据 <span id="siDumpFile" class="muted" style="font-weight:normal"></span></h4>
          <div id="siDump"><span class="kv muted">(暂无, Dump 卡片后显示)</span></div>
        </div>
      </div>
      <h4>⚙️ 任务执行</h4>
      <div id="siTasks"><span class="kv muted">(暂无任务)</span></div>
    </div>
  </div>

  <div id="right">
    <div class="ctop">
      <span>控制台输出</span><span class="grow"></span>
      <span id="status">未连接</span>
      <button onclick="abort()">中止当前</button>
      <button onclick="clearConsole()">清空</button>
    </div>
    <div id="console"></div>
    <div id="cbar">
      <input id="cmd" placeholder="手动命令, 回车发送 (如 hf mf info)" onkeydown="if(event.key==='Enter')sendManual()">
      <button class="pri" onclick="sendManual()">发送</button>
    </div>
  </div>
</div>

<div id="overlay"><div id="modal">
  <h2 id="mtitle"></h2><p id="mbody"></p>
  <div class="btns" id="mbtns"></div>
</div></div>

<script>
const $ = s => document.querySelector(s);
let connected=false;

// ---- 功能定义 ----
function sz(){ const v=$('#size').value; return {auto:'',mini:'--mini','1k':'--1k','2k':'--2k','4k':'--4k'}[v]||''; }
function mf(sub){ return ('hf mf '+sub+' '+sz()).trim(); }

const TABS = {
 '设备': [
   {t:'硬件版本 (hw version)', c:()=>run('硬件版本','hw version')},
   {t:'硬件状态 (hw status)', c:()=>run('硬件状态','hw status')},
   {t:'天线调谐 (hw tune)', c:()=>run('天线调谐','hw tune'), tip:'测量天线电压, 放上卡看场强变化'},
 ],
 '识别': [
   {t:'★ 全自动识别 (auto)', c:()=>run('全自动识别','auto',120), tip:'未知卡自动 HF+LF 检测', pri:1},
   {t:'高频搜索 (hf search)', c:()=>run('HF搜索','hf search',60)},
   {t:'低频搜索 (lf search)', c:()=>run('LF搜索','lf search',60)},
   {t:'14a 卡片信息 (hf 14a info)', c:()=>run('14a信息','hf 14a info')},
 ],
 'MIFARE Classic': [
   {t:'🧠 智能获取密钥 (自动选择攻击)', c:smartKeys, pri:1, tip:'识别卡型/PRNG, 自动选 nested/hardnested/staticnested/darkside 并保存密钥+dump'},
   {t:'卡片信息 (hf mf info)', c:()=>run('MFC信息','hf mf info')},
   {t:'快速默认密钥 (fchk)', c:()=>run('默认密钥','hf mf fchk '+sz(),120)},
   {t:'自动破解+导出 (autopwn)', c:()=>run('autopwn',mf('autopwn'),1800)},
   {t:'Nested 攻击', c:dlgNested, tip:'已知一个扇区密钥时推导其余'},
   {t:'Hardnested 攻击', c:dlgHardnested, tip:'针对加固卡, 较慢'},
   {t:'Darkside 攻击', c:()=>run('darkside','hf mf darkside',600)},
   {t:'Dump 卡片 (hf mf dump)', c:()=>run('Dump',mf('dump'),300)},
   {t:'写回/恢复 (restore)', c:dlgRestore},
 ],
 '脚本攻击': [
   {html:'<div class="tip">调用 pm3 内置 Python 脚本 (client/pyscripts) 的进阶密钥恢复。以下为已在本机客户端实测可加载运行的脚本 (耗时可能较长)。</div>'},
   {html:'<div class="tip" style="color:var(--accent2)">— Fudan FM11RF08S / FM11RF08 (带后门的 MIFARE Classic 仿制卡) —</div>'},
   {t:'FM11RF08S 密钥恢复 (recovery)', c:()=>run('FM11RF08S恢复','script run fm11rf08s_recovery',2700), pri:1,
     tip:'综合后门攻击恢复全部密钥, 视密钥复用情况约 1~30 分钟'},
   {t:'FM11RF08S 全量恢复+Dump (full -r)', c:()=>run('FM11RF08S全量','script run fm11rf08s_full -r',2700),
     tip:'恢复密钥并完整 dump (含 Bambu/MAD 解码)'},
   {t:'后门 Dump (mf_backdoor_dump)', c:()=>run('后门Dump','script run mf_backdoor_dump',600),
     tip:'用 FM11RF08S 等芯片的后门密钥快速读取可读数据'},
   {html:'<div class="tip" style="color:var(--accent2)">— NTAG / Ultralight —</div>'},
   {t:'NTAG22x SUNCMAC 恢复', c:()=>run('NTAG22x恢复','script run ntag22x_suncmac_recovery',600),
     tip:'恢复 NTAG 22x DNA 的 mask 与 SUNCMAC 密钥'},
   {t:'USCUID-UL 魔术卡配置 (uscuid)', c:()=>run('USCUID-UL','script run hf_mfu_uscuid -h',60),
     tip:'查看/配置 USCUID-UL 系列 UL 魔术卡 (先看帮助)'},
   {html:'<div class="tip">— 其它 —</div>'},
   {t:'列出全部可用脚本 (script list)', c:()=>run('脚本列表','script list',30)},
   {html:'<div class="tip" style="color:var(--bad)">注: mfulc_counterfeit_recovery (缺 mfulc_des_brute 工具)、mfulaes_mask_recovery、mfuev1_counter_reset 在本机客户端的内置 Python 3.9 下无法运行, 已隐藏。</div>'},
 ],
 '复制卡片': [
   {t:'① 智能读取源卡', c:smartKeys, pri:1, tip:'自动恢复全部密钥并保存 dump/keys'},
   {t:'从文件载入 dump', c:loadDump},
   {html:'<div class="info" id="cloneInfo">源卡: (未读取)</div>'},
   {radio:'cloneTarget', label:'新卡类型:', opts:[
     ['gen1a','魔术卡 Gen1a (后门, 完整克隆含UID)'],
     ['gen2','魔术卡 Gen2/CUID (可写块0)'],
     ['normal','普通卡 (仅数据扇区)']]},
   {t:'② 写入新卡', c:cloneWrite, pri:1},
   {t:'设置魔术卡 UID (csetuid)', c:dlgCsetuid},
 ],
 '手机复制': [
   {html:'<div class="tip">把实体卡复制到手机: ①读卡恢复密钥 → ②PM3模拟卡, 手机复制UID → ③手机切到该卡放PM3上, 验证UID后写入数据。仅支持 MIFARE Classic。</div>'},
   {radio:'phoneMethod', label:'写入方式 (写到手机卡):', opts:[
     ['restore_default','默认密钥写入 (restore, 推荐)'],
     ['cload','魔术卡后门写入 (cload, Gen1a)'],
     ['restore_ka','用源卡密钥写入 (restore --ka)']]},
   {t:'▶ 开始手机复制流程', c:phoneStart, pri:1, tip:'放上被复制的实体卡后点击, 按弹窗一步步操作'},
   {t:'■ 重置 / 取消流程', c:phoneCancel},
   {html:'<div class="info step" id="phoneStatus">状态: 待开始</div>'},
 ],
 '魔术卡': [
   {t:'写入 dump 到魔术卡 (cload)', c:dlgCload, tip:'含块0完整写入魔术卡'},
   {t:'从魔术卡读取保存 (csave)', c:()=>run('csave','hf mf csave '+sz(),120)},
   {t:'设置 UID (csetuid)', c:dlgCsetuid},
   {t:'擦除魔术卡 (cwipe)', c:()=>{ if(confirm('确定擦除魔术卡为默认状态?')) run('cwipe','hf mf cwipe',120); }},
   {t:'读取块0 (cgetblk)', c:()=>run('读块0','hf mf cgetblk --blk 0')},
 ],
 'Ultralight': [
   {t:'卡片信息 (hf mfu info)', c:()=>run('MFU信息','hf mfu info')},
   {t:'Dump 卡片 (hf mfu dump)', c:()=>run('MFU Dump','hf mfu dump',120)},
 ],
 '低频 LF': [
   {t:'读取 EM410x', c:()=>run('EM410x读取','lf em 410x reader')},
   {t:'克隆 EM410x 到 T55x7', c:dlgEm410x},
   {t:'T55xx 检测', c:()=>run('T55xx检测','lf t55xx detect')},
   {t:'T55xx Dump', c:()=>run('T55xx Dump','lf t55xx dump',120)},
   {t:'读取 HID Prox', c:()=>run('HID读取','lf hid reader')},
 ],
};

// ---- 构建界面 ----
function build(){
  const tabsEl=$('#tabs'), panelsEl=$('#panels'); let first=true;
  for(const name in TABS){
    const b=document.createElement('button'); b.textContent=name;
    b.onclick=()=>{ document.querySelectorAll('.tabs button').forEach(x=>x.classList.remove('active'));
      document.querySelectorAll('.panel').forEach(x=>x.classList.remove('active'));
      b.classList.add('active'); document.getElementById('panel-'+name).classList.add('active'); };
    tabsEl.appendChild(b);
    const p=document.createElement('div'); p.className='panel'; p.id='panel-'+name;
    const card=document.createElement('div'); card.className='card';
    const grid=document.createElement('div'); grid.className='grid';
    for(const item of TABS[name]){
      if(item.html){ const d=document.createElement('div'); d.innerHTML=item.html; grid.appendChild(d); continue; }
      if(item.radio){
        const wrap=document.createElement('div');
        wrap.innerHTML='<div style="font-size:12px;margin:4px 0">'+item.label+'</div>';
        item.opts.forEach((o,i)=>{ const l=document.createElement('label'); l.className='radio';
          l.innerHTML='<input type="radio" name="'+item.radio+'" value="'+o[0]+'"'+(i===0?' checked':'')+'> '+o[1];
          wrap.appendChild(l); });
        grid.appendChild(wrap); continue;
      }
      const btn=document.createElement('button'); btn.textContent=item.t; if(item.pri)btn.className='pri';
      btn.onclick=item.c; btn.dataset.act='1'; grid.appendChild(btn);
      if(item.tip){ const tp=document.createElement('div'); tp.className='tip'; tp.textContent=item.tip; grid.appendChild(tp); }
    }
    card.appendChild(grid); p.appendChild(card); panelsEl.appendChild(p);
    if(first){ b.classList.add('active'); p.classList.add('active'); first=false; }
  }
}

// ---- 通信 ----
async function api(path, body){
  const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})});
  return r.json();
}
function appendConsole(t){ const c=$('#console'); c.textContent+=t;
  if(c.textContent.length>400000) c.textContent=c.textContent.slice(-300000);
  c.scrollTop=c.scrollHeight; }
function clearConsole(){ $('#console').textContent=''; }

function run(label,cmd,timeout){ if(!chk())return; api('/api/run',{label,command:cmd,timeout:timeout||900}); }
function chk(){ if(!connected){ alert('请先连接 Proxmark3'); return false; } return true; }
function sendManual(){ const v=$('#cmd').value.trim(); if(!v||!chk())return; $('#cmd').value=''; api('/api/run',{label:'手动',command:v,timeout:1800}); }
function abort(){ api('/api/abort'); }
function smartKeys(){ if(!chk())return; api('/api/smart_keys',{size:sz()}); }
function cloneWrite(){ if(!chk())return; const t=document.querySelector('input[name=cloneTarget]:checked').value;
  if(!confirm('将把源卡数据写入【新卡】('+t+'), 请确认已放上新卡。继续?'))return;
  api('/api/clone_write',{target:t,size:sz()}); }
async function loadDump(){ const fs=await (await fetch('/api/files')).json();
  const name=prompt('输入 dump 文件名 (保存目录中):\n'+(fs.files||[]).join('\n'), fs.source||'');
  if(name) api('/api/set_source',{dump:name}); }

function dlgNested(){ if(!chk())return; const blk=prompt('已知扇区块号(如0)','0'); if(blk===null)return;
  const kt=prompt('密钥类型 a/b','a')||'a'; const key=prompt('已知密钥(12 hex)','FFFFFFFFFFFF')||'FFFFFFFFFFFF';
  run('nested',('hf mf nested '+sz()+' --blk '+blk+' -'+kt+' -k '+key).trim(),600); }
function dlgHardnested(){ if(!chk())return; const blk=prompt('已知扇区块号','0'); if(blk===null)return;
  const kt=prompt('已知密钥类型 a/b','a')||'a'; const key=prompt('已知密钥(12 hex)','FFFFFFFFFFFF')||'FFFFFFFFFFFF';
  const tb=prompt('目标块号','4')||'4'; const tt=prompt('目标密钥类型 a/b','a')||'a';
  run('hardnested','hf mf hardnested --blk '+blk+' -'+kt+' -k '+key+' --tblk '+tb+' --t'+tt,3600); }
function dlgRestore(){ if(!chk())return; const f=prompt('dump 文件名(留空自动)',''); if(f===null)return;
  let cmd=('hf mf restore '+sz()).trim(); if(f)cmd+=' -f '+f; run('restore',cmd,300); }
function dlgCsetuid(){ if(!chk())return; const u=prompt('新 UID (4或7 hex字节, 如04112233)',''); if(u) run('csetuid','hf mf csetuid -u '+u,60); }
async function dlgCload(){ if(!chk())return; const fs=await (await fetch('/api/files')).json();
  const f=prompt('要写入魔术卡的 dump 文件名:\n'+(fs.files||[]).join('\n'), fs.source||''); if(f) run('cload','hf mf cload -f '+f,300); }
function dlgEm410x(){ if(!chk())return; const id=prompt('EM410x ID (10 hex, 如0102030405)',''); if(id) run('EM410x克隆','lf em 410x clone --id '+id,60); }

// ---- 连接 ----
async function toggleConnect(){
  if(connected){ await api('/api/disconnect'); return; }
  $('#connlbl').textContent='连接中...'; $('#dot').className='dot wait';
  const r=await api('/api/connect',{exec:$('#exec').value.trim(),port:$('#port').value.trim(),savedir:$('#savedir').value.trim()});
  if(!r.ok){ alert('连接失败: '+r.message+'\n\n若客户端未编译, 请先在 proxmark3 目录执行 make'); }
}
async function scanPorts(){ const r=await (await fetch('/api/ports')).json(); fillPorts(r.ports); }
function fillPorts(ports){ const sel=$('#port'); const cur=sel.value; sel.innerHTML='<option value="">(自动)</option>';
  (ports||[]).forEach(p=>{ const o=document.createElement('option'); o.value=p; o.textContent=p; sel.appendChild(o); });
  if(cur) sel.value=cur; }

function setState(s){
  connected=s.connected;
  $('#dot').className='dot'+(s.connected?' on':'');
  $('#connlbl').textContent=s.connected?'已连接':'未连接';
  $('#connbtn').textContent=s.connected?'断开':'连接';
  $('#status').textContent = s.connected ? (s.busy?'忙碌':'空闲'+(s.queue?(' (队列'+s.queue+')'):'')) : '未连接';
  if(s.source){ const c=$('#cloneInfo'); if(c) c.textContent='源卡 UID: '+(s.source.uid||'?')+'\ndump: '+(s.source.dump||'(无)')+'\nkeys: '+(s.source.keys||'(无)'); }
}

// ---- 手机复制弹窗 ----
function modal(title, body, buttons){
  $('#mtitle').textContent=title; $('#mbody').textContent=body;
  const bb=$('#mbtns'); bb.innerHTML='';
  buttons.forEach(b=>{ const el=document.createElement('button'); el.textContent=b.t; if(b.pri)el.className='pri';
    el.onclick=()=>{ closeModal(); b.c&&b.c(); }; bb.appendChild(el); });
  $('#overlay').classList.add('show');
}
function closeModal(){ $('#overlay').classList.remove('show'); }
function phoneStart(){ if(!chk())return; $('#phoneStatus').textContent='状态: 步骤1/4 读取被复制卡片...'; api('/api/phone/start',{size:sz()}); }
function phoneCancel(){ closeModal(); $('#phoneStatus').textContent='状态: 流程已取消'; api('/api/phone/cancel'); }
function phoneMethodVal(){ const r=document.querySelector('input[name=phoneMethod]:checked'); return r?r.value:'restore_default'; }

function onPhone(d){
  const st=$('#phoneStatus');
  if(d.stage==='reading'){ st.textContent='状态: 步骤1/4 读取被复制卡片 (识别+恢复密钥)...'; }
  else if(d.stage==='fail'){ st.textContent='状态: 流程终止'; modal('手机复制 - 终止', d.msg, [{t:'知道了',pri:1}]); }
  else if(d.stage==='awaiting_copy'){
    st.textContent='状态: 步骤2/4 PM3 模拟源卡, 等待手机复制 UID...';
    modal('步骤2 · 手机复制 UID',
      'PM3 正在模拟源卡 (UID '+d.uid+')。\n\n请打开手机的 NFC 卡复制 App, 读取/复制这张『卡』的 UID。\n\n复制完成后点击下面按钮。',
      [{t:'取消',c:phoneCancel},{t:'手机已复制完成卡片卡号',pri:1,c:()=>{ st.textContent='状态: 步骤3/4 请放置手机...'; api('/api/phone/uid_copied'); }}]);
  }
  else if(d.stage==='awaiting_place'){
    st.textContent='状态: 步骤3/4 请把手机切到该卡并放到 PM3 上...';
    modal('步骤3 · 放置手机',
      '请在手机上切换到刚刚复制的那张卡 (与源卡同 UID), 并把手机贴放到 PM3 天线上。\n\n放好后点击下面按钮, PM3 将验证 UID 并写入数据。',
      [{t:'取消',c:phoneCancel},{t:'已切换并放置',pri:1,c:()=>{ st.textContent='状态: 步骤4/4 验证并写入...'; api('/api/phone/placed',{method:phoneMethodVal()}); }}]);
  }
  else if(d.stage==='verify_failed'){
    st.textContent='状态: 验证失败, 可重试';
    modal('验证失败', d.msg+'\n\n重新放置手机后点『重试』。',
      [{t:'取消',c:phoneCancel},{t:'重试',pri:1,c:()=>{ st.textContent='状态: 步骤4/4 验证并写入...'; api('/api/phone/placed',{method:phoneMethodVal()}); }}]);
  }
  else if(d.stage==='done'){
    st.textContent = d.ok ? '状态: ✓ 手机复制完成!' : '状态: 写入结束 (请核对日志)';
    modal('手机复制完成', d.ok? '数据已写入手机卡。\n请用手机刷卡实测是否生效。' : '写入流程已结束, 但日志中可能有失败扇区, 请查看控制台。',
      [{t:'完成',pri:1}]);
  }
  else if(d.stage==='cancelled'){ closeModal(); st.textContent='状态: 流程已取消'; }
}

// ---- 左下面板渲染 ----
function esc(s){ return (s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
let cardState={};
function mergeCard(c){
  if(c.uid && cardState.uid && c.uid!==cardState.uid){ cardState={}; // 换卡: 清空旧信息/密钥/扇区数据
    $('#siKeys').innerHTML='<span class="kv muted">(暂无)</span>'; $('#siKeyFile').textContent='';
    $('#siDump').innerHTML='<span class="kv muted">(暂无)</span>'; $('#siDumpFile').textContent=''; }
  for(const k in c){ const v=c[k]; if(v!==undefined && v!=='' && v!==null && v!==false) cardState[k]=v; }
  drawCard();
}
function drawCard(){
  const c=cardState;
  if(!c.uid && !c.family){ $('#siCard').innerHTML='<span class="muted">(尚未读取卡片)</span>'; return; }
  let pills='';
  if(c.prng==='weak') pills+='<span class="pill weak">PRNG weak</span>';
  else if(c.prng==='hard') pills+='<span class="pill hard">PRNG hard</span>';
  if(c.static) pills+='<span class="pill static">静态随机数</span>';
  if(c.magic) pills+='<span class="pill magic">魔术卡</span>';
  if(c.chip) pills+='<span class="pill chip">'+esc(c.chip)+'</span>';
  let h='';
  h+='<div><b>UID:</b> '+esc(c.uid||'?')+'</div>';
  h+='<div><b>类型:</b> MIFARE '+esc(c.family||'?')+(c.size?(' / '+esc(c.size)):'')+' '+pills+'</div>';
  if(c.atqa||c.sak) h+='<div class="muted">ATQA '+esc(c.atqa||'?')+'   SAK '+esc(c.sak||'?')+'</div>';
  if(c.chip) h+='<div><b>芯片指纹:</b> '+esc(c.chip)+'</div>';
  if(c.method) h+='<div><b>推荐方法:</b> '+esc(c.method)+'</div>';
  $('#siCard').innerHTML = h;
}
function renderKeys(d){
  $('#siKeyFile').textContent = d.file?('('+d.file+')'):'';
  const s=d.sectors||[];
  if(!s.length){ $('#siKeys').innerHTML='<span class="kv muted">(无)</span>'; return; }
  let t='<table class="tbl"><tr><th>扇区</th><th>Key A</th><th>Key B</th></tr>';
  s.forEach(r=>{ t+='<tr><td>'+r.sector+'</td><td class="hex ka">'+esc(r.a)+'</td><td class="hex kb">'+esc(r.b)+'</td></tr>'; });
  t+='</table>';
  $('#siKeys').innerHTML=t;
}
function fmtHex(h){ return (h||'').replace(/(..)/g,'$1 ').trim(); }
function renderDump(d){
  $('#siDumpFile').textContent = d.file?('('+d.file+')'):'';
  const b=d.blocks||[];
  if(!b.length){ $('#siDump').innerHTML='<span class="kv muted">(无)</span>'; return; }
  let t='<table class="tbl"><tr><th>扇区</th><th>块</th><th>数据 (16字节)</th></tr>';
  let prev=-1;
  b.forEach(r=>{
    const sep = r.sector!==prev ? ' secsep':''; prev=r.sector;
    t+='<tr class="'+(r.trailer?'trailer':'')+sep+'"><td>'+r.sector+'</td><td>'+r.block+(r.trailer?' 尾':'')+
       '</td><td class="hex">'+esc(fmtHex(r.hex))+'</td></tr>';
  });
  t+='</table>';
  $('#siDump').innerHTML=t;
}
let tasks=[];
function renderTask(d){
  if(d.state==='start') tasks.unshift({label:d.label, st:'run', ts:d.ts});
  else { const it=tasks.find(x=>x.label===d.label&&x.st==='run'); if(it){ it.st=d.state; it.ts=d.ts; it.err=d.err; }
         else tasks.unshift({label:d.label, st:d.state, ts:d.ts, err:d.err}); }
  tasks=tasks.slice(0,12);
  const sym={run:'▶',done:'✓',error:'✗'};
  $('#siTasks').innerHTML = tasks.map(t=>
    '<div class="tk '+(t.st==='done'?'ok':t.st==='error'?'err':'run')+'">'+
    (sym[t.st]||'')+' '+esc(t.ts||'')+'  '+esc(t.label)+(t.err?(' — '+esc(t.err)):'')+'</div>').join('');
}

// ---- SSE ----
function startSSE(){
  const es=new EventSource('/api/stream');
  es.addEventListener('log', e=>appendConsole(JSON.parse(e.data)));
  es.addEventListener('state', e=>setState(JSON.parse(e.data)));
  es.addEventListener('status', e=>{ /* 状态已由 state 更新 */ });
  es.addEventListener('analysis', e=>{ const a=JSON.parse(e.data);
    mergeCard({family:a.family, size:a.size_name, prng:a.prng, static:a.static, magic:a.magic, chip:a.chip, method:a.method}); });
  es.addEventListener('cardinfo', e=>mergeCard(JSON.parse(e.data)));
  es.addEventListener('keys', e=>renderKeys(JSON.parse(e.data)));
  es.addEventListener('dump', e=>renderDump(JSON.parse(e.data)));
  es.addEventListener('task', e=>renderTask(JSON.parse(e.data)));
  es.addEventListener('phone', e=>onPhone(JSON.parse(e.data)));
  es.onerror=()=>{ /* 自动重连 */ };
}

// ---- 初始化 ----
async function init(){
  build();
  const r=await (await fetch('/api/ports')).json();
  $('#exec').value=r.exec||''; $('#savedir').value=r.savedir||'';
  fillPorts(r.ports); if(r.config&&r.config.port) $('#port').value=r.config.port;
  setState(r.state||{connected:false});
  startSSE();
}
init();
</script>
</body>
</html>"""


# --------------------------------------------------------------------------- #
# HTTP 处理
# --------------------------------------------------------------------------- #

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass  # 静默

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, text):
        body = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return {}

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            return self._html(HTML_PAGE)
        if path == "/api/ports":
            cfg = load_config()
            return self._json({
                "ports": scan_ports(),
                "exec": cfg.get("exec", find_executable()),
                "savedir": cfg.get("savedir", os.path.join(PROJECT_ROOT, "pm3_data")),
                "config": cfg,
                "state": ENGINE.state(),
            })
        if path == "/api/files":
            return self._json({"files": ENGINE.list_dumps(), "source": ENGINE.source_dump or ""})
        if path == "/api/stream":
            return self._sse()
        return self._json({"error": "not found"}, 404)

    def do_POST(self):
        path = self.path.split("?")[0]
        d = self._body()
        if path == "/api/connect":
            return self._json(ENGINE.connect(d.get("exec", ""), d.get("port", ""), d.get("savedir", "")))
        if path == "/api/disconnect":
            return self._json(ENGINE.disconnect())
        if path == "/api/run":
            return self._json(ENGINE.enqueue_cmd(d.get("label", "命令"), d.get("command", ""),
                                                 int(d.get("timeout", 900))))
        if path == "/api/abort":
            return self._json(ENGINE.abort())
        if path == "/api/smart_keys":
            return self._json(ENGINE.smart_keys(d.get("size", "")))
        if path == "/api/clone_write":
            return self._json(ENGINE.clone_write(d.get("target", "gen1a"), d.get("size", "")))
        if path == "/api/set_source":
            if d.get("dump"):
                ENGINE.source_dump = d["dump"]
                m = re.search(r"hf-mf-([0-9A-Fa-f]+)-dump", d["dump"])
                if m:
                    ENGINE.source_uid = m.group(1)
                    kf = f"hf-mf-{m.group(1)}-key.bin"
                    if os.path.isfile(os.path.join(ENGINE.savedir, kf)):
                        ENGINE.source_keys = kf
                ENGINE.push_state()
            return self._json({"ok": True})
        if path == "/api/phone/start":
            return self._json(ENGINE.phone_start(d.get("size", "")))
        if path == "/api/phone/uid_copied":
            return self._json(ENGINE.phone_uid_copied())
        if path == "/api/phone/placed":
            return self._json(ENGINE.phone_placed(d.get("method", "restore_default")))
        if path == "/api/phone/cancel":
            return self._json(ENGINE.phone_cancel())
        return self._json({"error": "not found"}, 404)

    def _sse(self):
        q = ENGINE.add_client()
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            # 立即推送一次当前状态 (便于刷新页面后恢复显示)
            self._sse_send("state", ENGINE.state())
            if ENGINE.cardinfo:
                self._sse_send("cardinfo", ENGINE.cardinfo)
            k = ENGINE.read_keys()
            if k is not None:
                self._sse_send("keys", {"file": ENGINE.source_keys, "sectors": k})
            dmp = ENGINE.read_dump()
            if dmp is not None:
                self._sse_send("dump", {"file": ENGINE.source_dump, "blocks": dmp})
            while True:
                try:
                    ev, data = q.get(timeout=15)
                    self._sse_send(ev, data)
                except queue.Empty:
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            ENGINE.remove_client(q)

    def _sse_send(self, ev, data):
        # data 可为 str(日志) 或 dict(结构化), 统一 JSON 编码;
        # 前端对 log 与结构化事件都用 JSON.parse 解析。
        line = "event: " + ev + "\ndata: " + json.dumps(data, ensure_ascii=False) + "\n\n"
        self.wfile.write(line.encode("utf-8"))
        self.wfile.flush()


def main():
    if not HAVE_PTY and not IS_WINDOWS:
        print("错误: 当前平台既不支持 pty 也不是 Windows, 无法运行。")
        sys.exit(1)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = httpd.server_address[1]
    url = f"http://127.0.0.1:{port}/"
    print("=" * 52)
    print("  PM3一键工具 webUI")
    print("=" * 52)
    print(f"  已启动, 请在浏览器打开:  {url}")
    print("  (按 Ctrl-C 关闭服务)")
    print("=" * 52)
    try:
        webbrowser.open(url)
    except Exception:
        pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n正在关闭...")
        if ENGINE.session:
            ENGINE.session.stop()
        httpd.shutdown()


if __name__ == "__main__":
    main()
