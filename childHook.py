# -*- coding: utf-8 -*-
from __future__ import print_function

import threading
import time
import frida
from frida_tools.application import Reactor
import subprocess
import sys

package = "com.m***e.l****s"
child_gating = package + ":U**tyK**s**"
script_path = "*******\hook_socket.js"
log_file = '******\\frida_console2.log'

class Application(object):
    def __init__(self):
        self._stop_requested = threading.Event()
        self._reactor = Reactor(run_until_return=lambda reactor: self._stop_requested.wait())

        self._device = frida.get_usb_device()
        self._sessions = set()

    def run(self):
        self._reactor.schedule(lambda: self._start())
        self._reactor.run()

    def _start(self):
        self._device = frida.get_usb_device()
        #先启动父进程
        print("✔ spawn " + package)
        pid = self._device.spawn([package])
        print(f"✔ resume(pid={pid})")
        self._device.resume(pid)
        
        print("⏳ 等待子进程...")
        target_pid = None
        while True:
            result = subprocess.run(["adb", "shell", "ps", "-ef"], stdout=subprocess.PIPE, text=True)
            lines = [line for line in result.stdout.splitlines() if package in line]
            if len(lines) >= 2:
                target_pid = lines[1].split()[1]  # 第二个匹配行，取 PID
                print(f"✅ 找到目标子进程 PID: {target_pid}")
                break
            else:
                print("🔍 未找到第二个进程，继续等待...")
                time.sleep(1)
        self._instrument(int(target_pid))

    def _instrument(self, target_pid):
        cmd = [
            "frida",
            "-U",
            "-p", str(target_pid),
            "-l", script_path,
            "-o", log_file
        ]
        # cmd = [
        #     "python",
        #     "D:\\tools\\r0capture\\r0capture.py",
        #     "-U",
        #     str(target_pid)
        # ]
        # 启动并附加到进程
        subprocess.run(cmd)

    def _on_detached(self, pid, session, reason):
        print(f"⚡ detached: pid={pid}, reason='{reason}'")
        self._sessions.remove(session)
        self._reactor.schedule(self._stop_if_idle, delay=0.5)

app = Application()
app.run()
