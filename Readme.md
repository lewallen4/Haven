# ✦ Haven

<div align="center">

**Haven is a self-hosted, end-to-end encrypted chat client built for small groups who want real privacy without the overhead. No accounts, no servers you don't control, no data you didn't choose to share.**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com)

[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Configuration](#%EF%B8%8F-configuration) • [Screenshots](#-screenshots)

</div>

---

## ✦ Features

- **End-to-end encrypted** — post-quantum hybrid encryption on every message
- **Voice chat** — push-to-talk with per-device audio routing and adjustable release delay
- **Zero-latency sound effects** — pre-loaded PCM playback via PyAudio, no WinMM overhead
- **TOFU certificate trust** — first-connection fingerprint pinning with a human-friendly mismatch dialog
- **Fully themeable** — swap JSON theme files at runtime, live preview included
- **Custom name colors** — pick from a curated palette, synced to all users in the room
- **System tray support** — minimize to tray, notifications when backgrounded
- **No OS window chrome** — fully custom titlebar, resizable, remembers its last size

---

## ✦ Setup

```bash
pip install pyaudio pystray pillow pynput cryptography
python haven_client.py
```

Point it at your Haven server, enter a username and password, and you're in.

---

## ✦ Server

Haven requires a companion server. Drop `haven_server.py` on any machine you control, open the port, and share the IP with whoever you want in the room. That's it — no sign-up, no cloud, no middleman.

---

## ✦ Stack

`Python` · `Tkinter` · `PyAudio` · `PortAudio` · `AES-GCM` · `pynput` · `pystray`

---

<div align="center">
  <sub>built with care &nbsp;✦&nbsp; v3.2</sub>
</div>
