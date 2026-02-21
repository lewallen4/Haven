# ⚡ Haven Chat

<div align="center">

**A secure, feature-rich voice and text chat application with a retro-futuristic aesthetic**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com)

[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Configuration](#%EF%B8%8F-configuration) • [Screenshots](#-screenshots)

</div>

---

## 🌟 Features

### 🎤 Voice Communication


### 💬 Text Chat


### 🎨 Modern UI/UX


### 🔐 Security
- **Password-protected servers** with SHA-256 hashing
- **Optional password remembering** for convenience
- **IP-based ban system** for server administrators


### ⚙️ Customization


### 🛠️ Administration


---

## 📋 Requirements

### Client Requirements
- Python 3.8 or higher
- tkinter (usually included with Python)
- PyAudio
- NumPy (optional, for enhanced audio features)

### Server Requirements
- Python 3.8 or higher
- Standard library modules only (no external dependencies)

---

## 🚀 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/haven-chat.git
cd haven-chat
```

### 2. Install Dependencies

#### Windows
```bash
pip install pyaudio numpy
```

#### Linux (Ubuntu/Debian)
```bash
sudo apt-get install python3-pyaudio portaudio19-dev
pip install pyaudio numpy
```

---

## ⚡ Quick Start

### Starting the Server



1. **Run the server**:
   ```bash
   python server.py
   ```

2. **Admin console commands**:
   ```
   /kick <username>      - Kick a user from the server
   /ban <IP>            - Ban an IP address
   /unban <IP>          - Remove an IP from ban list
   /password <newpass>  - Change server password
   /list                - Show all connected users
   /history [n]         - Show last n chat messages
   /save                - Manually save chat history
   /help                - Display help information
   ```

### Connecting as a Client

1. **Run the client**:
   ```bash
   python client.py
   ```

2. **First-time setup**:
   - Enter the server IP
   - Enter your desired username
   - Enter the server password
   - (Optional) Check "Remember password" for auto-login

---

## ⚙️ Configuration

### Client Configuration
The client automatically saves preferences to `haven_config.json`:

```json
{
  "username": "YourUsername",
  "password": "optional_saved_password",
  "ptt_key": "Control_L",
  "name_color": "#00ff88",
  "input_device": "Default",
  "output_device": "Default",
  "input_volume": 100,
  "output_volume": 100
}
```

### Port Configuration
Default ports can be changed in both files:
- **TCP Port**: 5000 (text chat, control messages)
- **UDP Port**: 5001 (voice data)

---

## 🎯 Usage Tips

### For the Best Experience

1. **Audio Setup**
   - Test your microphone and speakers using the built-in test feature
   - Adjust input/output volumes to your preference (100% is default)
   - Use headphones to prevent echo/feedback

2. **Push-to-Talk**
   - Default key is Left Ctrl
   - Choose a key that's comfortable for your setup
   - Key is displayed on the voice button

3. **Username Colors**
   - Colors are automatically assigned from the palette
   - Change your color anytime via Settings → Change Name Color
   - Colors sync across all connected clients

4. **Performance**
   - The app auto-detects the best audio sample rate for your device
   - Supports rates from 8kHz (phone quality) to 48kHz (studio quality)
   - Lower rates use less bandwidth but reduce audio quality

---

## 🔧 Troubleshooting

### Audio Issues

**Problem**: Microphone not working
```
Solution: 
1. Go to Settings → Audio Devices & Volume
2. Select the correct input device
3. Test the microphone using the "Test Microphone" button
4. Ensure your OS hasn't muted the application
```

**Problem**: Can't hear other users
```
Solution:
1. Check output device in Settings
2. Increase output volume
3. Test speakers using "Test Speakers" button
4. Verify your system audio isn't muted
```

### Connection Issues

**Problem**: Can't connect to server
```
Solution:
1. Verify server is running
2. Check SERVER_HOST is correct (use server's IP, not 127.0.0.1 for remote connections)
3. Ensure ports 5000 and 5001 are open in firewall
4. Verify correct password
```

**Problem**: "Username taken" error
```
Solution:
1. Choose a different username
2. Or wait for the previous session to timeout
3. Server admin can kick the old session
```

### Platform-Specific Issues

**Windows**: If PyAudio installation fails:
```bash
pip install pipwin
pipwin install pyaudio
```

**Linux**: If you get "ALSA lib" errors:
```bash
sudo apt-get install libasound2-dev
```

**macOS**: If microphone access is denied:
```
System Preferences → Security & Privacy → Microphone → Enable for Terminal/Python
```

---

## 🏗️ Architecture

### Network Protocol

```
┌─────────────┐                    ┌─────────────┐
│   Client    │                    │   Server    │
│             │  TCP (Port 5000)   │             │
│  ┌───────┐  │◄──────────────────►│  ┌───────┐  │
│  │ Text  │  │  Control Messages  │  │  TCP  │  │
│  │ Chat  │  │  Authentication    │  │Handler│  │
│  └───────┘  │  User Management   │  └───────┘  │
│             │                    │             │
│  ┌───────┐  │  UDP (Port 5001)   │  ┌───────┐  │
│  │ Voice │  │◄──────────────────►│  │  UDP  │  │
│  │ Data  │  │  Audio Packets     │  │Handler│  │
│  └───────┘  │                    │  └───────┘  │
└─────────────┘                    └─────────────┘
```

### Message Types

**TCP Messages** (JSON format):
- `login` - Authentication with username and password hash
- `chat` - Text message broadcast
- `voice_start` / `voice_stop` - Voice activity notifications
- `change_username` - Username/color update
- `userlist_full` - Complete user list with colors
- `chat_history` - Historical messages on connect

**UDP Messages** (Binary):
- Raw audio data (PCM format, 16-bit signed integers)

---

## 📝 License

This project is licensed under the Grackle User License Agreement (GULA)

```
Grackle User License Agreement (GULA)

Copyright (c) 2026 Haven

By downloading, installing, or using this Software, you hereby affirm to uphold truth, justice, equity, and the democratic ideals of the American way. You further acknowledge and agree to defend and respect the sovereignty, self-determination, and human rights of all peoples, including but not limited to those of Ukraine, Palestine, Taiwan, Hong Kong, Tibet, Sudan, and any nation or community striving toward freedom and dignity. You strive to uphold the right of every person to live authentically, free from discrimination or harm, regardless of race, creed, sexual orientation, or gender identity and expression. Use of this Software constitutes your pledge to counter oppression, misinformation, and authoritarianism in all forms, and to act in good faith toward a more just, accepting, tolerant and sustainable world.

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

## 🙏 Acknowledgments

- **Design Inspiration**: NASA Mission Control, Google Material Design, Jet Set Radio Future
- **Audio Processing**: PyAudio library
- **Python Community**: For excellent documentation and support

---

## 📞 Support

### Found a bug?
Please [open an issue](https://github.com/yourusername/haven-chat/issues) with:
- Description of the problem
- Steps to reproduce
- Your OS and Python version
- Relevant error messages

### Have a question?
- Check the [Troubleshooting](#-troubleshooting) section
- Look through [existing issues](https://github.com/yourusername/haven-chat/issues)
- Open a new issue with the "question" label

### Want a feature?
- Open an issue with the "enhancement" label
- Describe the feature and why it would be useful
- Consider contributing it yourself!

---

## 🗺️ Roadmap

Future enhancements being considered:

- [ ] **File sharing** - Send files through the chat
- [ ] **Voice channels** - Multiple voice rooms
- [ ] **Server browser** - Discover public Haven servers
- [ ] **Encryption** - End-to-end encrypted messages
- [ ] **Mobile clients** - iOS and Android support
- [ ] **Voice effects** - Filters and audio processing
- [ ] **Screen sharing** - Share your screen with others
- [ ] **Better codec** - Opus audio codec for better quality/bandwidth
- [ ] **Database backend** - PostgreSQL/SQLite for scalability
- [ ] **Web interface** - Browser-based client option

---

<div align="center">

**Made with ⚡ by the Haven Chat Team**

[⭐ Star this repo](https://github.com/yourusername/haven-chat) • [🐛 Report Bug](https://github.com/yourusername/haven-chat/issues) • [💡 Request Feature](https://github.com/yourusername/haven-chat/issues)

</div>
