
# 🐉 JARVIS - Just A Rather Very Intelligent System  
**Kali Dragon Edition 🔥**

A Kali Linux-optimized AI personal assistant written in Python, designed for pentesters, security researchers, and lazy geniuses who want asynchronous tool launching, security automation, and system management without the clicking fatigue.

> "Because clicking is for peasants, and typing full commands is for people with time to waste."

---

## ⚡ Why This Project?

Every pentester knows the pain:

- Opening **5 terminals** manually for different tools  
- Typing `nmap -sV -sC -O 192.168.1.1` **for the 1000th time**  
- Forgetting where those damn **wordlists** are  
- Context switching between tools, breaking your **flow**  
- Documenting findings when you could be **hacking**  

**JARVIS** was born from pure laziness and evolved into a full-fledged pentesting companion.  

> Started as a 300-line C++ script to open YouTube faster. Now it's **1.8k lines of Python** that can scan networks, crack hashes, and still open YouTube in 2 seconds. (The 2 seconds were just the gateway drug.)

---

## 🧭 Workflow

1. Run **JARVIS** (optionally as root for full power)  
2. Speak naturally (no need for exact syntax)  
3. Watch the magic happen (**async launching = no freezing**)  
4. Profit (literally, more time for coffee ☕)  

Example:

You: "scan network 192.168.1.0/24"
JARVIS: 🔍 Starting Nmap scan... (runs in background)
You: "open burpsuite"
JARVIS: 🕷️ Launching Burp Suite... (also in background)
You: *sips coffee while tools run*
# 🧠 Core Features
⚡ Asynchronous Everything
Non-blocking tool launches

Run multiple tools simultaneously

Terminal spawns for interactive tools

UI never freezes

# 🔥 Kali Linux Deep Integration
Native support for 50+ pentesting tools

Automatic tool path detection

Wordlist location mapping

Root privilege awareness

Network interface detection

# 💾 Persistent Memory
Remembers your favorite tools

Stores target history

Custom command aliases

Project path tracking

Offline, private, no cloud BS

# 🎯 Security-Focused Commands
Network scanning (nmap, masscan)

Web app testing (nikto, gobuster, sqlmap)

Exploitation (metasploit, searchsploit)

Password cracking (hashcat, john)

Wireless attacks (aircrack-ng, wifite)

# 🐉 Dragon Vibes
Hacker ASCII art

Motivational phrases

"HACK THE PLANET" energy

Makes you feel like a god

# 💬 Example Commands

# 🎯 Security Tools
scan network 192.168.1.0/24
nmap -sV 10.10.10.10
scan website https://example.com
nikto -h https://example.com
dirbust https://example.com
wpscan --url https://example.com
sql injection http://testphp.vulnweb.com/artists.php?artist=1
crack hash 5f4dcc3b5aa765d61d8327deb882cf99
search exploit apache 2.4.49
start metasploit
open burpsuite
open wireshark
hydra ssh://192.168.1.100
aircrack

# 💻 System Commands
system info
network info
show processes
show resources
check root
list files
show wordlists
open folder /usr/share/wordlists

# 🌐 Web & Apps
open youtube
open github
open hackthebox
open tryhackme
search web for exploit-db
open firefox
open terminal
open vim
🎮 Fun & Misc
joke
hack the planet
set target 10.10.10.10
show target
generate report engagement_1
help
exit

# 🛠️ Tech Stack
Python 3.8+ – Core language

threading – Async execution

subprocess – Tool launching

regex – Command parsing

pickle – Memory persistence

psutil – System monitoring

netifaces – Network interfaces

✅ No bloated frameworks
✅ No cloud dependencies
✅ No telemetry
✅ All local, all private

📦 Installation
# Clone the repository
git clone https://github.com/akn-cybersec/jarvis.git
cd jarvis

# Install dependencies (optional but recommended)
pip install psutil netifaces

# Make it executable
chmod +x jarvis.py

# Run as user (some tools need root)
python3 jarvis.py

# Or run as root for full power
sudo python3 jarvis.py
# 💡 Best experience on Kali Linux with all pentesting tools installed

# 🚀 Pro Tips
Create an alias for instant access

echo "alias jarvis='sudo python3 /path/to/jarvis.py'" >> ~/.zshrc
source ~/.zshrc
# Now just type 'jarvis' anywhere
Set your preferences

# Edit the Config class to match your setup
USER_NAME = "your_username"
HOSTNAME = "your_hostname"
Create custom aliases

JARVIS> set alias code = vscode
JARVIS> set alias web = firefox
JARVIS> open code  # Now opens vscode
Use target tracking

JARVIS> set target 10.10.10.10
JARVIS> scan current  # Scans your target
JARVIS> show target   # Remembers for you
🔧 Requirements
OS: Kali Linux (works on any Debian-based)

Python: 3.8+

Optional: psutil, netifaces (for system monitoring)

Root: Recommended for full tool access

#🌱 Future Enhancements
AI-powered vulnerability suggestions

Automated report generation from scan results

Session recording for compliance

Plugin system for custom tools

Voice control integration

Docker/Kubernetes support

Collaborative pentesting features

JSON backup/restore system

Cloud sync (optional, encrypted)

Machine learning for attack patterns

# 🤔 Philosophy
"The best tools aren't built by companies with millions in funding. They're built by annoyed people who said 'Fine. I'll do it myself.'"

JARVIS proves that:

Laziness drives innovation

One-time pain > repetitive suffering

AI can amplify your ideas

You don't need a team to build useful things

The best solutions come from personal annoyance

# 📊 Stats
Lines of Code: 1,800+ (started at 300)
Tools Supported: 50+
Time Saved Per Day: Hours
Coffee Consumption: Infinite
Clicks Saved: Countless
Satisfaction Level: Maximum
# 🐉 The Origin Story
"I was just a lazy kid who hated clicking. I built a 300-line C++ script to open YouTube faster. Then I discovered Python. Then I discovered Kali. Then I discovered I could control everything. Now I have a dragon that hacks for me while I nap."

# ⚠️ Disclaimer
This tool is for authorized security testing only. The author is not responsible for misuse.
With great power comes great responsibility (and root access).

# ✍️ Author
Muhammad Abdullah Khan (Kaizen)

Professional lazy person

Professional idiot

Professional hacker

Professional "fine, I'll do it myself"-er

From 300 lines of C++ to 1.8k lines of Python dragon magic — all because clicking was too much effort.

# 📜 License
MIT – Do whatever you want, just don't blame me if you pwn something you shouldn't.

