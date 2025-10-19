#!/bin/bash

# UÇK Scanner v4.0 - Installation Script
# Installs all required tools for high-quality vulnerability scanning

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║         UÇK SCANNER v4.0 - INSTALLATION                      ║
║         Installing All Required Tools...                      ║
╚═══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo -e "${RED}[!] Please don't run as root${NC}"
    exit 1
fi

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="mac"
else
    echo -e "${RED}[!] Unsupported OS${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Detected OS: $OS${NC}"

# Install Go if not present
if ! command -v go &> /dev/null; then
    echo -e "${YELLOW}[*] Installing Go...${NC}"
    if [ "$OS" == "linux" ]; then
        wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
        sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
        rm go1.21.5.linux-amd64.tar.gz
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
        source ~/.bashrc
    else
        brew install go
    fi
    echo -e "${GREEN}[✓] Go installed${NC}"
else
    echo -e "${GREEN}[✓] Go already installed${NC}"
fi

# Create tools directory
TOOLS_DIR="$HOME/tools"
mkdir -p "$TOOLS_DIR"
cd "$TOOLS_DIR"

echo -e "\n${CYAN}[+] Installing security tools...${NC}\n"

# 1. Subfinder - Subdomain enumeration
if ! command -v subfinder &> /dev/null; then
    echo -e "${YELLOW}[*] Installing subfinder...${NC}"
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    echo -e "${GREEN}[✓] subfinder installed${NC}"
else
    echo -e "${GREEN}[✓] subfinder already installed${NC}"
fi

# 2. Dalfox - XSS Scanner
if ! command -v dalfox &> /dev/null; then
    echo -e "${YELLOW}[*] Installing dalfox...${NC}"
    go install github.com/hahwul/dalfox/v2@latest
    echo -e "${GREEN}[✓] dalfox installed${NC}"
else
    echo -e "${GREEN}[✓] dalfox already installed${NC}"
fi

# 3. Nuclei - Vulnerability scanner
if ! command -v nuclei &> /dev/null; then
    echo -e "${YELLOW}[*] Installing nuclei...${NC}"
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    echo -e "${YELLOW}[*] Updating nuclei templates...${NC}"
    nuclei -update-templates
    echo -e "${GREEN}[✓] nuclei installed${NC}"
else
    echo -e "${GREEN}[✓] nuclei already installed${NC}"
fi

# 4. Naabu - Port Scanner
if ! command -v naabu &> /dev/null; then
    echo -e "${YELLOW}[*] Installing naabu...${NC}"
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    echo -e "${GREEN}[✓] naabu installed${NC}"
else
    echo -e "${GREEN}[✓] naabu already installed${NC}"
fi

# 5. S3Scanner - S3 Bucket Scanner
if ! command -v s3scanner &> /dev/null; then
    echo -e "${YELLOW}[*] Installing S3Scanner...${NC}"
    go install github.com/sa7mon/s3scanner@latest
    echo -e "${GREEN}[✓] S3Scanner installed${NC}"
else
    echo -e "${GREEN}[✓] S3Scanner already installed${NC}"
fi

# 6. Subjack - Subdomain takeover
if ! command -v subjack &> /dev/null; then
    echo -e "${YELLOW}[*] Installing subjack...${NC}"
    go install github.com/haccer/subjack@latest
    # Download fingerprints
    wget https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json -O ~/fingerprints.json
    echo -e "${GREEN}[✓] subjack installed${NC}"
else
    echo -e "${GREEN}[✓] subjack already installed${NC}"
fi

# 7. SQLMap - SQL Injection scanner
if ! command -v sqlmap &> /dev/null; then
    echo -e "${YELLOW}[*] Installing sqlmap...${NC}"
    if [ "$OS" == "linux" ]; then
        sudo apt-get update
        sudo apt-get install -y sqlmap
    else
        brew install sqlmap
    fi
    echo -e "${GREEN}[✓] sqlmap installed${NC}"
else
    echo -e "${GREEN}[✓] sqlmap already installed${NC}"
fi

# 8. ffuf - Fuzzer (optional but recommended)
if ! command -v ffuf &> /dev/null; then
    echo -e "${YELLOW}[*] Installing ffuf...${NC}"
    go install github.com/ffuf/ffuf/v2@latest
    echo -e "${GREEN}[✓] ffuf installed${NC}"
else
    echo -e "${GREEN}[✓] ffuf already installed${NC}"
fi

# 9. httpx - HTTP probe
if ! command -v httpx &> /dev/null; then
    echo -e "${YELLOW}[*] Installing httpx...${NC}"
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    echo -e "${GREEN}[✓] httpx installed${NC}"
else
    echo -e "${GREEN}[✓] httpx already installed${NC}"
fi

# 10. gau - Get All URLs
if ! command -v gau &> /dev/null; then
    echo -e "${YELLOW}[*] Installing gau...${NC}"
    go install github.com/lc/gau/v2/cmd/gau@latest
    echo -e "${GREEN}[✓] gau installed${NC}"
else
    echo -e "${GREEN}[✓] gau already installed${NC}"
fi

# 11. ParamSpider - Parameter discovery
if ! command -v paramspider &> /dev/null; then
    echo -e "${YELLOW}[*] Installing ParamSpider...${NC}"
    cd "$TOOLS_DIR"
    if [ ! -d "ParamSpider" ]; then
        git clone https://github.com/devanshbatham/ParamSpider
        cd ParamSpider
        # Use pipx instead of pip3 for Kali Linux
        if command -v pipx &> /dev/null; then
            pipx install -e .
        else
            # Fallback to pip with --break-system-packages for Kali
            pip3 install -r requirements.txt --break-system-packages 2>/dev/null || \
            pip3 install -r requirements.txt --user
        fi
        sudo ln -sf $(pwd)/paramspider.py /usr/local/bin/paramspider 2>/dev/null || true
        chmod +x paramspider.py
        cd ..
    fi
    echo -e "${GREEN}[✓] ParamSpider installed${NC}"
else
    echo -e "${GREEN}[✓] ParamSpider already installed${NC}"
fi

# 12. Arjun - HTTP parameter discovery
if ! command -v arjun &> /dev/null; then
    echo -e "${YELLOW}[*] Installing Arjun...${NC}"
    # Use pipx for Kali Linux
    if command -v pipx &> /dev/null; then
        pipx install arjun
    else
        # Fallback to pip
        pip3 install arjun --break-system-packages 2>/dev/null || \
        pip3 install arjun --user
    fi
    echo -e "${GREEN}[✓] Arjun installed${NC}"
else
    echo -e "${GREEN}[✓] Arjun already installed${NC}"
fi

# 13. Katana - Web crawler
if ! command -v katana &> /dev/null; then
    echo -e "${YELLOW}[*] Installing Katana...${NC}"
    go install github.com/projectdiscovery/katana/cmd/katana@latest
    echo -e "${GREEN}[✓] Katana installed${NC}"
else
    echo -e "${GREEN}[✓] Katana already installed${NC}"
fi

echo -e "\n${CYAN}[+] Building UÇK Scanner...${NC}\n"

# Compile the Go scanner
cd ~/

# Check if uck_scanner.go exists
if [ ! -f "uck_scanner.go" ]; then
    echo -e "${RED}[!] uck_scanner.go not found in home directory${NC}"
    echo -e "${YELLOW}[*] Please ensure uck_scanner.go is in ~/uck_scanner.go${NC}"
    exit 1
fi

# Build without go.mod (standalone file)
go build -o uck_scanner uck_scanner.go

if [ $? -eq 0 ]; then
    chmod +x uck_scanner
    sudo mv uck_scanner /usr/local/bin/
    echo -e "${GREEN}[✓] UÇK Scanner compiled and installed${NC}"
else
    echo -e "${RED}[!] Failed to compile scanner${NC}"
    echo -e "${YELLOW}[*] Trying alternative build method...${NC}"
    
    # Alternative: use GO111MODULE=off
    GO111MODULE=off go build -o uck_scanner uck_scanner.go
    
    if [ $? -eq 0 ]; then
        chmod +x uck_scanner
        sudo mv uck_scanner /usr/local/bin/
        echo -e "${GREEN}[✓] UÇK Scanner compiled and installed (alternative method)${NC}"
    else
        echo -e "${RED}[!] Compilation failed. Please check the error messages above.${NC}"
        exit 1
    fi
fi

echo -e "\n${GREEN}${BOLD}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║              INSTALLATION COMPLETE!                           ║
╚═══════════════════════════════════════════════════════════════╝

Usage:
  uck_scanner -d example.com -m s,sqli,xss,ssrf,aes,nuclei,s3

Modules:
  s        - Subdomain enumeration + takeover check
  sqli     - SQL Injection testing (SQLMap)
  xss      - XSS testing (Dalfox)
  ssrf     - SSRF testing
  aes      - JavaScript crypto analysis
  nuclei   - Comprehensive vulnerability scan
  s3       - S3 bucket scanning

Examples:
  # Full scan
  uck_scanner -d example.com -m s,sqli,xss,ssrf,aes,nuclei,s3 -t 100

  # Quick scan
  uck_scanner -d example.com -m s,nuclei

  # Crypto + XSS only
  uck_scanner -d example.com -m s,aes,xss

Happy hunting! 🎯
EOF
echo -e "${NC}"
