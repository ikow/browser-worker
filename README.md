# Browser Permission Tester with Enhanced Download Methods

## Features

### Enhanced Download Compatibility
The shell script generator now uses **5 advanced fallback methods** optimized for remote browser environments based on research of successful download sites:

#### Method 1: Window.open + LocalStorage (Remote Browser Optimized)
- Uses `window.open()` with temporary storage-based content passing
- Stores content in sessionStorage/localStorage temporarily
- Opens download page in new window that retrieves and downloads content
- **Most reliable for remote browsers and VMs**

#### Method 2: Form POST Download (Server-side)
- Creates hidden HTML form with POST to `/api/download-script`
- Handles both JSON and form data on server
- Uses `Content-Disposition: attachment` header
- **Works when JavaScript blob methods are blocked**

#### Method 3: Blob Download (Standard)
- Uses `Blob` API with `URL.createObjectURL()`
- `Content-Type: application/octet-stream` for better compatibility
- Works in most modern browsers locally

#### Method 4: Base64 Data URI Download
- Uses `data:application/octet-stream;base64,` URI scheme
- Base64 encoding prevents character encoding issues
- Fallback for browsers that block blob downloads

#### Method 5: Clipboard + Manual Copy (Final Fallback)
- Automatic clipboard copy if all downloads fail
- Modal dialog with textarea for manual copy
- Works even in highly restricted environments
- User-friendly instructions for manual save

## Usage

1. **Start the server**: `npm run dev`
2. **Visit**: `http://localhost:8787` or your deployed URL
3. **Navigate to**: "📜 Shell Script Generator" section
4. **Choose a template** or write custom script
5. **Click "Generate & Download Script"**

The system will automatically try all methods until one succeeds:
- ✅ **Success**: File downloads normally
- 🔄 **Fallback**: Tries next method if current fails
- 📋 **Final**: Copies to clipboard or shows manual copy dialog

## Template Scripts

### Permission Test Template
- Tests file system, network, and process permissions
- Safe for defensive security testing
- Outputs `[OK]`/`[FAIL]` status for each test

### Reverse Shell Template  
- For defensive testing only
- Shows available reverse shell methods
- Includes safety warnings and no actual connections

### System Info Template
- Comprehensive system information gathering
- Network, process, and file system details
- Security tools availability check

## Security Features

- All script generation is logged server-side
- Templates include defensive security warnings
- No actual malicious code execution
- Designed for authorized testing only

## Browser Compatibility

- ✅ Chrome/Chromium (all methods)
- ✅ Firefox (all methods) 
- ✅ Safari (methods 1-4)
- ✅ Edge (all methods)
- ✅ Remote/VM browsers (methods 2-4)
- ✅ Corporate networks (methods 3-4)