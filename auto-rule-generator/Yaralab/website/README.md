# Malware Detection Website

I have built a **Next.js** web application with a **Flask-based Python backend** for scanning files and URLs using YARA rules. The project is structured to be deployed on **Vercel**.

## Features Implemented
- **Modern UI**: Dark-themed, glassmorphism design with drag-and-drop file upload and URL entry.
- **Backend Scanning**: A serverless-ready Python API (`/api/scan`) that processes uploads and runs YARA rules.
- **YARA Integration**: Basic YARA rules included for demonstration (detecting malicious strings, PE headers, etc.).
- **Vercel Config**: `vercel.json` and `requirements.txt` configured for seamless deployment.

## Security Features
- **SSRF Protection**: The scanner includes a security layer (`api/security.py`) that prevents users from scanning internal network resources (localhost, 192.168.x.x, etc.) or cloud metadata services. This protects the host infrastructure from Server-Side Request Forgery attacks.
- **Input Sanitization**: All inputs are strictly typed and validated before processing.
- **Sandboxed Execution**: YARA rules run in a stateless serverless environment, ensuring no persistence of malicious files.

## Project Structure
- `website/src/`: Frontend code (Next.js App Router).
- `website/api/`: Backend code (Flask app).
- `website/api/rules/`: YARA rule files.
- `website/tests/`: Unit tests for the backend.

## How to Run Locally

### Prerequisites
- Node.js & npm
- Python 3.9+

### Steps
1. **Frontend Setup**:
   ```bash
   cd website
   npm install
   ```

2. **Backend Setup**:
   Create a virtual environment and verify dependencies (if not done).
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Running Development Server**:
   **Option A: Using Vercel CLI (Recommended)**
   ```bash
   vercel dev
   ```
   
   **Option B: Manual Setup (If Vercel CLI is missing)**
   You must run **TWO** separate terminals:
   
   **Terminal 1 (Backend)**: runs on port 5328
   ```bash
   # From project root
   python3 website/api/index.py
   ```
   
   **Terminal 2 (Frontend)**: runs on port 3000
   ```bash
   # From website/ directory
   cd website
   npm run dev
   ```
   *Note: `next.config.ts` is configured to proxy `/api/scan` to localhost:5328 in development.*

## Deployment to Vercel
1. Push the code to a Git repository.
2. Import the project into Vercel.
3. Vercel will automatically detect Next.js and the Python API.
4. Ensure the `ENABLE_vc_build_deps` environment variable is not needed (modern Vercel usually handles it), but if YARA compilation fails, verify build logs.

## Verification
- Run `npm run build` to verify the frontend builds successfully (Completed).

## Troubleshooting
- **YARA Installation Fails**: If you see `command '/usr/bin/clang' failed with exit code 69`, you need to agree to Xcode licenses:
  ```bash
  sudo xcodebuild -license
  ```
- **Port Conflicts**: If port 3000 or 5328 is in use, the scripts might fail. Kill the processes or change ports in `api/index.py` and `next.config.ts`.
- **Python 3.13**: If `yara-python` fails to build even after fixing Xcode, try using Python 3.11 or 3.12, as 3.13 is very new and might lack pre-built wheels.
