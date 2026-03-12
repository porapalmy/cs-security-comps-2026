# cs-security-comps-2026

This repository contains our 2026 CS Security Comps project.

Authors: Rachel Azan, Jeremy Gautama, Palmy Klangsathorn, Daniel Lumbu

## Do SSH into the AWS EC2 Server

Set the correct permissions for the private key file using the chmod command (SSH requires the key to be unreadable by others):
bash
`chmod 400 CompsServerKey.pem`
Connect to your instance using the ssh command:
bash
`ssh -i "CompsServerKey.pem" ubuntu@18.188.219.228`

change the username@ipaddress to your username and ip address!

## How to Run Locally

### Prerequisites
- [Node.js](https://nodejs.org/) & npm
- [Python 3.9+](https://www.python.org/)

### Steps

1. **Frontend Setup**
   Install the necessary Node dependencies for the web app:
   ```bash
   cd website
   npm install
   ```

2. **Backend Setup**
   Create a Python virtual environment and install the required packages.
   _Note: If you are using a Mac/Linux machine, follow these commands:_
   ```bash
   cd website
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
   *(On Windows, use `venv\Scripts\activate` instead of `source venv/bin/activate`)*

3. **Running the Application**
   You will need to run the backend and frontend simultaneously in two separate terminal windows.

   **Terminal 1 (Backend API):**
   ```bash
   cd website
   source venv/bin/activate
   python3 api/index.py
   ```
   *(The backend API will run on port 5328)*

   **Terminal 2 (Frontend Web App):**
   ```bash
   cd website
   npm run dev
   ```
   *(The Next.js frontend will run on port 3000)*

4. **Access the App**
   Open your browser and navigate to [http://localhost:3000](http://localhost:3000). The frontend is configured to automatically route API requests to the backend.
