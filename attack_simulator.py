import requests
import json

BASE_URL = "http://localhost:8000"

def simulate_sql_injection():
    print("Simulē SQL injekciju...")
    login_url = f"{BASE_URL}/token"
    data = {
        "username": "admin' OR '1'='1",
        "password": "nejauša_parole"
    }
    response = requests.post(login_url, data=data)
    print("Atbilde:", response.status_code, response.text)

def simulate_xss():
    print("Simulē XSS ievainojamību...")
    register_url = f"{BASE_URL}/register"
    payload = {
        "username": "<script>alert('XSS')</script>",
        "password": "securepassword",
        "role": "user"
    }
    headers = {"Content-Type": "application/json"}
    response = requests.post(register_url, data=json.dumps(payload), headers=headers)
    print("Atbilde:", response.status_code, response.text)

def simulate_jwt_replay():
    print("Simulē JWT replay uzbrukumu...")
    login_url = f"{BASE_URL}/token"
    data = {
        "username": "testuser",
        "password": "securepassword"
    }
    response = requests.post(login_url, data=data)
    if response.status_code != 200:
        print("Neizdevās iegūt tokenu.")
        return
    tokens = response.json()
    access_token = tokens["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}
    protected_url = f"{BASE_URL}/protected"
    response = requests.get(protected_url, headers=headers)
    print("Atbilde:", response.status_code, response.text)

def simulate_session_hijacking():
    print("Simulē sesiju pārņemšanu...")
    login_url = f"{BASE_URL}/token"
    data = {
        "username": "testuser",
        "password": "securepassword"
    }
    session = requests.Session()
    response = session.post(login_url, data=data)
    print("Pirmais pieraksts:", response.status_code, response.text)
    protected_url = f"{BASE_URL}/protected"
    response2 = session.get(protected_url)
    print("Pēc sesijas atkārtotas izmantošanas:", response2.status_code, response2.text)

def simulate_brute_force():
    print("Simulē bruteforce uzbrukumu...")
    login_url = f"{BASE_URL}/token"
    for i in range(7):
        data = {
            "username": "nonexistent",
            "password": "wrong"
        }
        response = requests.post(login_url, data=data)
        print(f"Mēģinājums {i+1}: Status {response.status_code} - {response.text}")

if __name__ == '__main__':
    simulate_sql_injection()
    simulate_xss()
    simulate_jwt_replay()
    simulate_session_hijacking()
    simulate_brute_force()

