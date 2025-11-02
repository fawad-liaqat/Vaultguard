# 🏦 VaultGuard — Secure Digital Wallet for Modern FinTech

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Flask](https://img.shields.io/badge/Framework‑Flask-lightgrey?logo=flask)
![Security](https://img.shields.io/badge/Focus‑Cybersecurity-green?logo=shield)
![Status](https://img.shields.io/badge/Status‑Stable-success)
![License](https://img.shields.io/badge/License‑MIT-lightblue)

---

## 🔒 Overview

**VaultGuard** is a secure and lightweight FinTech web application that acts as a a digital wallet + user account manager.  
It is built with strong attention to security, implementing hashing, encryption, session management, input validation, and controlled data access.  
VaultGuard is designed to be both usable and safe — offering a clean interface while enforcing robust security measures.

---

## 🌟 Key Highlights

- **End‑to‑End Security architecture** with encryption at rest, hashed passwords, secure sessions, and input sanitization.  
- **Modular Flask design** with clear separation of concerns (backend logic / templates / utilities).  
- **Realistic fintech features**: wallet management, profile updates, audit logging, secure file upload.  
- **Manual testing friendly**: built to explore vulnerabilities and validate security controls.  
- **Educational & demo potential**: serves as a secure reference project or portfolio piece.

---

## 🧩 Core Features

| **Feature** | **Description** |
|------------|------------------|
| 🔐 **Secure Authentication** | Users register and log in using hashed passwords. |
| 🧱 **Input Validation** | All user inputs are sanitized to prevent injections or XSS. |
| 🔏 **Data Encryption** | Sensitive fields stored encrypted in the database. |
| 🧾 **Activity Logs** | Logs track user actions, updates, and other events. |
| 🧠 **Error Handling** | Generic error messages to avoid exposing internal details. |
| 🧮 **Profile Management** | Users can update account details with validation checks. |
| 🚪 **Session Management** | Secure sessions with logout and expiration. |
| 🗂 **File Upload Validation** | Restricts dangerous file types and enforces safe formats. |

---

## 🛡️ Security Architecture

The application is built with security by design:

- **Authentication & authorization** are handled via session tokens and controlled access.
- **Password security** is ensured via strong one‑way hashing.
- **Input validation** occurs at both client and server side to mitigate common web attacks.
- **Confidentiality** is preserved through encryption of sensitive data at storage.
- **Logging & audit** mechanisms ensure traceability of user actions.
- **Error control** ensures that no internal implementation details are exposed to end users.

---

## 🖥️ Tech Stack

| Layer | Technology |
|------|-------------|
| **Backend** | Python + Flask |
| **Frontend** | HTML, CSS, Bootstrap |
| **Database** | SQLite |
| **Security Libraries** | bcrypt, cryptography, hashing libraries |
| **Logging** | Python `logging` |
| **Environment** | Virtual environment (`venv`) |

---

## 🧱 Project Structure

```
vaultguard/
│
├── app.py               # Main application entry point
├── config.py            # App and security configuration
├── requirements.txt     # Dependencies
├── static/              # CSS, JS, and static assets
├── templates/           # HTML templates
├── utils/               # Helper & encryption modules
├── database/            # SQLite storage files
├── logs/                # Activity / error logs
└── README.md            # Documentation
```

---

## 🚀 Installation & Setup

### 1️⃣ Clone the repository  
```bash
git clone https://github.com/fawad-liaqat/vaultguard.git
cd vaultguard
```

### 2️⃣ Create and activate a virtual environment  
```bash
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On macOS / Linux:
source .venv/bin/activate
```

### 3️⃣ Install dependencies  
```bash
pip install -r requirements.txt
```

### 4️⃣ Run the application  
```bash
python app.py
```

### 5️⃣ Access via browser  
```
http://127.0.0.1:5000/
```

---

## 🧠 How It Works

1. A user registers, and their password is hashed before being stored securely.  
2. On login, sessions are created with secure cookies and managed until logout or expiration.  
3. All inputs from forms are sanitized and validated to prevent attacks.  
4. Sensitive data (e.g. wallet balances or personal data) is encrypted before writing to the database.  
5. All user actions (login, updates, uploads) are logged for audit.  
6. Errors are handled gracefully: generic messages delivered without revealing backend structure.

---

## 📊 Example Use Cases

- Prototyping a small FinTech wallet with secure account features.  
- Demonstrating secure coding practices in a full‑stack web app.  
- Presenting in portfolio to showcase knowledge in building secure web systems.

---

## 💡 Learning Outcomes

- Built end‑to‑end authentication and authorization in a web environment.  
- Applied encryption and hashing for data confidentiality and integrity.  
- Designed safe user interfaces with proper validation.  
- Implemented logging and auditing for transparency and accountability.  
- Developed the mindset of building applications with security first.

---

## 🧑‍💻 Author

**Fawad Liaqat**  
📧 [GitHub Profile](https://github.com/fawad-liaqat)  
📧 [LinkedIn](https://www.linkedin.com/in/fawad-liaqat)

---

## 📜 License

This project is released under the **MIT License**.  
You are free to use, modify, and distribute it with proper attribution.

---

## 💬 Contributions Are Welcome!

Feel free to fork, explore, report issues, or submit pull requests — especially if you want to add features such as role‑based access, two‑factor authentication, or external API integrations.

---
