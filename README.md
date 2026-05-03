# 🔐 Secure SSD Unlock System (Hardware-Based Authentication)

## 📌 Overview

This project is a **secure SSD unlock system** that uses external hardware authentication (Arduino/ESP32) combined with encryption to protect storage access.

Unlike traditional software-only disk protection, this system ensures that the SSD **cannot be accessed without valid hardware authentication**, adding an extra physical security layer.

---

## 🚨 Problem Statement

Most disk encryption systems rely only on:

* Password-based authentication
* Software-level protection

This creates risks such as:

* Brute-force attacks
* Unauthorized access if credentials are leaked
* Lack of hardware-level security

---

## 💡 Solution

This project introduces a **multi-layer security system**:

* 🔐 Encryption using AES (GCM / CBC)
* 🧠 External authentication via microcontroller
* 🧬 Optional biometric / NFC integration
* 🔄 Secure communication between device and host
* 🧩 Split data validation (hardware + database)

➡️ Result: SSD access is only granted when all authentication layers are valid.

---

## 🏗️ System Architecture

[![System Architecture](docs/architecture.png)](https://github.com/rudi-ardianto84/Secure-SSD-Unlock-System/blob/main/version-arduino/program_mikrokontroler/schematic/schematic.jpg)

---

## 🔄 Flowchart

![Flowchart](docs/flowchart.png)

---

## ⚙️ Tech Stack

* **Hardware**:

  * Arduino / ESP32
  * Fingerprint sensor (optional)
  * NFC module (optional)

* **Software**:

  * Python (host system)
  * Serial communication
  * Encryption (AES-GCM / AES-CBC)

* **Security Concepts**:

  * Authenticated encryption (AES-GCM)
  * Nonce & timestamp validation
  * Anti replay attack mechanism

---

## 🔑 Key Features

* Hardware-based SSD unlocking
* Secure communication using AES-GCM
* Protection against replay attacks
* Multi-factor authentication (hardware + data)
* Modular system (can integrate biometric / NFC)

---

## 🧪 How It Works

1. User initiates unlock request
2. System sends encrypted challenge to hardware
3. Hardware verifies authentication (fingerprint/NFC/etc.)
4. Encrypted response is validated
5. SSD is unlocked only if all checks pass

---

## 📷 Demo / Implementation

(Add your real hardware photos or demo video here)

---

## 📖 Documentation

Detailed explanation (Bahasa Indonesia):
👉 `docs/artikel.md`

---

## 🚀 Future Improvements

* Integration with TPM / secure element
* Full disk automation
* Enhanced key management (Argon2 / PBKDF2)

---

## 👨‍💻 Author

**Rudi Ardianto**
Electronics Engineering Student – Embedded Systems & Security

---

## ⭐ Notes

This project is designed as a **practical implementation of hardware-based storage security**, combining embedded systems and cryptography.
