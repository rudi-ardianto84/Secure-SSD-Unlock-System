# Secure SSD Unlock System (Arduino Edition)

The Secure SSD Unlock System is an advanced security solution that combines hardware and software to enable fingerprint or NFC authentication via Arduino before unlocking and mounting an encrypted container on an SSD NVMe. The system is designed to run entirely in a portable manner, without requiring a Python installation on the host machine — the Python interpreter and all required modules are installed directly on the root of the SSD to be encrypted.

The architecture is modular: Arduino acts as the authentication controller. Once a fingerprint or NFC card is verified, the Arduino sends a signal to the Python scripts to decrypt and mount the secure VeraCrypt volume. The encrypted container is stored in the `bin` folder on the SSD, ensuring that all data remains inside the encrypted drive and can only be accessed through authorized authentication.

To set up the system, install a portable Python version directly onto the root of the SSD (for example, `Z:\PythonPortable\`). Then, open the portable Python terminal and run the following command to install all required dependencies:


Next, create a VeraCrypt container with the desired size, place the resulting `.hc` file in the `bin` folder on the SSD, and run `start.exe` to initiate the authentication and automatic mounting process.

**Key Features:**
- Fingerprint and NFC authentication via Arduino.
- Secure encryption and decryption of SSD containers using VeraCrypt.
- Fully portable Python environment for system independence from the host machine.
- Centralized `bin` folder to store the container, ensuring data integrity and security.

This project is ideal for users who want to enhance the security of SSD NVMe drives, such as in public laptops, shared workstations, or systems that require high-level data protection. Contributions are welcome for adding features such as access logging, multi-user support, or additional authentication methods.

**License:** [Insert your project license, e.g., MIT]  
**Author:** Rudi Ardianto — [GitHub rudi-ardianto84](https://github.com/rudi-ardianto84)
