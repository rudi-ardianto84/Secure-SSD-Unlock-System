import os
import subprocess
import sys
import serial
import time
import serial.tools.list_ports
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import random
import string
import json
import rarfile
import binascii
import struct
from Crypto.Cipher import AES
import secrets
import pyperclip

# Definisikan kunci AES-128 (16 byte)
AES_KEY = b'\xA7\x4B\x9D\xF1\xC2\x3E\x65\x88\x14\xAB\x3D\xE9\x71\xF5\x0C\x6B'


# 🕒 Waktu referensi RTC pertama kali (Mon Jan 3 06:18:55 2000)
RTC_REFERENCE_FILE = "rtc_reference.txt"
UPDATE_INTERVAL = 432000  # 5 hari dalam detik (5 * 24 * 60 * 60)

try:
    with open(RTC_REFERENCE_FILE, "r") as f:
        ARDUINO_REFERENCE_TIME = int(f.read().strip())
        if ARDUINO_REFERENCE_TIME > int(time.time()):  # Hindari nilai masa depan
            raise ValueError("Waktu referensi RTC tidak valid.")
except (FileNotFoundError, ValueError):
    ARDUINO_REFERENCE_TIME = 947252577  # Default jika file tidak ada atau error

# Hitung selisih waktu awal (pastikan tidak negatif)
SELISIH_WAKTU = max(int(time.time()) - ARDUINO_REFERENCE_TIME, 0)
print(f"🕒 Selisih waktu awal: {SELISIH_WAKTU} detik")

# Lokasi instalasi VeraCrypt
veracrypt_path = r"C:\Program Files\VeraCrypt\VeraCrypt.exe"  # Sesuaikan dengan lokasi VeraCrypt di komputer 
volume_path = r"Z:\bin\rahasia.hc"  # Sesuaikan dengan path volume yang ingin di buka
drive_letter = "r"  # Huruf drive untuk mount volume

# Lokasi file dissable.py yang akan dijalankan setelah SSD dibuka
dissable_file_path = r"D:\program\autentikasi\dissable.py"

# Tentukan lokasi unrar.exe dari instalasi WinRAR
rarfile.UNRAR_TOOL = r"C:\Program Files\WinRAR\UnRAR.exe"

# Lokasi file JSON
DATA_BASE_FILE = "data_base.json"
ARCHIVED_FILE = "data_base.rar"
RAR_PASSWORD = "qwerty123456789"
SEND_COUNT_LIMIT = 60
send_count = 0  # Hitungan pengiriman password

# Kunci enkripsi untuk file JSON
ENCRYPTION_KEY = b'R&dY3!xWm7#bL2Pf1234567890123456'  # 32 byte key

# Fungsi untuk mengenkripsi data base dengan AES-GCM standard NIST
def encrypt_data(data):
    iv = os.urandom(12)  # IV 12 byte  sesuai standar NIST
    cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
    tag = encryptor.tag  # Tag autentikasi (16 byte)

    return base64.b64encode(iv + ciphertext + tag).decode()

# Fungsi untuk mendekripsi data base dengan AES-GCM Standar NIST
def decrypt_data(encrypted_data):
    try:
        encrypted_data_bytes = base64.b64decode(encrypted_data)
        
        # Debugging: Cek panjang data yang diterima
        print(f"Total Encrypted Data Length: {len(encrypted_data_bytes)}")

        if len(encrypted_data_bytes) < 28:  # IV (12) + Tag (16) = minimal 28 byte
            raise ValueError(f"Data terenkripsi terlalu pendek: {len(encrypted_data_bytes)} byte.")

        iv = encrypted_data_bytes[:12]  # IV 12 byte pertama 
        tag = encrypted_data_bytes[-16:]  # Tag autentikasi 16 byte terakhir
        ciphertext = encrypted_data_bytes[12:-16]  # Sisanya adalah ciphertext

        print(f"IV Length: {len(iv)}, Tag Length: {len(tag)}, Ciphertext Length: {len(ciphertext)}")

        cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()

        return decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as e:
        print(f"Error saat dekripsi: {e}")
        raise

# Fungsi untuk memuat database dari file JSON terenkripsi
def load_database():
    # Jika file JSON ada, baca langsung
    if os.path.exists(DATA_BASE_FILE):
        if os.path.getsize(DATA_BASE_FILE) == 0:
            print("⚠️ File JSON ada tetapi kosong! Menggunakan database kosong.")
            return {}

        with open(DATA_BASE_FILE, "r") as f:
            encrypted_data = f.read().strip()
            if not encrypted_data:
                print("⚠️ File JSON kosong!")
                return {}

            return json.loads(decrypt_data(encrypted_data))

    # Jika file JSON tidak ada, coba baca dari arsip RAR
    elif os.path.exists(ARCHIVED_FILE):
        try:
            with rarfile.RarFile(ARCHIVED_FILE, 'r') as rf:
                rf.setpassword(RAR_PASSWORD)  # Set password sebelum membuka arsip
                
                # Cek apakah file ada dalam arsip
                file_list = rf.namelist()
                print(f"📂 Isi arsip: {file_list}")  # Debug: Lihat isi arsip

                if DATA_BASE_FILE not in file_list:
                    print(f"❌ File {DATA_BASE_FILE} tidak ditemukan dalam arsip RAR!")
                    return {}

                with rf.open(DATA_BASE_FILE) as f:
                    encrypted_data = f.read().decode().strip()
                    if not encrypted_data:
                        print("⚠️ Data dalam arsip kosong! Menggunakan database kosong.")
                        return {}

                    return json.loads(decrypt_data(encrypted_data))

        except Exception as e:
            print(f"❌ Gagal membaca arsip RAR: {e}")
            return {}

    # Jika tidak ada file JSON maupun RAR, buat database kosong
    print("⚠️ Tidak ditemukan file database, membuat database kosong.")
    return {}

# Fungsi untuk menyimpan database ke file JSON terenkripsi
def save_database(database):
    global send_count
    encrypted_data = encrypt_data(json.dumps(database))
    with open(DATA_BASE_FILE, "w") as f:
        f.write(encrypted_data)
    
    send_count += 1
    print(f"🔄 Data tersimpan. Hitungan pengiriman: {send_count}")

    if send_count >= SEND_COUNT_LIMIT:
        print("📁 Mencapai batas pengiriman. Mengarsipkan database...")
        archive_database()
        send_count = 0  # Reset hitungan setelah arsip

# Fungsi untuk mengarsipkan file database JSON ke dalam RAR
def archive_database():
    """Mengarsipkan data_base.json menjadi data_base.rar menggunakan WinRAR."""
    if not os.path.exists(DATA_BASE_FILE):
        print("⚠️ File database tidak ditemukan, tidak ada yang diarsipkan.")
        return

    try:
        # Jalankan WinRAR untuk membuat arsip dengan password
        subprocess.run([
            r"C:\Program Files\WinRAR\WinRAR.exe", "a", "-hp" + RAR_PASSWORD, ARCHIVED_FILE, DATA_BASE_FILE
        ], check=True)

        print("✅ Database berhasil diarsipkan ke data_base.rar")

        # Hapus file JSON setelah diarsipkan
        os.remove(DATA_BASE_FILE)
        print("🗑️ File database asli telah dihapus setelah diarsipkan.")

    except Exception as e:
        print(f"❌ Gagal mengarsipkan database: {e}")

# Memuat database awal
data_base = load_database()

def get_current_drive():
    """
    Mendapatkan huruf drive tempat file Python ini berada.
    """
    return os.path.splitdrive(__file__)[0][0]  # Ambil huruf drive (contoh: 'R')

def change_drive_letter(current_letter, new_letter):
    """
    Mengubah huruf drive menggunakan perintah diskpart.
    Parameters:
        current_letter (str): Huruf drive saat ini (contoh: 'R').
        new_letter (str): Huruf drive baru (contoh: 'Z').
    """
    try:
        # Buat file instruksi untuk diskpart
        with open("diskpart_script.txt", "w") as f:
            f.write(f"select volume {current_letter}\n")
            f.write(f"assign letter={new_letter}\n")
        
        # Jalankan diskpart dengan file instruksi
        subprocess.run(["diskpart", "/s", "diskpart_script.txt"], check=True)
        print(f"Drive {current_letter}: berhasil diubah menjadi {new_letter}:")
    except Exception as e:
        print(f"⚠️Terjadi kesalahan saat mengubah drive: {e}")
    finally:
        # Hapus file instruksi setelah selesai
        try:
            os.remove("diskpart_script.txt")
        except Exception as cleanup_error:
            print(f"⚠️Gagal menghapus file diskpart_script.txt: {cleanup_error}")

def wait_for_ready(arduino):
    """Menunggu sinyal READY dari Arduino sebelum memulai autentikasi"""
    while True:
        line = arduino.readline().decode(errors="ignore").strip()  # Abaikan karakter aneh
        if line == "READY":
            print("✅ Arduino siap untuk autentikasi!")
            break
        else:
            print(f"⚠️ Menerima data awal aneh: {line}, diabaikan...")

def authenticate_arduino(arduino, AES_KEY):
    """Melakukan autentikasi dengan Arduino menggunakan kombinasi waktu + angka acak (terenkripsi)"""

    # Buat timestamp (4 byte) & angka acak (4 byte)
    timestamp = int(time.time()) & 0xFFFFFFFF
    random_part = secrets.randbelow(0xFFFFFFFF)  # 4 byte angka acak

    # Gabungkan timestamp + random part jadi 8 byte
    nonce = struct.pack("<II", timestamp, random_part)

    # Enkripsi nonce dengan AES-128-ECB
    aes = AES.new(AES_KEY, AES.MODE_ECB)
    encrypted_nonce = aes.encrypt(nonce.ljust(16, b'\x00'))  # Tambah padding jadi 16 byte

    # Kirim nonce terenkripsi ke Arduino
    arduino.write(encrypted_nonce)

    # Buat timestamp tambahan untuk validasi
    timestamp_validation = int(time.time()) & 0xFFFFFFFF
    encrypted_timestamp = aes.encrypt(struct.pack("<I", timestamp_validation).ljust(16, b'\x00'))
    
    # Kirim timestamp terenkripsi kedua
    arduino.write(encrypted_timestamp)

    # Baca respons dari Arduino (16 byte AES ciphertext)
    ciphertext = arduino.read(16)
    if len(ciphertext) != 16:
        print("⚠️ Data tidak lengkap!")
        return False

    # Dekripsi dengan AES-128-ECB
    plaintext = aes.decrypt(ciphertext)

    # Debug: Lihat hasil dekripsi dalam hex
    print(f"🔍 Plaintext (Hex): {plaintext.hex()}")

    # Ambil timestamp & random part yang dikirim Python, serta timestamp RTC dari Arduino
    received_timestamp, received_random, rtc_timestamp = struct.unpack("<III", plaintext[:12])

    print(f"📌 Timestamp Dikirim  : {received_timestamp} ({time.ctime(received_timestamp)})")
    print(f"📌 Random Part Dikirim: {received_random}")
    print(f"📌 Timestamp RTC      : {rtc_timestamp} ({time.ctime(rtc_timestamp)})")

    # Validasi timestamp agar tidak terlalu lama (maks 5 detik beda)
    current_time = int(time.time())
    if abs(current_time - rtc_timestamp) > 5:
        print("❌ Timestamp dari Arduino tidak valid! Mungkin terjadi replay attack.")
        return False

    # Validasi random part
    if received_random != random_part:
        print("❌ Random part tidak cocok! Kemungkinan perangkat tidak valid.")
        return False

    print("✅ Autentikasi sukses! Arduino asli.")
    return True

# Fungsi untuk menghasilkan password acak
def generate_random_password(length=32):
    characters = string.ascii_letters + string.digits
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

# Fungsi enkripsi data password
def encrypt_aes_gcm_with_password(data, password):
    iv = os.urandom(12)  # IV harus 12 byte untuk AES-GCM
    key = os.urandom(32)  # Gunakan kunci AES-256 (32 byte)

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
    tag = encryptor.tag  # Tag autentikasi 16 byte

    # Ubah password menjadi bytes (32 byte)
    password_bytes = password.encode()

    # Sisipkan password di posisi acak dalam ciphertext
    split_point = random.randint(0, len(ciphertext))
    encrypted_data_with_password = ciphertext[:split_point] + password_bytes + ciphertext[split_point:]

    # Gabungkan IV + ciphertext yang berisi password + Tag autentikasi
    final_encrypted_data = base64.b64encode(iv + encrypted_data_with_password + tag).decode()
    return final_encrypted_data, key  # Kembalikan data terenkripsi & kunci asli

# Fungsi padding agar sesuai dengan blok 16 byte
def pad(data):
    pad_length = 16 - (len(data) % 16)
    return data + bytes([pad_length] * pad_length)

# Fungsi enkripsi AES-ECB
def encrypt_part1_ecb(data):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    padded_data = pad(data.encode())  # Pastikan dalam bentuk bytes dan kelipatan 16
    encrypted = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted).decode()  # Convert ke HEX agar bisa dikirim ke Arduino

# fungsi untuk memisahkan data
def split_and_store_encrypted_data(encrypted_data):
    global data_base
    address_base = 2  # Alamat awal
    split_point = 15  # Jumlah byte untuk part1

    # Ambil hanya key yang berupa angka
    numeric_keys = [int(k) for k in data_base.keys() if k.isdigit()]
    if numeric_keys:
        max_address = max(numeric_keys)
        address_base = max_address + 30  # Penambahan 100 untuk address baru

    part1 = encrypted_data[:split_point]  # Ambil bagian pertama
    part2 = encrypted_data[split_point:]  # Ambil bagian kedua

    # **Enkripsi part1 dengan AES-ECB sebelum dikirim ke Arduino**
    encrypted_part1 = encrypt_part1_ecb(part1)

    # Simpan part2 ke database
    data_base[str(address_base)] = part2
    save_database(data_base)

    print(f"Data disimpan: Alamat={address_base}, Data={part2}")

    return encrypted_part1, address_base  # Kirim part1 yang sudah dienkripsi

#fungsi untuk mencari data di data base dan menggabungkan
# Fungsi dekripsi AES-128-ECB untuk part1
def decrypt_part1_ecb(part1_hex):
    key = bytes([
        0xA7, 0x4B, 0x9D, 0xF1,
        0xC2, 0x3E, 0x65, 0x88,
        0x14, 0xAB, 0x3D, 0xE9,
        0x71, 0xF5, 0x0C, 0x6B
    ])
    ciphertext = binascii.unhexlify(part1_hex)  # Konversi HEX ke byte
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)

    return decrypted.decode('utf-8').strip()  # Kembalikan hasil dekripsi asli

# Mengambil part2 lalu menggabungkan dengan hasil dekripsi part1
def retrieve_and_merge_encrypted_data(address, part1):
    global data_base

    address_str = str(address)
    if address_str in data_base:
        part2 = data_base[address_str]
        return part1 + part2  # Menggabungkan part1 (hasil dekripsi) dengan part2 dari database
    else:
        raise ValueError(f"⚠️ Alamat {address} tidak ditemukan di database.")

# fungsi untuk deksripsi data password
def decrypt_aes_gcm_with_password(encrypted_data, key):
    encrypted_data_bytes = base64.b64decode(encrypted_data)

    iv = encrypted_data_bytes[:12]  # Ambil IV (12 byte)
    tag = encrypted_data_bytes[-16:]  # Ambil Tag (16 byte)
    encrypted_data_with_password = encrypted_data_bytes[12:-16]  # Ambil ciphertext + password

    password_length = 32  # Panjang password yang disisipkan (diubah dari 16 ke 32)
    ciphertext_length = len(encrypted_data_with_password)

    found_password = None
    valid_plaintext = None

    # Coba cari password dalam ciphertext
    for i in range(ciphertext_length - password_length):
        possible_password = encrypted_data_with_password[i:i + password_length]

        try:
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()

            # Pisahkan ciphertext asli (tanpa password yang disisipkan)
            ciphertext = encrypted_data_with_password[:i] + encrypted_data_with_password[i + password_length:]
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            found_password = possible_password.decode()
            valid_plaintext = plaintext.decode()
            break  # Jika berhasil, hentikan pencarian
        except Exception:
            continue  # Coba posisi lain jika gagal

    if found_password:
        print(f"Password ditemukan: {found_password}")
        return valid_plaintext
    else:
        raise ValueError("⚠️Password tidak ditemukan atau data terenkripsi rusak.")

# fungsi untuk mencari arduino secara otomatis dalam device manager
def find_arduino():
    ports = list(serial.tools.list_ports.comports())
    for port in ports:
        print(f"Menemukan port: {port.device} - {port.description}")
        if 'USB Serial Port' in port.description or 'COM20' in port.description:
            return port.device
    return None

# fungsi untuk menerima data dari arduino
def receive_data_from_arduino(arduino):
    print("Menunggu data dari Arduino...")
    while True:
        if arduino.in_waiting > 0:
            data = arduino.readline().decode('utf-8').strip()
            if data:
                print(f"Data diterima dari Arduino: {data}")
                return data

# fungsi untuk mengirim data ke arduino
def send_password_to_arduino(password, arduino):
    print(f"Mengirim password terenkripsi: {password}")
    arduino.write((password.strip() + '\0').encode())
    time.sleep(2)

# fungsi untuk membuka veracrypt
def verifikasi_password(password):
    print("🔓 Membuka SSD NVMe dengan VeraCrypt...")

    try:
        # Jalankan VeraCrypt untuk membuka SSD
        result = subprocess.run(
            [
                veracrypt_path,
                "/v", volume_path,
                "/p", password,
                "/l", drive_letter,
                "/q", "/s", "/b"
            ],
            capture_output=True, text=True
        )

        if result.returncode == 0:
            print("✅ SSD berhasil dibuka!")

            # Hapus password dari memori sebelum menjalankan disable.py
            password = None
            print("🔒 Password sudah dihapus dari memori.")

            # Menjalankan disable.py melalui cmd dengan hak administrator
            try:
                print("🚀 Menjalankan disable.py sebagai administrator melalui cmd...")
                subprocess.run([
                    "powershell",
                    "-Command",
                    (
                        f"$psi = New-Object System.Diagnostics.ProcessStartInfo; "
                        f"$psi.FileName = 'cmd.exe'; "
                        f"$psi.Arguments = '/c python \"{dissable_file_path}\"'; "
                        f"$psi.Verb = 'runas'; "
                        f"$psi.WindowStyle = 'Hidden'; "
                        f"[System.Diagnostics.Process]::Start($psi)"
                    )
                ], check=True)
                print("✅ File disable.py berhasil dijalankan dengan administrator.")
            except Exception as e:
                print(f"⚠️ Gagal menjalankan disable.py sebagai administrator: {e}")

            # Tutup program utama setelah menjalankan disable.py
            sys.exit()

        else:
            print(f"⚠️ Gagal membuka SSD: {result.stderr}")

    except subprocess.TimeoutExpired:
        print("⚠️ Timeout saat mencoba membuka SSD.")
    except Exception as e:
        print(f"⚠️⚠️ Error saat membuka SSD: {e}")
    finally:
        # Pastikan password dihapus dari memori setelah digunakan
        password = None

def open_veracrypt_gui_with_clipboard(password):
    volume_path = "Z:\\bin\\rahasia.hc"
    veracrypt_path = "C:\\Program Files\\VeraCrypt\\VeraCrypt.exe"

    # Salin password lama ke clipboard
    pyperclip.copy(password)
    print("📋 Password lama sudah disalin ke clipboard.")

    # Buka VeraCrypt GUI langsung dengan volume ditunjuk
    subprocess.Popen([veracrypt_path, volume_path])

    print("📢 Silakan buka menu 'Tools > Change Volume Password'")
    print("🔑 Paste password lama (Ctrl+V), lalu masukkan password baru.")

def auto_shutdown_arduino(arduino):
    try:
        arduino.write(b'shutdown\0')
        print("💤 Mengirim perintah shutdown ke Arduino.")
    except Exception as e:
        print(f"⚠️ Gagal mengirim perintah shutdown: {e}")

# susunan proses program
def main():
     # Mengubah drive letter terlebih dahulu
    target_drive = "Z"
    current_drive = get_current_drive()
    print(f"Program sedang berjalan dari drive {current_drive}:")
    
    if current_drive != target_drive:
        print(f"Mengubah drive {current_drive} menjadi {target_drive}...")
        change_drive_letter(current_drive, target_drive)
    else:
        print("Drive sudah sesuai. Tidak ada perubahan yang diperlukan.")

    port = find_arduino()
    if port is None:
        print("⚠️ Arduino tidak ditemukan.")
        return

    print(f"Arduino terhubung di port: {port}")
    arduino = serial.Serial(port, 9600, timeout=1)
    time.sleep(2)

    # Tunggu "READY" dari Arduino sebelum autentikasi
    wait_for_ready(arduino)

    # Lakukan autentikasi
    if not authenticate_arduino(arduino, AES_KEY):
        print("❌ Gagal autentikasi! Program dihentikan.")
        return

    print("🔓 Autentikasi berhasil, melanjutkan proses...")

    password = None

    while True:
        data_from_arduino = receive_data_from_arduino(arduino)

        if data_from_arduino == "eeprom_penuh":
            print("⚠️ EEPROM penuh! Program akan keluar.")
            sys.exit()  # Keluar langsung dari program

        if data_from_arduino == "ganti_password":
            # Konfirmasi hapus database
            confirm = input("⚠️ Apakah Anda ingin menghapus file database lama (data_base.rar)? (y/n): ").lower()
            if confirm == "y":
                try:
                    os.remove("data_base.rar")
                    print("✅ File data_base.rar berhasil dihapus.")
                except FileNotFoundError:
                    print("ℹ️ File data_base.rar tidak ditemukan, lanjutkan proses.")
                except Exception as e:
                    print(f"❌ Gagal menghapus file: {e}")
            else:
                print("🚫 Penghapusan database dibatalkan.")

            if password is None:
                password = input("Masukkan password baru: ")

            # Enkripsi password dengan AES-GCM
            encrypted_password, key = encrypt_aes_gcm_with_password(
                password, generate_random_password()
            )

            # Simpan part1 dan address terlebih dahulu
            part1, address = split_and_store_encrypted_data(encrypted_password)

            # Simpan key ke database setelah address diperoleh
            data_base[f"{address}_key"] = base64.b64encode(key).decode()
            save_database(data_base)

            # Kirim part1 ke Arduino
            send_password_to_arduino(part1, arduino)

            response = receive_data_from_arduino(arduino)
            if response == "data_diterima":
                print("Arduino mengonfirmasi data diterima, mengulang pengiriman password...")
                continue  # Tetap dalam loop tanpa keluar

        elif data_from_arduino == "mode_verifikasi":
            print("Menunggu password dari Arduino...")
            address = int(receive_data_from_arduino(arduino))
            part1_hex = receive_data_from_arduino(arduino)

            # Validasi format part1 (harus dalam HEX)
            if not all(c in "0123456789ABCDEFabcdef" for c in part1_hex):
                print("⚠️ Data yang diterima bukan format HEX yang valid.")
                continue

            try:
                # Dekripsi part1 sebelum penggabungan
                part1_decrypted = decrypt_part1_ecb(part1_hex)
                
                # Ambil kembali encrypted_password dari EEPROM
                encrypted_password = retrieve_and_merge_encrypted_data(address, part1_decrypted)
                print(f"Data terenkripsi lengkap: {encrypted_password}")

                # Ambil key dari database
                key_base64 = data_base.get(f"{address}_key", None)
                if key_base64 is None:
                    raise ValueError("⚠️ Key tidak ditemukan, dekripsi gagal.")

                key = base64.b64decode(key_base64)

                # Dekripsi password
                password = decrypt_aes_gcm_with_password(encrypted_password, key)
                print(f"Password terdekripsi: {password}")

                verifikasi_password(password)
                auto_shutdown_arduino(arduino)

            except Exception as e:
                print(f"Dekripsi gagal: {e}")

        elif data_from_arduino == "password_PC":
            print("Permintaan password_PC diterima dari Arduino...")

            address = int(receive_data_from_arduino(arduino))
            part1_hex = receive_data_from_arduino(arduino)

            # Validasi format HEX
            if not all(c in "0123456789ABCDEFabcdef" for c in part1_hex):
                print("⚠️ Data bukan format HEX yang valid.")
                continue

            try:
                part1_decrypted = decrypt_part1_ecb(part1_hex)
                encrypted_password = retrieve_and_merge_encrypted_data(address, part1_decrypted)
                print(f"Data terenkripsi lengkap: {encrypted_password}")

                key_base64 = data_base.get(f"{address}_key", None)
                if key_base64 is None:
                    raise ValueError("⚠️ Key tidak ditemukan, dekripsi gagal.")

                key = base64.b64decode(key_base64)
                password = decrypt_aes_gcm_with_password(encrypted_password, key)
                print(f"✅ Password lama VeraCrypt berhasil didekripsi.")

                open_veracrypt_gui_with_clipboard(password)
                auto_shutdown_arduino(arduino)

            except Exception as e:
                print(f"❌ Gagal proses password_PC: {e}")
            continue


if __name__ == "__main__":
    main()