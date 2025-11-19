import os
import time
import subprocess
import filecmp
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from plyer import notification
from threading import Thread
import winreg as reg


# Folder dan file yang ingin dilindungi
FOLDER_DILINDUNGI = [r"Z:\bin", r"Z:\bin2", r"Z:\bin3", r"Z:\bin4", r"Z:\python"]
FILE_DILINDUNGI = []
status_proteksi_terakhir = {}

# Lokasi yang dipantau untuk deteksi penyalinan
FOLDER_PANTAU = [
    r"C:\Users\%USERNAME%\Desktop",
    r"C:\Users\%USERNAME%\Downloads",
    r"D:\\", r"E:\\", r"F:\\"
]

def kunci_acl(path):
    """Proteksi agar file/folder hanya bisa dibaca, tidak bisa disalin atau dihapus."""
    try:
        user = os.getlogin()

        # Cabut warisan izin
        subprocess.run(["icacls", path, "/inheritance:r"], check=True)

        # Hapus semua grup umum
        subprocess.run(["icacls", path, "/remove:g", "Everyone"], check=True)
        subprocess.run(["icacls", path, "/remove", "Users"], check=True)

        # Grant Read & Execute (RX) pada user aktif
        subprocess.run(["icacls", path, "/grant:r", f"{user}:(RX)"], check=True)

        # Deny Modify dan Delete (hapus & tulis)
        subprocess.run(["icacls", path, "/deny", f"{user}:(M,DE)"], check=True)

        print(f"🔒 Proteksi copy/hapus aktif untuk: {path}")
        notification.notify(
            title="Proteksi Folder Aktif",
            message=f"Hanya bisa dibuka, tidak bisa disalin/dihapus: {path}",
            timeout=5
        )
    except Exception as e:
        print(f"❌ Gagal proteksi {path}: {e}")


def set_read_only(path):
    """Set file sebagai read-only (opsional jika icacls gagal)."""
    try:
        # Coba hanya jika masih bisa ditulis
        if os.access(path, os.W_OK):
            os.chmod(path, 0o444)  # Hanya baca
            print(f"🔐 Set read-only: {path}")
            notification.notify(
                title="Proteksi Read-Only",
                message=f"{path} diatur menjadi hanya baca",
                timeout=5
            )
    except PermissionError:
        pass  # Sudah tidak punya akses, artinya sudah terkunci
    except Exception as e:
        print(f"❌ Gagal set read-only {path}: {e}")

def cek_status_proteksi(path):
    """Cek apakah file/folder sudah diproteksi (hanya bisa dibaca oleh user aktif)."""
    try:
        result = subprocess.run(["icacls", path], capture_output=True, text=True, check=True)
        output = result.stdout

        # Ambil nama user aktif
        user = os.getlogin()

        # Cek apakah hanya user aktif yang punya hak Read (R), tidak ada (F), (M), atau (W)
        for line in output.splitlines():
            if user.lower() in line.lower():
                if "(R)" in line and all(p not in line for p in ("(F)", "(M)", "(W)")):
                    return True
        return False
    except Exception as e:
        print(f"⚠️ Gagal cek proteksi: {e}")
        return False

def drive_terhubung(drive_letter="Z:\\"):
    """Cek apakah drive dengan letter tertentu terhubung ke sistem."""
    return os.path.exists(drive_letter)

def cek_dan_perbaiki_proteksi():
    """Cek proteksi secara periodik dan berhenti jika disk Z: tidak ditemukan."""
    global status_proteksi_terakhir

    while True:
        if not drive_terhubung("Z:\\"):
            print("❌ Disk Z: dicabut. Program dihentikan.")
            notification.notify(
                title="Disk Hilang", 
                message="Disk Z: tidak ditemukan. Program dihentikan.", 
                timeout=5
            )
            os._exit(1)

        for path in FOLDER_DILINDUNGI + FILE_DILINDUNGI:
            try:
                result = subprocess.run(["icacls", path], capture_output=True, text=True, check=True)
                output = result.stdout.strip()

                # Ambil status sebelumnya
                last_output = status_proteksi_terakhir.get(path)

                # Bandingkan ACL sekarang vs sebelumnya
                if output != last_output:
                    print(f"🔄 Memulihkan proteksi: {path}")
                    kunci_acl(path)
                    set_read_only(path)

                    # Simpan ACL terbaru
                    result_after = subprocess.run(["icacls", path], capture_output=True, text=True, check=True)
                    status_proteksi_terakhir[path] = result_after.stdout.strip()
            except Exception as e:
                print(f"⚠️ Gagal cek ACL {path}: {e}")

        time.sleep(4)


def kunci_semua():
    """Kunci semua folder dan file."""
    for path in FOLDER_DILINDUNGI + FILE_DILINDUNGI:
        if os.path.exists(path):
            kunci_acl(path)
            set_read_only(path)

def ambil_file_asli():
    """Ambil daftar semua file asli dari folder yang dilindungi."""
    data = []
    for folder in FOLDER_DILINDUNGI:
        for root, dirs, files in os.walk(folder):
            for f in files:
                data.append(os.path.join(root, f))
    for f in FILE_DILINDUNGI:
        if os.path.exists(f):
            data.append(f)
    return data

class Pemantau(FileSystemEventHandler):
    """Kelas event handler untuk salinan file."""
    def on_created(self, event):
        if event.is_directory:
            return
        try:
            for ori in file_asli:
                if os.path.exists(event.src_path) and filecmp.cmp(ori, event.src_path, shallow=False):
                    os.remove(event.src_path)
                    print(f"🛑 Salinan dihapus: {event.src_path}")
                    notification.notify(
                        title="🚨 Salinan Terdeteksi",
                        message=f"File disalin dan dihapus: {event.src_path}",
                        timeout=5
                    )
                    break
        except Exception as e:
            print(f"⚠️ Gagal deteksi salinan: {e}")
            notification.notify(
                title="⚠️ Deteksi Gagal",
                message=f"Gagal mendeteksi: {event.src_path}",
                timeout=5
            )

def mulai_monitor():
    """Mulai monitoring folder untuk salinan file."""
    obs = Observer()
    for f in FOLDER_PANTAU:
        path = os.path.expandvars(f)
        if os.path.exists(path):
            obs.schedule(Pemantau(), path, recursive=True)
    obs.start()
    print("👀 Proteksi aktif dan berjalan.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        obs.stop()
    obs.join()

if __name__ == "__main__":
    kunci_semua()
    file_asli = ambil_file_asli()
    Thread(target=cek_dan_perbaiki_proteksi, daemon=True).start()
    mulai_monitor()
