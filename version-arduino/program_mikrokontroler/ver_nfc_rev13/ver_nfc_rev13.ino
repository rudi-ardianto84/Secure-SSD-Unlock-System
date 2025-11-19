#include <Wire.h>
#include <Adafruit_SSD1306.h>
#include <EEPROM.h>
#include <Crypto.h>
#include <AES.h>
#include <string.h>
#include <RTClib.h>
#include <Adafruit_Fingerprint.h>
#include <Adafruit_PN532.h>

#define PIN_FINGER 30
#define PIN_NFC 31
#define EEPROM_I2C_ADDR 0x50  // Alamat I2C EEPROM AT24C256
#define PN532_IRQ   2   // Sesuaikan dengan pin IRQ yang  gunakan
#define PN532_RESET 3   // Sesuaikan dengan pin RESET yang  gunakan
#define OLED_RESET 4
#define DATA_START_ADDRESS sizeof(int)  // Atur sesuai struktur penyimpanan EEPROM
#define NFC_TIMEOUT 50000  // 5 detik timeout
Adafruit_SSD1306 display(OLED_RESET);
RTC_DS3231 rtc;
AES128 aes128;

byte key[16] = {
  0xA7, 0x4B, 0x9D, 0xF1,
  0xC2, 0x3E, 0x65, 0x88,
  0x14, 0xAB, 0x3D, 0xE9,
  0x71, 0xF5, 0x0C, 0x6B
};

byte ciphertext[16];

const int relayPin = 7;
const int switchPin = 6;
const int execPin = 5;

unsigned long previousMillis = 0;
const long interval = 500;

// Sensor sidik jari menggunakan komunikasi serial dengan Arduino
Adafruit_Fingerprint finger = Adafruit_Fingerprint(&Serial1);;
Adafruit_PN532 nfc(PN532_IRQ, PN532_RESET, &Wire);

// EEPROM
const int maxEntries = 30;
const int dataLength = 30;
int currentEntry = 0;
bool readEntries[maxEntries] = {false};
int readCount = 0;
int currentReadIndex = 0; // Menyimpan indeks data yang sedang dibaca

uint16_t getTanggalAddress(uint8_t id) {
  return 0x0400 + ((id - 1) * 4);
}

bool verificationStarted = false; // hapus tanda // kalau perlu
bool isRegistering = false;
bool isChangingPassword = false;
bool isRegisteringNFC = false;  // Mode pendaftaran NFC
bool validated = false; // Tambahkan di atas, sebelum void setup()
bool isChangingPCPassword = false;

// Deklarasi prototipe fungsi
void loadReadEntriesFromEEPROM() {
    EEPROM.get(sizeof(int), readEntries); // Memuat status pembacaan dari EEPROM
}

void clearEEPROM() {
    for (int i = 0; i < EEPROM.length(); i++) {
        EEPROM.write(i, 0);
    }
    Serial.println(F("EEPROM cleared"));
}

void setup() {
  Serial.begin(9600);

  if (!rtc.begin()) {
      Serial.println("RTC tidak ditemukan!");
      while (1);
  }

  pinMode(relayPin, OUTPUT);
  digitalWrite(relayPin, HIGH);

  pinMode(switchPin, INPUT_PULLUP);
  pinMode(execPin, INPUT_PULLUP);
  pinMode(PIN_FINGER, INPUT_PULLUP);
  pinMode(PIN_NFC, INPUT_PULLUP);

  pinMode(8, OUTPUT); 
  digitalWrite(8, LOW); 

  pinMode(9, OUTPUT); // 
  digitalWrite(9, LOW); // 

  pinMode(10, OUTPUT); // 
  digitalWrite(10, LOW); // 

  pinMode(11, OUTPUT); // 
  digitalWrite(11, LOW); // 

  nfc.begin();

  ////Serial.println("Mengecek modul PN532...");
  uint32_t versiondata = nfc.getFirmwareVersion();
    if (!versiondata) {
        ///Serial.println("Tidak dapat menemukan PN532. Cek koneksi!");
        ////while (1);
    }
  //////Serial.println("PN532 ditemukan!");
  nfc.SAMConfig();

  display.begin(SSD1306_SWITCHCAPVCC, 0x3C);
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(WHITE);
  Serial1.begin(57600); // Sensor fingerprint R307
  if (finger.verifyPassword()) {
    display.setCursor(0, 0);
    display.println(F("Sensor siap."));
    display.display();
  } else {
    display.setCursor(0, 0);
    display.println(F("Gagal hubungkan sensor."));
    display.display();
    ////while (1);  // Hentikan eksekusi jika tidak bisa terhubung// sementara mati dulu
  }
  // Inisialisasi angka acak
  randomSeed(analogRead(0));  // Menggunakan nilai analog pada pin A0 untuk seed

  display.clearDisplay();
  display.setCursor(0, 0);
  display.println(F("Pilih mode:"));
  display.println(F("Tekan tombol untuk switch."));
  display.display();
  delay(50);

  // Cek apakah EEPROM sudah diinisialisasi
    EEPROM.get(0, currentEntry);

    if (currentEntry < 0 || currentEntry > maxEntries) {
        currentEntry = 0;
        EEPROM.put(0, currentEntry);
    }

    // Tambahkan log untuk memverifikasi isi EEPROM
    for (int i = 0; i < maxEntries; i++) {
        String data = readDataFromEEPROM(i);
    }

  loadReadEntriesFromEEPROM();
  EEPROM.get(sizeof(int), readEntries);
  EEPROM.get(sizeof(int) + sizeof(readEntries), readCount);

  // Muat indeks pembacaan terakhir dari EEPROM internal
  currentReadIndex = readReadIndexFromInternalEEPROM();

  // Ubah pembacaan dimulai dari 1 jika nilai indeks adalah 0
  if (currentReadIndex <= 0 || currentReadIndex >= currentEntry) {
    currentReadIndex = 1;  // Reset ke indeks pertama
  }
}

void loop() {
  unsigned long currentMillis = millis();
  if (!verificationStarted && currentMillis >= 2000) { 
  // Jalankan hanya sekali setelah 4 detik pertama
  digitalWrite(8, LOW);
  digitalWrite(9, HIGH);
  digitalWrite(10, HIGH);
  delay(2000);
  Serial.println(F("READY"));
  verificationStarted = true; 
  previousMillis = currentMillis; // Reset timer
}

//fungsi nonced dan timestamp/////////////////////////////////////////////////////////
static bool statusDisplayed = false;
static unsigned long waitingStartTime = 0;

if (!validated) {
  if (!statusDisplayed) {

    display.clearDisplay();
    display.setCursor(0, 0);
    display.println(F("Menunggu Validasi..."));
    display.display();
    statusDisplayed = true;
    waitingStartTime = millis(); // Mulai hitung
  }

  if (Serial.available() >= 16) {
    // Data nonce pertama diterima
    byte encrypted_nonce[16];
    Serial.readBytes((char*)encrypted_nonce, 16);
    
    byte decrypted_nonce[16];
    aes128.setKey(key, sizeof(key));
    aes128.decryptBlock(decrypted_nonce, encrypted_nonce);
    
    uint32_t timestamp, random_part;
    memcpy(&timestamp, decrypted_nonce, 4);
    memcpy(&random_part, decrypted_nonce + 4, 4);

    // Tunggu timestamp kedua
    unsigned long secondStartTime = millis();
    while (Serial.available() < 16) {
      if (millis() - secondStartTime > 10000) {
        display.clearDisplay();
        display.setCursor(0, 0);
        display.println(F("Validasi Gagal"));
        display.println(F("Tidak Ada Data 2"));
        display.display();
        delay(2000);
        digitalWrite(relayPin, LOW);
        return;
      }
    }

    byte encrypted_timestamp[16];
    Serial.readBytes((char*)encrypted_timestamp, 16);
    
    byte decrypted_timestamp[16];
    aes128.decryptBlock(decrypted_timestamp, encrypted_timestamp);
    
    uint32_t received_timestamp;
    memcpy(&received_timestamp, decrypted_timestamp, 4);
    
    DateTime now = rtc.now();
    uint32_t rtc_timestamp = now.unixtime();
    
    if (abs((int)(rtc_timestamp - received_timestamp)) > 60) {
      display.clearDisplay();
      display.setCursor(0, 0);
      display.println(F("Validasi Gagal"));
      display.println(F("Timestamp Tidak Cocok"));
      display.display();
      delay(2000);
      digitalWrite(relayPin, LOW);
      return;
    }

    // Validasi sukses
    byte plaintext[16] = {0};
    memcpy(plaintext, &timestamp, 4);
    memcpy(plaintext + 4, &random_part, 4);
    memcpy(plaintext + 8, &rtc_timestamp, 4);
    
    byte ciphertext[16];
    aes128.encryptBlock(ciphertext, plaintext);
    Serial.write(ciphertext, 16);

    validated = true;
    statusDisplayed = false; // Reset buat nanti
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println(F("Validasi Berhasil"));
    display.println(F("Tekan Switch"));
    display.display();
    delay(1000);
  }
  else {
    // Tidak ada data masuk
    if (millis() - waitingStartTime > 10000) {
      // Timeout 5 detik
      display.clearDisplay();
      display.setCursor(0, 0);
      display.println(F("Tidak Terhubung"));
      display.println(F("Komputer"));
      display.display();
      delay(3000); // Biar bisa kebaca
      digitalWrite(relayPin, LOW);
      return;
    }
  }

  return;
}

// === Kalau sudah tervalidasi, lanjut program utama ===
currentMillis = millis();
  
// Mode Switch dan Pendaftaran
if (digitalRead(switchPin) == LOW && currentMillis - previousMillis >= interval) {
    previousMillis = currentMillis;

    if (!isChangingPassword && !isRegistering && !isRegisteringNFC && !isChangingPCPassword) {
      display.clearDisplay();
      display.setCursor(0, 0);
      display.println(F("Mode: Manage Finger"));
      display.display();
      isRegistering = true;
      isChangingPassword = false;
      isRegisteringNFC = false;
      isChangingPCPassword = false;
    } 
    else if (isRegistering) {
      display.clearDisplay();
      display.setCursor(0, 0);
      display.println(F("Mode: Ganti Password"));
      display.println(F("Arduino"));
      display.display();
      isRegistering = false;
      isChangingPassword = true;
      isRegisteringNFC = false;
      isChangingPCPassword = false;
    } 
    else if (isChangingPassword) {
      display.clearDisplay();
      display.setCursor(0, 0);
      display.println(F("Mode: Daftar NFC"));
      display.display();
      isRegistering = false;
      isChangingPassword = false;
      isRegisteringNFC = true;
      isChangingPCPassword = false;
    }
    else if (isRegisteringNFC) {
      display.clearDisplay();
      display.setCursor(0, 0);
      display.println(F("Mode: Ganti Password"));
      display.println(F("Komputer"));
      display.display();
      isRegistering = false;
      isChangingPassword = false;
      isRegisteringNFC = false;
      isChangingPCPassword = true;
    }
    else {
      display.clearDisplay();
      display.setCursor(0, 0);
      display.println(F("Mode: Verifikasi"));
      display.display();
      isRegistering = false;
      isChangingPassword = false;
      isRegisteringNFC = false;
      isChangingPCPassword = false;
    }
    delay(200);
}


// Mode Ganti Password - Meminta input data setelah tombol eksekusi ditekan
if (isChangingPassword) {
    static bool isVerified = false;  // Menyimpan status verifikasi

    if (!isVerified) {  // Hanya verifikasi sekali di awal
        if (digitalRead(execPin) == LOW && currentMillis - previousMillis >= interval) {
          previousMillis = currentMillis;

      ///Serial.println("Masuk Mode Ganti Password");

        display.clearDisplay();
        display.setCursor(0, 0);
        display.println("Pilih Mode:");
        display.println("Tombol 1: NFC");
        display.println("Tombol 2: Fingerprint");
        display.display();

        bool verifikasi_berhasil = false;
        unsigned long startMillis = millis();
        const unsigned long timeout = 60000;  // 60 detik

          while (millis() - startMillis < timeout) {
              if (digitalRead(PIN_FINGER) == LOW) {
                bool hasil = prosesSidikJari();
                if (hasil) {
                  verifikasi_berhasil = true;
                  break;
                }
              }

              if (digitalRead(PIN_NFC) == LOW) {
                  display.clearDisplay();
                  display.setCursor(0, 0);
                  display.println("Verifikasi NFC...");
                  display.display();

                  // Aktifkan pencarian kartu secara manual
                  nfc.SAMConfig();
                  nfc.inListPassiveTarget();

                  unsigned long nfcStart = millis();
                  const unsigned long nfcTimeout = 5000; // 5 detik timeout NFC

                  while (millis() - nfcStart < nfcTimeout) {
                      // Cek apakah tombol NFC dilepas
                      if (digitalRead(PIN_NFC) == HIGH) {
                          display.clearDisplay();
                          display.setCursor(0, 0);
                          display.println("Verifikasi NFC Dibatalkan");
                          display.display();
                          delay(2000);
                          break;
                      }

                      // Buffer UID
                      uint8_t success;
                      uint8_t uid[7];
                      uint8_t uidLength;

                      // Non-blocking cek kartu
                      success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength, 50);  // timeout 50ms

                      if (success) {
                          String uidStr = "";
                          for (uint8_t i = 0; i < uidLength; i++) {
                              char hexStr[3];
                              sprintf(hexStr, "%02X", uid[i]);
                              uidStr += hexStr;
                          }

                          String nfcData = "";
                          for (int page = 4; page < 8; page++) {
                              uint8_t ndefBuffer[4];
                              if (nfc.ntag2xx_ReadPage(page, ndefBuffer)) {
                                  for (int i = 0; i < 4; i++) {
                                      char hexStr[3];
                                      sprintf(hexStr, "%02X", ndefBuffer[i]);
                                      nfcData += hexStr;
                                  }
                              }
                          }

                          if (verifikasiKartu(nfcData.length() == 0 ? uidStr : nfcData)) {
                              verifikasi_berhasil = true;
                              break;
                          } else {
                              display.clearDisplay();
                              display.setCursor(0, 0);
                              display.println("Kartu NFC Tidak Valid!");
                              display.display();
                              delay(2000);
                              break;
                          }
                      }

                      delay(50);  // kasih napas biar gak terlalu tight loop
                  }

                  // reset kartu
                  nfc.SAMConfig(); // inisialisasi ulang agar bisa baca ulang nanti

                  if (verifikasi_berhasil) break;
              }
              delay(100);
          }

          if (verifikasi_berhasil) {
              display.clearDisplay();
              display.setCursor(0, 0);
              display.println("Verifikasi Berhasil.");
              display.display();
              delay(1000);
              display.clearDisplay();
              display.setCursor(0, 0);
              display.println("masukkan password");
              display.println("Sama Di Veracrypt");
              display.println("Tekan EXEC lanjut");
              display.println("Tekan SWITCH batal");
              display.display();

              // Tunggu input tombol
              while (true) {
                  if (digitalRead(execPin) == LOW) {
                      // Menampilkan pesan sebelum menghapus EEPROM
                      display.clearDisplay();
                      display.setCursor(0, 0);
                      display.println("Menghapus EEPROM...");
                      display.display();

                      // Proses penghapusan EEPROM
                      for (int i = 0; i < EEPROM.length(); i++) {
                          EEPROM.write(i, 0xFF);  // Atau 0 jika ingin isi 0
                          delay(2);  // Tambahkan sedikit delay agar tidak terlalu cepat
                      }

                      display.clearDisplay();
                      display.setCursor(0, 0);
                      display.println("EEPROM dihapus!");
                      display.display();
                      delay(1000);
                      currentEntry = 0;  //  Reset index setelah EEPROM dihapus
                      isVerified = true;
                      break;
                  } else if (digitalRead(switchPin) == LOW) {
                      // Batal: Keluar dari mode ganti password
                      display.clearDisplay();
                      display.setCursor(0, 0);
                      display.println("Dibatalkan.");
                      display.display();
                      delay(2000);
                      isChangingPassword = false;
                      return;
                  }
                  delay(100);
              }

          } else {
              display.clearDisplay();
              display.setCursor(0, 0);
              display.println("Verifikasi Gagal!");
              display.display();
              delay(2000);
              return;
          }
        }
      }

      // Setelah verifikasi, langsung ke mode input data tanpa verifikasi ulang
      if (isVerified) {
      digitalWrite(8, HIGH);  // Pin 8 HIGH saat masuk mode verifikasi
      digitalWrite(9, HIGH);
      digitalWrite(10, HIGH);
      digitalWrite(11, HIGH);  // Pin 8 HIGH saat masuk mode verifikasi
      digitalWrite(relayPin, HIGH);  // Pastikan pin 7 HIGH

      // pengecekan EEPROM penuh 
      if (currentEntry >= maxEntries) {
        display.clearDisplay();
        display.setCursor(0, 0);
        display.println(F("EEPROM penuh."));
        display.display();
        Serial.println(F("eeprom_penuh"));
        delay(2000);
        digitalWrite(relayPin, LOW);
        isChangingPassword = false;
        return;
      }

      if (currentEntry < maxEntries) {
        display.clearDisplay();
        display.setCursor(0, 0);
        display.println(F("Masukkan data..."));
        display.display();
        Serial.println(F("ganti_password"));
        delay(200);
        while (Serial.available() == 0) {
          delay(200);  // Menunggu input data
        }
        delay(3000);

        String hexData = "";
        while (Serial.available()) {
          char ch = Serial.read();
          if (ch == '\n' || ch == '\r') break;
          hexData += ch;
        }
        hexData.trim();

        String newData;
        decryptAES(hexData, newData);  // Dekripsi data yang diterima
        delay(3000);

        if (newData.length() > dataLength) {
          display.clearDisplay();
          display.setCursor(0, 0);
          display.println(F("Data terlalu panjang."));
          display.display();
          Serial.println(F("data_terlalu_panjang"));
          delay(2000);
        } else {
          if (saveDataToEEPROM(newData)) {
            display.clearDisplay();
            display.setCursor(0, 0);
            display.println(F("Data disimpan."));
            display.display();
            Serial.println(F("data_diterima"));
            delay(6000);

            // Secara otomatis "menekan" tombol eksekusi (set pin ke LOW)
            digitalWrite(execPin, LOW);  // Tekan tombol (LOW)
            delay(50);  // Simulasi waktu penekanan tombol
            digitalWrite(execPin, HIGH);  // Lepaskan tombol (HIGH)

          } else {
            Serial.println(F("eeprom_penuh"));
            display.clearDisplay();
            display.setCursor(0, 0);
            display.println(F("EEPROM penuh."));
            display.display();
            delay(2000);
            isChangingPassword = false;  // Keluar dari mode Ganti Password jika EEPROM penuh

            // Matikan eksekusi pin jika EEPROM penuh
            digitalWrite(execPin, HIGH);  // Pastikan tombol eksekusi tidak tertekan
          }
        }
      }
    }
  }

  // Mode ganti password PC
  if (isChangingPCPassword) {
        if (digitalRead(execPin) == LOW && millis() - previousMillis >= interval) {
          previousMillis = millis();

        display.clearDisplay();
        display.setCursor(0, 0);
        display.println("Pilih Mode:");
        display.println("Tombol 1: NFC");
        display.println("Tombol 2: Fingerprint");
        display.display();

        bool verifikasi_berhasil = false;
        unsigned long startMillis = millis();
        const unsigned long timeout = 60000;  // 60 detik

        while (millis() - startMillis < timeout) {
            if (digitalRead(PIN_FINGER) == LOW) {
                bool hasil = prosesSidikJari();
                if (hasil) {
                  verifikasi_berhasil = true;
                  break;
                }
              }

            if (digitalRead(PIN_NFC) == LOW) {
                display.clearDisplay();
                display.setCursor(0, 0);
                display.println("Verifikasi NFC...");
                display.display();

                unsigned long waktuMulaiNFC = millis(); // Mulai stopwatch NFC

                nfc.SAMConfig();
                nfc.inListPassiveTarget();

                unsigned long nfcStart = millis();
                const unsigned long nfcTimeout = 5000;

                bool sudahDiproses = false;

                while (millis() - nfcStart < nfcTimeout) {
                    if (digitalRead(PIN_NFC) == HIGH) {
                        display.clearDisplay();
                        display.setCursor(0, 0);
                        display.println("Verifikasi NFC Dibatalkan");
                        display.display();
                        delay(2000);
                        sudahDiproses = true;
                        break;
                    }

                    uint8_t success;
                    uint8_t uid[7];
                    uint8_t uidLength;

                    success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength, 50);
                    if (success) {
                        String uidStr = "";
                        for (uint8_t i = 0; i < uidLength; i++) {
                            char hexStr[3];
                            sprintf(hexStr, "%02X", uid[i]);
                            uidStr += hexStr;
                        }

                        String nfcData = "";
                        for (int page = 4; page < 8; page++) {
                            uint8_t ndefBuffer[4];
                            if (nfc.ntag2xx_ReadPage(page, ndefBuffer)) {
                                for (int i = 0; i < 4; i++) {
                                    char hexStr[3];
                                    sprintf(hexStr, "%02X", ndefBuffer[i]);
                                    nfcData += hexStr;
                                }
                            }
                        }

                        float waktuVerifikasi = (millis() - waktuMulaiNFC) / 1000.0;

                        if (verifikasiKartu(nfcData.length() == 0 ? uidStr : nfcData)) {
                            display.clearDisplay();
                            display.setCursor(0, 0);
                            display.println("NFC Berhasil!");
                            display.print("Waktu: ");
                            display.print(waktuVerifikasi, 2);
                            display.println(" detik");
                            display.display();

                            verifikasi_berhasil = true;
                            sudahDiproses = true;
                            delay(2000);
                            break;
                        } else {
                            display.clearDisplay();
                            display.setCursor(0, 0);
                            display.println("NFC Gagal!");
                            display.print("Waktu: ");
                            display.print(waktuVerifikasi, 2);
                            display.println(" detik");
                            display.display();

                            sudahDiproses = true;
                            delay(2000);
                            break;
                        }
                    }

                    delay(50);
                }

                // Jika tidak berhasil menemukan kartu sampai timeout
                if (!sudahDiproses) {
                    float waktuVerifikasi = (millis() - waktuMulaiNFC) / 1000.0;
                    display.clearDisplay();
                    display.setCursor(0, 0);
                    display.println("NFC Timeout!");
                    display.print("Waktu: ");
                    display.print(waktuVerifikasi, 2);
                    display.println(" detik");
                    display.display();
                    delay(2000);
                }

                nfc.SAMConfig();  // Reset NFC setelah selesai

                if (verifikasi_berhasil) break;
            }
            delay(100);
        }

        if (verifikasi_berhasil) {
            display.clearDisplay();
            display.setCursor(0, 0);
            display.println("Verifikasi Berhasil.");
            display.display();
            delay(1000);
        } else {
            display.clearDisplay();
            display.setCursor(0, 0);
            display.println("Verifikasi Gagal!");
            display.display();
            delay(2000);
            return;
        }
     
        digitalWrite(8, LOW);
        digitalWrite(9, HIGH);
        digitalWrite(10, HIGH);
        digitalWrite(relayPin, HIGH);

        display.clearDisplay();
        display.setCursor(0, 0);
        display.println(F("ganti password PC"));
        delay(2000);
        display.display();
        Serial.println(F("password_PC"));
        delay(200);

        String data = getNextValidDataFromEEPROM();
        if (data == "Tidak ada data valid") {
          display.clearDisplay();
          display.setCursor(0, 0);
          display.println(F("Data tidak valid"));
          display.display();
          delay(2000);
        } else {
  ////////////////Fungsi enkripsi data/////////////////////////////////
          // Konversi String ke byte array untuk enkripsi
          byte plaintext[16] = {0};
          data.getBytes(plaintext, 16);

          // Enkripsi dengan AES-128 ECB
          aes128.setKey(key, 16);
          aes128.encryptBlock(ciphertext, plaintext);

          // Konversi ciphertext ke HEX
          char hexCiphertext[33];
          for (int i = 0; i < 16; i++) {
            sprintf(hexCiphertext + (i * 2), "%02X", ciphertext[i]);
          }
          hexCiphertext[32] = '\0';
  /////////////////////////////////////////////////////////////////////
          // Kirim hasil enkripsi ke komputer
          Serial.println(hexCiphertext);

          display.clearDisplay();
          display.setCursor(0, 0);
          display.println(F("Data password sebelumnya dikirim."));
          display.display();
          delay(2000);

          digitalWrite(8, LOW);
          digitalWrite(9, LOW);
          digitalWrite(10, LOW);
          delay(2000);
        }
        digitalWrite(relayPin, LOW);
      }
    }

    // Mode Verifikasi
    if (!isRegistering && !isChangingPassword && !isRegisteringNFC && !isChangingPCPassword) { 
        if (digitalRead(execPin) == LOW && millis() - previousMillis >= interval) {
          previousMillis = millis();

          display.clearDisplay();
          display.setCursor(0, 0);
          display.println("Pilih Mode:");
          display.println("Tombol 1: NFC");
          display.println("Tombol 2: Fingerprint");
          display.display();

          bool verifikasi_berhasil = false;
          unsigned long startMillis = millis();
          const unsigned long timeout = 60000;  // 60 detik

          while (millis() - startMillis < timeout) {
              if (digitalRead(PIN_FINGER) == LOW) {
                bool hasil = prosesSidikJari();
                if (hasil) {
                  verifikasi_berhasil = true;
                  break;
                }
              }

              if (digitalRead(PIN_NFC) == LOW) {
                  display.clearDisplay();
                  display.setCursor(0, 0);
                  display.println("Verifikasi NFC...");
                  display.display();

                  unsigned long waktuMulaiNFC = millis(); // Mulai stopwatch NFC

                  nfc.SAMConfig();
                  nfc.inListPassiveTarget();

                  unsigned long nfcStart = millis();
                  const unsigned long nfcTimeout = 5000;

                  bool sudahDiproses = false;

                  while (millis() - nfcStart < nfcTimeout) {
                      if (digitalRead(PIN_NFC) == HIGH) {
                          display.clearDisplay();
                          display.setCursor(0, 0);
                          display.println("Verifikasi NFC Dibatalkan");
                          display.display();
                          delay(2000);
                          sudahDiproses = true;
                          break;
                      }

                      uint8_t success;
                      uint8_t uid[7];
                      uint8_t uidLength;

                      success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength, 50);
                      if (success) {
                          String uidStr = "";
                          for (uint8_t i = 0; i < uidLength; i++) {
                              char hexStr[3];
                              sprintf(hexStr, "%02X", uid[i]);
                              uidStr += hexStr;
                          }

                          String nfcData = "";
                          for (int page = 4; page < 8; page++) {
                              uint8_t ndefBuffer[4];
                              if (nfc.ntag2xx_ReadPage(page, ndefBuffer)) {
                                  for (int i = 0; i < 4; i++) {
                                      char hexStr[3];
                                      sprintf(hexStr, "%02X", ndefBuffer[i]);
                                      nfcData += hexStr;
                                  }
                              }
                          }

                          float waktuVerifikasi = (millis() - waktuMulaiNFC) / 1000.0;

                          if (verifikasiKartu(nfcData.length() == 0 ? uidStr : nfcData)) {
                              display.clearDisplay();
                              display.setCursor(0, 0);
                              display.println("NFC Berhasil!");
                              display.print("Waktu: ");
                              display.print(waktuVerifikasi, 2);
                              display.println(" detik");
                              display.display();

                              verifikasi_berhasil = true;
                              sudahDiproses = true;
                              delay(2000);
                              break;
                          } else {
                              display.clearDisplay();
                              display.setCursor(0, 0);
                              display.println("NFC Gagal!");
                              display.print("Waktu: ");
                              display.print(waktuVerifikasi, 2);
                              display.println(" detik");
                              display.display();

                              sudahDiproses = true;
                              delay(2000);
                              break;
                          }
                      }

                      delay(50);
                  }

                  // Jika tidak berhasil menemukan kartu sampai timeout
                  if (!sudahDiproses) {
                      float waktuVerifikasi = (millis() - waktuMulaiNFC) / 1000.0;
                      display.clearDisplay();
                      display.setCursor(0, 0);
                      display.println("NFC Timeout!");
                      display.print("Waktu: ");
                      display.print(waktuVerifikasi, 2);
                      display.println(" detik");
                      display.display();
                      delay(2000);
                  }

                  nfc.SAMConfig();  // Reset NFC setelah selesai

                  if (verifikasi_berhasil) break;
              }
              delay(100);
          }

          if (verifikasi_berhasil) {
              display.clearDisplay();
              display.setCursor(0, 0);
              display.println("Verifikasi Berhasil.");
              display.display();
              delay(1000);
          } else {
              display.clearDisplay();
              display.setCursor(0, 0);
              display.println("Verifikasi Gagal!");
              display.display();
              delay(2000);
              return;
          }
      
          digitalWrite(8, LOW);
          digitalWrite(9, HIGH);
          digitalWrite(10, HIGH);
          digitalWrite(relayPin, HIGH);

          display.clearDisplay();
          display.setCursor(0, 0);
          display.println(F("Mode Verifikasi"));
          delay(2000);
          display.display();
          Serial.println(F("mode_verifikasi"));
          delay(200);

          String data = getNextValidDataFromEEPROM();
          if (data == "Tidak ada data valid") {
            display.clearDisplay();
            display.setCursor(0, 0);
            display.println(F("Data tidak valid"));
            display.display();
            delay(2000);
          } else {
    ////////////////Fungsi enkripsi data/////////////////////////////////
            // Konversi String ke byte array untuk enkripsi
            byte plaintext[16] = {0};
            data.getBytes(plaintext, 16);

            // Enkripsi dengan AES-128 ECB
            aes128.setKey(key, 16);
            aes128.encryptBlock(ciphertext, plaintext);

            // Konversi ciphertext ke HEX
            char hexCiphertext[33];
            for (int i = 0; i < 16; i++) {
              sprintf(hexCiphertext + (i * 2), "%02X", ciphertext[i]);
            }
            hexCiphertext[32] = '\0';
    /////////////////////////////////////////////////////////////////////
            // Kirim hasil enkripsi ke komputer
            Serial.println(hexCiphertext);

            display.clearDisplay();
            display.setCursor(0, 0);
            display.println(F("Data dienkripsi & dikirim."));
            display.display();
            delay(2000);

            digitalWrite(8, LOW);
            digitalWrite(9, LOW);
            digitalWrite(10, LOW);
            delay(2000);
          }
          digitalWrite(relayPin, LOW);
        }
      }

      // Mode Pendaftaran
      if (isRegistering) {
        if (digitalRead(execPin) == LOW && currentMillis - previousMillis >= interval) {
          previousMillis = currentMillis;  // Restart timer debounce
          
          ///Serial.println("Masuk Mode Pendaftaran Sidik Jari");

            display.clearDisplay();
            display.setCursor(0, 0);
            display.println("Pilih Mode:");
            display.println("Tombol 1: NFC");
            display.println("Tombol 2: Fingerprint");
            display.display();

            bool verifikasi_berhasil = false;
            unsigned long startMillis = millis();
            const unsigned long timeout = 60000;  // 60 detik

            while (millis() - startMillis < timeout) {
                if (digitalRead(PIN_FINGER) == LOW) {
                  bool hasil = prosesSidikJari();
                  if (hasil) {
                    verifikasi_berhasil = true;
                    break;
                  }
                }

                if (digitalRead(PIN_NFC) == LOW) {
                    display.clearDisplay();
                    display.setCursor(0, 0);
                    display.println("Verifikasi NFC...");
                    display.display();

                    unsigned long waktuMulaiNFC = millis(); // Mulai stopwatch NFC

                    nfc.SAMConfig();
                    nfc.inListPassiveTarget();

                    unsigned long nfcStart = millis();
                    const unsigned long nfcTimeout = 5000;

                    bool sudahDiproses = false;

                    while (millis() - nfcStart < nfcTimeout) {
                        if (digitalRead(PIN_NFC) == HIGH) {
                            display.clearDisplay();
                            display.setCursor(0, 0);
                            display.println("Verifikasi NFC Dibatalkan");
                            display.display();
                            delay(2000);
                            sudahDiproses = true;
                            break;
                        }

                        uint8_t success;
                        uint8_t uid[7];
                        uint8_t uidLength;

                        success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength, 50);
                        if (success) {
                            String uidStr = "";
                            for (uint8_t i = 0; i < uidLength; i++) {
                                char hexStr[3];
                                sprintf(hexStr, "%02X", uid[i]);
                                uidStr += hexStr;
                            }

                            String nfcData = "";
                            for (int page = 4; page < 8; page++) {
                                uint8_t ndefBuffer[4];
                                if (nfc.ntag2xx_ReadPage(page, ndefBuffer)) {
                                    for (int i = 0; i < 4; i++) {
                                        char hexStr[3];
                                        sprintf(hexStr, "%02X", ndefBuffer[i]);
                                        nfcData += hexStr;
                                    }
                                }
                            }

                            float waktuVerifikasi = (millis() - waktuMulaiNFC) / 1000.0;

                            if (verifikasiKartu(nfcData.length() == 0 ? uidStr : nfcData)) {
                                display.clearDisplay();
                                display.setCursor(0, 0);
                                display.println("NFC Berhasil!");
                                display.print("Waktu: ");
                                display.print(waktuVerifikasi, 2);
                                display.println(" detik");
                                display.display();

                                verifikasi_berhasil = true;
                                sudahDiproses = true;
                                delay(2000);
                                break;
                            } else {
                                display.clearDisplay();
                                display.setCursor(0, 0);
                                display.println("NFC Gagal!");
                                display.print("Waktu: ");
                                display.print(waktuVerifikasi, 2);
                                display.println(" detik");
                                display.display();

                                sudahDiproses = true;
                                delay(2000);
                                break;
                            }
                        }

                        delay(50);
                    }

                    // Jika tidak berhasil menemukan kartu sampai timeout
                    if (!sudahDiproses) {
                        float waktuVerifikasi = (millis() - waktuMulaiNFC) / 1000.0;
                        display.clearDisplay();
                        display.setCursor(0, 0);
                        display.println("NFC Timeout!");
                        display.print("Waktu: ");
                        display.print(waktuVerifikasi, 2);
                        display.println(" detik");
                        display.display();
                        delay(2000);
                    }

                    nfc.SAMConfig();  // Reset NFC setelah selesai

                    if (verifikasi_berhasil) break;
                }
                delay(100);
            }

            if (verifikasi_berhasil) {
                display.clearDisplay();
                display.setCursor(0, 0);
                display.println("Verifikasi Berhasil.");
                display.display();
                delay(1000);
            } else {
                display.clearDisplay();
                display.setCursor(0, 0);
                display.println("Verifikasi Gagal!");
                display.display();
                delay(2000);
                return;
            }

            uint8_t selectedID = 1;
            unsigned long lastSwitchPress = 0;

            // === MODE PILIH ID SIDIK JARI ===
            while (true) {
              display.clearDisplay();
              display.setCursor(0, 0);
              display.println("Pilih Slot ID Sidik Jari:");
              display.print("ID: ");
              display.println(selectedID);
              display.println("Switch = Ganti");
              display.println("Exec = OK");
              display.display();

              if (digitalRead(switchPin) == LOW && millis() - lastSwitchPress > 300) {
                selectedID++;
                if (selectedID > 127) selectedID = 1;  // Batas maksimal tergantung sensor
                lastSwitchPress = millis();
              }

              if (digitalRead(execPin) == LOW) {
                delay(300); // debounce
                break;
              }
            }

            // === CEK APAKAH SLOT ID SUDAH TERISI ===
            uint8_t p = finger.loadModel(selectedID);
            if (p == FINGERPRINT_OK) {
              // Slot sudah terisi, minta konfirmasi
              display.clearDisplay();
              display.setCursor(0, 0);
              display.println("Slot sudah terpakai!");
              display.println("Switch = Batal");
              display.println("Exec = Timpa");
              display.display();

              while (true) {
                if (digitalRead(switchPin) == LOW) {
                  delay(300);
                  return; // Batalkan proses
                }
                if (digitalRead(execPin) == LOW) {
                  delay(300);
                  break; // Lanjut menimpa
                }
              }
            }

            // === MODE PENDAFTARAN SIDIK JARI ===
            display.clearDisplay();
            display.setCursor(0, 0);
            display.print("Mendaftarkan ID ");
            display.println(selectedID);
            display.display();

            if (enrollSingleFingerprint(selectedID)) {
              display.clearDisplay();
              display.setCursor(0, 0);
              display.println("Pendaftaran sukses!");
              display.display();
              delay(2000);
            } else {
              display.clearDisplay();
              display.setCursor(0, 0);
              display.println("Pendaftaran gagal!");
              display.display();
              delay(2000);
            }
          }
        }

        // Mode Pendaftaran NFC
        if (isRegisteringNFC) {
            if (digitalRead(execPin) == LOW && millis() - previousMillis >= interval) {
                previousMillis = millis();

            display.clearDisplay();
            display.setCursor(0, 0);
            display.println("Pilih Mode:");
            display.println("Tombol 1: NFC");
            display.println("Tombol 2: Fingerprint");
            display.display();

            bool verifikasi_berhasil = false;
            unsigned long startMillis = millis();
            const unsigned long timeout = 60000;  // 60 detik

            while (millis() - startMillis < timeout) {
                if (digitalRead(PIN_FINGER) == LOW) {
                  bool hasil = prosesSidikJari();
                  if (hasil) {
                    verifikasi_berhasil = true;
                    break;
                  }
                }

                if (digitalRead(PIN_NFC) == LOW) {
                    display.clearDisplay();
                    display.setCursor(0, 0);
                    display.println("Verifikasi NFC...");
                    display.display();

                    unsigned long waktuMulaiNFC = millis(); // Mulai stopwatch NFC

                    nfc.SAMConfig();
                    nfc.inListPassiveTarget();

                    unsigned long nfcStart = millis();
                    const unsigned long nfcTimeout = 5000;

                    bool sudahDiproses = false;

                    while (millis() - nfcStart < nfcTimeout) {
                        if (digitalRead(PIN_NFC) == HIGH) {
                            display.clearDisplay();
                            display.setCursor(0, 0);
                            display.println("Verifikasi NFC Dibatalkan");
                            display.display();
                            delay(2000);
                            sudahDiproses = true;
                            break;
                        }

                        uint8_t success;
                        uint8_t uid[7];
                        uint8_t uidLength;

                        success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength, 50);
                        if (success) {
                            String uidStr = "";
                            for (uint8_t i = 0; i < uidLength; i++) {
                                char hexStr[3];
                                sprintf(hexStr, "%02X", uid[i]);
                                uidStr += hexStr;
                            }

                            String nfcData = "";
                            for (int page = 4; page < 8; page++) {
                                uint8_t ndefBuffer[4];
                                if (nfc.ntag2xx_ReadPage(page, ndefBuffer)) {
                                    for (int i = 0; i < 4; i++) {
                                        char hexStr[3];
                                        sprintf(hexStr, "%02X", ndefBuffer[i]);
                                        nfcData += hexStr;
                                    }
                                }
                            }

                            float waktuVerifikasi = (millis() - waktuMulaiNFC) / 1000.0;

                            if (verifikasiKartu(nfcData.length() == 0 ? uidStr : nfcData)) {
                                display.clearDisplay();
                                display.setCursor(0, 0);
                                display.println("NFC Berhasil!");
                                display.print("Waktu: ");
                                display.print(waktuVerifikasi, 2);
                                display.println(" detik");
                                display.display();

                                verifikasi_berhasil = true;
                                sudahDiproses = true;
                                delay(2000);
                                break;
                            } else {
                                display.clearDisplay();
                                display.setCursor(0, 0);
                                display.println("NFC Gagal!");
                                display.print("Waktu: ");
                                display.print(waktuVerifikasi, 2);
                                display.println(" detik");
                                display.display();

                                sudahDiproses = true;
                                delay(2000);
                                break;
                            }
                        }

                        delay(50);
                    }

                    // Jika tidak berhasil menemukan kartu sampai timeout
                    if (!sudahDiproses) {
                        float waktuVerifikasi = (millis() - waktuMulaiNFC) / 1000.0;
                        display.clearDisplay();
                        display.setCursor(0, 0);
                        display.println("NFC Timeout!");
                        display.print("Waktu: ");
                        display.print(waktuVerifikasi, 2);
                        display.println(" detik");
                        display.display();
                        delay(2000);
                    }

                    nfc.SAMConfig();  // Reset NFC setelah selesai

                    if (verifikasi_berhasil) break;
                }
                delay(100);
            }

            if (verifikasi_berhasil) {
                display.clearDisplay();
                display.setCursor(0, 0);
                display.println("Verifikasi Berhasil.");
                display.display();
                delay(1000);
            } else {
                display.clearDisplay();
                display.setCursor(0, 0);
                display.println("Verifikasi Gagal!");
                display.display();
                delay(2000);
                return;
            }
          
            uint8_t selectedID = 0;
            unsigned long lastSwitchPress = 0;

            // === MODE PILIH SLOT ===
            while (true) {
                display.clearDisplay();
                display.setCursor(0, 0);
                display.println("Pilih Slot ID Kartu:");
                display.print("ID: ");
                display.println(selectedID);
                display.println("Switch = Ganti");
                display.println("Exec = OK");
                display.display();

                // Tombol Switch untuk ganti ID
                if (digitalRead(switchPin) == LOW && millis() - lastSwitchPress > 300) {
                    selectedID = (selectedID + 1) % 5;
                    lastSwitchPress = millis();
                }

                // Tombol Exec untuk konfirmasi
                if (digitalRead(execPin) == LOW) {
                    delay(300); // debounce
                    break; // Keluar dari loop pemilihan
                }
            }

            // === MODE SCAN NFC ===
            display.clearDisplay();
            display.setCursor(0, 0);
            display.println("Tempelkan kartu NFC...");
            display.display();

            uint8_t uid[7];
            uint8_t uidLength;
            String uidStr = "", nfcData = "";

            while (!nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength)) {
                if (millis() - startMillis > 15000) {
                    display.clearDisplay();
                    display.setCursor(0, 0);
                    display.println("Waktu habis!");
                    display.display();
                    delay(2000);
                    return;
                }
            }

            for (uint8_t i = 0; i < uidLength; i++) {
                char hexStr[3];
                sprintf(hexStr, "%02X", uid[i]);
                uidStr += hexStr;
            }

            for (int page = 4; page < 8; page++) {
                uint8_t ndefBuffer[4];
                if (nfc.ntag2xx_ReadPage(page, ndefBuffer)) {
                    for (int i = 0; i < 4; i++) {
                        char hexStr[3];
                        sprintf(hexStr, "%02X", ndefBuffer[i]);
                        nfcData += hexStr;
                    }
                }
            }

            daftarKartu(nfcData.length() == 0 ? uidStr : nfcData, selectedID);
        }
      }
    }

int verifyFingerprint() {
  uint8_t p = finger.getImage();
  if (p != FINGERPRINT_OK) return -1;

  p = finger.image2Tz();
  if (p != FINGERPRINT_OK) return -2;

  p = finger.fingerFastSearch();
  if (p != FINGERPRINT_OK) return -3;

  return 1;  // Sidik jari berhasil diverifikasi
}

bool prosesSidikJari() {
  unsigned long waktuMulai = millis();  // Mulai stopwatch

  display.clearDisplay();
  display.setCursor(0, 0);
  display.println("Verifikasi Sidik Jari...");
  display.display();

  uint8_t p = finger.getImage();
  if (p == FINGERPRINT_NOFINGER) {
    return false;
  }

  if (p != FINGERPRINT_OK) {
    float waktuTotal = (millis() - waktuMulai) / 1000.0;
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("Gagal Baca Gambar Jari");
    display.print("Waktu: ");
    display.print(waktuTotal, 2);
    display.println(" dtk");
    display.display();
    delay(2000);
    return false;
  }

  p = finger.image2Tz();
  if (p != FINGERPRINT_OK) {
    float waktuTotal = (millis() - waktuMulai) / 1000.0;
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("Gagal Proses Jari");
    display.print("Waktu: ");
    display.print(waktuTotal, 2);
    display.println(" dtk");
    display.display();
    delay(2000);
    return false;
  }

  p = finger.fingerSearch();
  float waktuTotal = (millis() - waktuMulai) / 1000.0;

  if (p == FINGERPRINT_OK) {
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("Verifikasi Berhasil.");
    display.print("Waktu: ");
    display.print(waktuTotal, 2);
    display.println(" dtk");
    display.display();
    delay(1000);
    return true;
  } else if (p == FINGERPRINT_NOTFOUND) {
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("Sidik Jari Tidak Dikenali!");
    display.print("Waktu: ");
    display.print(waktuTotal, 2);
    display.println(" dtk");
    display.display();
    delay(2000);
    return false;
  } else {
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("Error Saat Verifikasi");
    display.print("Waktu: ");
    display.print(waktuTotal, 2);
    display.println(" dtk");
    display.display();
    delay(2000);
    return false;
  }
}

bool enrollSingleFingerprint(uint8_t id) {
  unsigned long waktuMulai = millis();  // Mulai stopwatch

  int p = -1;
  unsigned long startTime = millis();

  while (p != FINGERPRINT_OK) {
    display.clearDisplay();
    display.setCursor(0, 0);
    display.print("Letakkan jari untuk ID ");
    display.print(id);
    display.display();
    p = finger.getImage();

    if (millis() - startTime > 200000) {  // Timeout 200 detik
      float waktuTotal = (millis() - waktuMulai) / 1000.0;
      display.clearDisplay();
      display.setCursor(0, 0);
      display.println("Timeout. Gagal.");
      display.print("Waktu: ");
      display.print(waktuTotal, 2);
      display.println(" dtk");
      display.display();
      return false;
    }
    delay(200);
  }

  p = finger.image2Tz(1);
  if (p != FINGERPRINT_OK) {
    float waktuTotal = (millis() - waktuMulai) / 1000.0;
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("Gagal konversi gambar.");
    display.print("Waktu: ");
    display.print(waktuTotal, 2);
    display.println(" dtk");
    display.display();
    return false;
  }

  display.clearDisplay();
  display.setCursor(0, 0);
  display.println("Angkat jari Anda.");
  display.display();
  delay(2000);

  while (p != FINGERPRINT_NOFINGER) {
    p = finger.getImage();
    delay(200);
  }

  display.clearDisplay();
  display.setCursor(0, 0);
  display.println("Letakkan jari lagi.");
  display.display();

  // Ambil gambar kedua
  startTime = millis();
  p = -1;
  while (p != FINGERPRINT_OK) {
    p = finger.getImage();
    if (millis() - startTime > 200000) {
      float waktuTotal = (millis() - waktuMulai) / 1000.0;
      display.clearDisplay();
      display.setCursor(0, 0);
      display.println("Timeout. Gagal.");
      display.print("Waktu: ");
      display.print(waktuTotal, 2);
      display.println(" dtk");
      display.display();
      return false;
    }
    delay(200);
  }

  p = finger.image2Tz(2);
  if (p != FINGERPRINT_OK) {
    float waktuTotal = (millis() - waktuMulai) / 1000.0;
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("Gagal konversi gambar 2.");
    display.print("Waktu: ");
    display.print(waktuTotal, 2);
    display.println(" dtk");
    display.display();
    return false;
  }

  p = finger.createModel();
  if (p != FINGERPRINT_OK) {
    float waktuTotal = (millis() - waktuMulai) / 1000.0;
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("Gagal membuat model.");
    display.print("Waktu: ");
    display.print(waktuTotal, 2);
    display.println(" dtk");
    display.display();
    return false;
  }

  p = finger.storeModel(id);
  float waktuTotal = (millis() - waktuMulai) / 1000.0;

  if (p != FINGERPRINT_OK) {
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("Gagal simpan model.");
    display.print("Waktu: ");
    display.print(waktuTotal, 2);
    display.println(" dtk");
    display.display();
    return false;
  }

  display.clearDisplay();
  display.setCursor(0, 0);
  display.println("Pendaftaran sukses!");
  display.print("ID: ");
  display.println(id);
  display.print("Waktu: ");
  display.print(waktuTotal, 2);
  display.println(" dtk");
  display.display();
  delay(2000);

  return true;
}

void writeEEPROM(uint16_t addr, uint8_t *data, uint8_t length) {
    for (uint8_t i = 0; i < length; i++) {
        Wire.beginTransmission(EEPROM_I2C_ADDR);
        Wire.write((int)(addr >> 8));   // MSB alamat
        Wire.write((int)(addr & 0xFF)); // LSB alamat
        Wire.write(data[i]);            // Tulis data
        Wire.endTransmission();
        delay(5);  // Tunggu EEPROM siap
        addr++;    // Geser alamat
    }
}

void readEEPROM(uint16_t addr, uint8_t *data, uint8_t length) {
    for (uint8_t i = 0; i < length; i++) {
        Wire.beginTransmission(EEPROM_I2C_ADDR);
        Wire.write((int)(addr >> 8));   // MSB alamat
        Wire.write((int)(addr & 0xFF)); // LSB alamat
        Wire.endTransmission();
        
        Wire.requestFrom(EEPROM_I2C_ADDR, 1);
        if (Wire.available()) {
            data[i] = Wire.read();
        } else {
            data[i] = 0xFF; // Default jika tidak ada data
        }
        addr++; // Geser alamat
    }
}

void daftarKartu(String data, uint8_t slotID) {
    unsigned long waktuMulai = millis();  // Mulai stopwatch

    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("Menyimpan Data...");
    display.display();
    delay(1000);

    // Ambil jumlah kartu
    uint8_t jumlahKartu;
    readEEPROM(0, &jumlahKartu, 1);

    if (slotID >= jumlahKartu) {
        jumlahKartu = slotID + 1; // Jika slot ID baru, perbaharui jumlah kartu
    }

    // === HAPUS DATA LAMA SLOT YANG DIPILIH ===
    String slotData[5]; // Array untuk menyimpan data kartu
    uint8_t newJumlah = 0;
    uint16_t addr = 1;
    
    bool isDataExist = false;

    for (int i = 0; i < jumlahKartu; i++) {
        uint8_t len;
        readEEPROM(addr, &len, 1);  // Baca panjang data
        addr++;

        String temp = "";
        for (int j = 0; j < len; j++) {
            uint8_t b;
            readEEPROM(addr++, &b, 1);
            temp += (char)b;
        }

        if (i != slotID) {
            slotData[newJumlah++] = temp;
        } else {
            if (!isDataExist) {
                slotData[slotID] = data;
                newJumlah = slotID + 1;
                isDataExist = true;
            }
        }
    }

    if (!isDataExist) {
        slotData[slotID] = data;
        newJumlah = slotID + 1;
    }

    // === TULIS ULANG KE EEPROM ===
    addr = 1;
    for (int i = 0; i < newJumlah; i++) {
        uint8_t len = slotData[i].length();
        writeEEPROM(addr++, &len, 1);
        for (int j = 0; j < len; j++) {
            uint8_t b = slotData[i][j];
            writeEEPROM(addr++, &b, 1);
        }
    }

    // Simpan jumlah kartu yang baru
    writeEEPROM(0, &newJumlah, 1);

    float waktuTotal = (millis() - waktuMulai) / 1000.0;  // Stopwatch selesai

    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("Data Tersimpan!");
    display.print("Waktu: ");
    display.print(waktuTotal, 2);
    display.println(" dtk");
    display.display();
    delay(2000);
}

bool verifikasiKartu(String data) {
    uint8_t jumlahKartu;
    readEEPROM(0, &jumlahKartu, 1);

    if (jumlahKartu == 0) {
        return false; // Tidak ada kartu
    }

    uint16_t addr = 1;

    for (int i = 0; i < jumlahKartu; i++) {
        uint8_t storedDataLength;
        readEEPROM(addr++, &storedDataLength, 1);

        if (storedDataLength != data.length()) {
            addr += storedDataLength; // Skip
            continue;
        }

        bool match = true;
        for (int j = 0; j < storedDataLength; j++) {
            uint8_t dataByte;
            readEEPROM(addr++, &dataByte, 1);
            if (dataByte != (uint8_t)data[j]) {
                match = false;
            }
        }

        if (match) {
            return true; // Kartu cocok
        }
    }

    return false; // Tidak ada yang cocok
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Fungsi untuk mendapatkan data valid berikutnya dari EEPROM secara acak
String getNextValidDataFromEEPROM() {
    int availableIndices[currentEntry]; 
    int count = 0;

    for (int i = 1; i < currentEntry; i++) {
        if (!readEntries[i]) {
            availableIndices[count++] = i;
        }
    }
    //Serial.print("Jumlah data yang belum terbaca: ");
    //Serial.println(count);

    if (count == 0) {
        resetReadEntries();
        return getNextValidDataFromEEPROM();
    }

    int randomIndex = availableIndices[random(0, count)];
    String data = readDataFromEEPROM(randomIndex);

    if (data.length() > 0) {
        readEntries[randomIndex] = true;
        EEPROM.put(sizeof(int), readEntries);
        saveReadIndexToInternalEEPROM(randomIndex); //bagian simpan status
        int address = DATA_START_ADDRESS + randomIndex * dataLength;
        //Serial.print("Alamat EEPROM: ");
        Serial.println(address);
        return data;
    }

    return getNextValidDataFromEEPROM();
}

// Fungsi untuk mereset array pembacaan//////////////////////////////////////////////////////////
void resetReadEntries() {
    for (int i = 1; i < currentEntry; i++) {
        readEntries[i] = false;
    }

    currentReadIndex = 1;  // Reset ke indeks awal
    EEPROM.put(sizeof(int), readEntries);  // Simpan status reset ke EEPROM
    saveReadIndexToInternalEEPROM(currentReadIndex);
}

// Fungsi untuk membaca data dari EEPROM///////////////////////////////////////////////////////
String readDataFromEEPROM(int index) {
    int startAddress = sizeof(int) + index * dataLength;
    String data = "";

    // Hapus atau nonaktifkan log berikut jika tidak diperlukan
    // Serial.print(F("Membaca dari alamat EEPROM: "));
    // Serial.println(startAddress);

    for (int i = 0; i < dataLength; i++) {
        char ch = EEPROM.read(startAddress + i);
        if (ch == '\0') break;  // Berhenti jika mencapai karakter null
        data += ch;
    }

    //Serial.print(F("Data yang dibaca: "));  // Nonaktifkan log ini
    //Serial.println(data);

    data.trim();  // Hapus spasi di awal/akhir string
    return data;
}

// Fungsi untuk menyimpan data ke EEPROM/////////////////////////////////////////////////
bool saveDataToEEPROM(String data) {
  if (currentEntry < maxEntries) {
    int startAddress = sizeof(int) + currentEntry * dataLength;
    for (int i = 0; i < data.length(); i++) {
      EEPROM.write(startAddress + i, data[i]);
    }
    EEPROM.write(startAddress + data.length(), '\0');

    currentEntry++;
    EEPROM.put(0, currentEntry);

    return true; // Berhasil menyimpan
  } else {
    return false; // EEPROM penuh
  }
}

// Fungsi untuk menyimpan indeks pembacaan terakhir ke EEPROM internal////////////////
void saveReadIndexToInternalEEPROM(int index) {
  EEPROM.put(sizeof(int) + sizeof(readEntries) + sizeof(readCount), index);
}

// Fungsi untuk membaca indeks pembacaan terakhir dari EEPROM internal//////////////
int readReadIndexFromInternalEEPROM() {
  int index;
  EEPROM.get(sizeof(int) + sizeof(readEntries) + sizeof(readCount), index);
  return index;
}

// Fungsi konversi HEX ke byte array///////////////////////////////////////////////
void hexToBytes(const char* hex, byte* bytes, int length) {
  for (int i = 0; i < length; i++) {
    sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
  }
}

// Fungsi hapus padding PKCS7///////////////////////////////////////////////////
void removePadding(byte* data, int& length) {
  int pad = data[length - 1];
  if (pad > 0 && pad <= 16) {
    length -= pad;
    data[length] = '\0'; // Null terminator
  }
}

//Fungsi dekripsi///////////////////////////////////////////////////////////////
void decryptAES(String hexCiphertext, String &plainText) {
  byte ciphertext[16];
  byte decrypted[16];

  // Konversi HEX ke byte array
  hexToBytes(hexCiphertext.c_str(), ciphertext, 16);

  // Dekripsi AES
  aes128.setKey(key, 16);
  aes128.decryptBlock(decrypted, ciphertext);

  // Hapus padding
  int decrypted_length = 16;
  removePadding(decrypted, decrypted_length);

  // Konversi hasil dekripsi ke string
  plainText = String((char*)decrypted);
}