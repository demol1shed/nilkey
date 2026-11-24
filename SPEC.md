# nilkey — Zero-Knowledge CLI Password Vault Teknik Spesifikasyonu (`SPEC.md`)

**Proje Adı:** `nilkey`  
**Sürüm:** 1.0 (V1 Tasarım Sözleşmesi)  
**Hedef Platform:** Linux (POSIX)  
**Dil ve Derleme Yığını:** Modern C++ (C++20), `libsodium` (>= 1.0.18), `CMake`  
**Dağıtım Modeli:** Açık Kaynak (Tek harici bağımlılık: `libsodium`)

---

## 1. Proje Özeti ve Temel İlkeler

`nilkey`, kullanıcı parolalarını yerel diskte saklanan tek bir şifreli `.vault` dosyasında yöneten, komut satırı (CLI) tabanlı, **sıfır bilgi (Zero-Knowledge)** mimarisine sahip açık kaynak bir parola kasasıdır.

### Değiştirilemez İlkeler
1. **Sıfır Bilgi (Zero-Knowledge):** Ana parola (master password) veya parolanın özeti (hash) hiçbir yerde saklanmaz. Doğrulama yalnızca AEAD şifre çözme etiketinin (Auth Tag) doğrulanmasıyla yapılır.
2. **Kriptografi Altın Kuralı:** Hiçbir kriptografik primitif sıfırdan yazılmaz. Tüm anahtar türetme, şifreleme, rastgele sayı üretimi, özetleme ve sabit zamanlı karşılaştırma işlemleri denetlenmiş `libsodium` API'leri üzerinden yürütülür.
3. **Tek Harici Bağımlılık (`libsodium`):** Kasa içi serileştirme, hata yönetimi, CLI ayrıştırma ve birim testler harici kütüphane eklenmeden (JSON, Catch2, GTest vb. olmadan) yazılır.
4. **Denetlenebilir ve İstisnasız C++20:** Her güvenlik kritik satır insan tarafından okunabilir, sade, RAII tabanlı ve C++ istisnaları kapalı (`-fno-exceptions -fno-rtti`) şekilde geliştirilir.

---

## 2. Tehdit Modeli (Threat Model)

### 2.1 Kapsam İçi (Korunan Senaryolar)
* **Çalınan Kasa Dosyası (Offline Brute-Force):** Ele geçirilen `.vault` dosyasına karşı GPU/ASIC tabanlı çevrimdışı parola kırma girişimleri (`Argon2id` + benzersiz salt).
* **Dosya Manipülasyonu (Tampering / Bit-Flipping / Downgrade):** Başlık (header) veya şifreli yük (ciphertext) üzerindeki tek bitlik değişiklikler ve KDF parametrelerini düşürme girişimleri (66 byte'lık başlığın tamamı `AAD` olarak doğrulanır).
* **Swap ve Core Dump Sızıntısı:** Açık parolaların veya anahtarların RAM'den diskteki swap alanına yazılması ya da çökme anında core dump dosyasına düşmesi.
* **Kalıntı Bellek (Post-Use Memory):** İşlem sonrası serbest bırakılmış fakat sıfırlanmamış bellek bloklarından hassas verilerin okunması.
* **Pano (Clipboard) Sızıntısı:** Kopyalanan şifrenin sistem panosunda uzun süre kalması.
* **Kesinti Kaynaklı Bozulma (Crash Corruption):** Kasa kaydedilirken elektrik kesintisi veya süreç sonlanması nedeniyle dosyanın yarım kalması.

### 2.2 Kapsam Dışı (Korunmayan Senaryolar)
* İşletim sisteminde zaten aktif olan rootkit, kernel-level keylogger veya bellek okuyan root yetkili zararlı yazılımlar.
* Kullanıcının zayıf veya kolay tahmin edilebilir bir ana parola seçmesi.
* Fiziksel ekran gözetleme (shoulder surfing).
* Sistem hazırda bekletme (hibernation / suspend-to-disk) moduna geçtiğinde çekirdeğin tüm RAM içeriğini diske yazması (kullanıcıya şifreli disk/swap önerilir; `nilkey doctor` etkin swap alanlarını sayar ve hibernasyon uyarısı verir, ancak swap'ın şifreli olup olmadığına ve hibernasyon yapılandırmasına bakmaz; bkz. §9.4).

---

## 3. Teknoloji Yığını, Hata Yönetimi ve Derleme Kapıları

* **Dil Standardı:** C++20 (`CMAKE_CXX_STANDARD 20`, `CMAKE_CXX_STANDARD_REQUIRED ON`, `CMAKE_CXX_EXTENSIONS OFF`).
* **Tek Harici Bağımlılık:** `libsodium` (>= 1.0.18; Argon2id, XChaCha20-Poly1305-IETF ve `sodium_stackzero` desteği için).
* **Hata Yönetimi Sözleşmesi:**
  * Tüm hedefler (testler dahil) `-fno-exceptions -fno-rtti` ile derlenir; kod tabanında `try`, `catch`, `throw` kullanılmaz.
  * Sıfır bağımlılıklı, `std::variant` tabanlı ve `[[nodiscard]]` işaretli `nilkey::Result<T, Error>` (ve değer döndürmeyen işlemler için `nilkey::Status`) kullanılır. Değere erişim `std::get_if` ile yapılır; `std::get` kullanılmaz (`-fno-exceptions` altında yanlış alternatifte `abort` eder), yanlış erişim açıkça `std::abort()` ile sonlanır.
  * `Error` yapısı yalnızca yapısal `ErrorCode` (`enum class`) ve sabit statik açıklama içerir; hata nesnelerine asla parola, anahtar veya açık veri parçası yazılmaz.
* **Test Çatısı:** `tests/test_framework.hpp` (tek dosyalık, harici bağımlılıksız hafif test makroları) + CMake `CTest`. Çatı `-fno-exceptions` uyumlu, `return` tabanlı doğrulama makroları kullanır; hata çıktısına değer basmaz (yalnızca ifade metni ve `dosya:satır`); sır içeren baytları `sodium_memcmp` tabanlı makroyla karşılaştırır (bu nedenle test hedefleri de `libsodium`'a bağlanır).
* **Zorunlu Derleyici Bayrakları:** `-Wall -Wextra -Werror -Wpedantic -Wconversion -Wshadow -fno-exceptions -fno-rtti`. `-Werror`, paketleyicilerin yeni derleyici sürümlerinde kırılmaması için `NILKEY_WERROR` CMake seçeneğiyle (varsayılan `ON`) kapatılabilir; geliştirme ve CI derlemeleri `ON` kalır.
* **Sanitizer Kapısı (Debug / Test):** `-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all` (ASan + UBSan) zorunludur; `-fno-sanitize-recover=all` olmadan UBSan bulguyu yazıp çıkış kodu 0 ile devam eder. Tüm testler sıfır bulguyla geçmelidir. CTest ortamı `ASAN_OPTIONS` / `UBSAN_OPTIONS` değerlerini CMake'ten alır.
* **Sertleştirme Bayrakları (Release):** `-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE` ve linker tarafında `-Wl,-z,relro,-z,now`.

### Önerilen Açık Kaynak Dizin Yapısı
```text
nilkey/
├── CMakeLists.txt
├── .gitignore
├── LICENSE
├── README.md
├── SPEC.md
├── CLAUDE.md
├── include/nilkey/
│   ├── error.hpp
│   ├── result.hpp
│   ├── secure_buffer.hpp
│   ├── hardening.hpp
│   ├── crypto.hpp
│   ├── vault_format.hpp
│   ├── atomic_file.hpp
│   ├── tlv.hpp
│   ├── vault.hpp
│   ├── store.hpp
│   ├── fd_io.hpp
│   ├── display.hpp
│   ├── passgen.hpp
│   ├── terminal.hpp
│   ├── args.hpp
│   ├── cli.hpp
│   ├── commands.hpp
│   ├── clipboard.hpp
│   └── doctor.hpp
├── src/
│   ├── main.cpp
│   └── ... (karşılık gelen .cpp dosyaları)
└── tests/
    ├── test_framework.hpp
    └── test_*.cpp
```

---

## 4. Kriptografik Boru Hattı

### 4.1 Anahtar Türetme (KDF) — Argon2id
* **Algoritma:** `Argon2id` (RFC 9106 / `crypto_pwhash_ALG_ARGON2ID13`).
* **Parola Girdi Kuralı (OWASP Uyumlu):** Ana parolalar tüm UTF-8 karakterlerini (uluslararası alfabeler, emoji) ve gömülü NUL (`\0`) baytlarını destekleyecek şekilde uzunluk bilgisini taşıyan tamponlar (`SecureBuffer` / `std::span<const std::byte>`) üzerinden işlenir; `strlen` veya C-string sonlandırması kullanılmaz.
* **Tuz (Salt):** `16 byte` (`crypto_pwhash_SALTBYTES`), `randombytes_buf` ile yalnızca `init` ve `passwd` işlemlerinde üretilir.
* **Çıktı Anahtarı:** `32 byte` (256 bit).
* **Varsayılan Maliyet Parametreleri:**
  * `mem_kib = 65536` (64 MiB — RFC 9106'nın bellek kısıtlı sistem önerisindeki bellek ve geçiş değerleriyle aynı, OWASP minimumlarının üzerinde. *Not:* RFC'nin bu önerisi `p = 4` kullanır; `libsodium` `p = 1` sabitlediği için V1 bu parametre kümesiyle birebir aynı değildir.)
  * `iterations = 3` (`opslimit = 3`).
  * `parallelism = 1` (**`libsodium` API Notu:** `libsodium`'un `crypto_pwhash()` API'si dahili olarak `p = 1` ile çalışır ve dışarıdan paralellik parametresi almaz. İleriye dönük format uyumluluğu için başlıkta 4 byte `kdf_parallelism` alanı korunur; V1 yazarken `1` yazar, okurken `kdf_parallelism != 1` ise desteklenmeyen parametre hatası döndürür).
* **Parametre Sınır Denetimi (Downgrade & OOM Koruması):**
  * **Alt sınır (Downgrade koruması):** Okunan kasa dosyasında `mem_kib < 19456` (19 MiB) veya `iterations < 2` ise reddedilir *(yalnızca izole birim testlerinde derleme zamanı `NILKEY_ALLOW_TEST_KDF` bayrağıyla daha düşük maliyet kullanılabilir)*.
  * **Üst sınır (OOM/DoS koruması):** `mem_kib > 2097152` (2 GiB) veya `iterations > 20` ise bellek ayırmadan önce reddedilir.

### 4.2 Kimlik Doğrulamalı Şifreleme (AEAD) — XChaCha20-Poly1305
* **Algoritma:** `XChaCha20-Poly1305-IETF` birleşik mod (`crypto_aead_xchacha20poly1305_ietf_encrypt` / `_decrypt`).
* **Anahtar Boyutu:** `32 byte` (256 bit).
* **Nonce Boyutu:** `24 byte` (192 bit), her kaydetme işleminde `randombytes_buf` ile yeniden üretilir. Aynı `(key, nonce)` çifti asla tekrar kullanılmaz.
* **Auth Tag Boyutu:** `16 byte` (128 bit, ciphertext sonuna eklenir).
* **AAD (Additional Authenticated Data):** 66 byte'lık sabit dosya başlığının tamamı (`offset 0..65`).
* **Maksimum Yük Boyutu:** Şifreli yük boyutu en fazla `16 MiB` (`16 * 1024 * 1024` byte) + `16 byte` Auth Tag ile sınırlandırılır; bu sınırı aşan dosyalar bellek ayrılmadan reddedilir.

---

## 5. İkili (Binary) Kasa Dosyası Formatı (V1)

Tüm çok baytlı tam sayılar **Little-Endian (LE)** formatında kodlanır.

### 5.1 Sabit Başlık (66 Byte — Tamamı AAD Olarak Doğrulanır)

| Ofset (Byte) | Alan | Boyut | Tip / Değer | Açıklama |
| :--- | :--- | :--- | :--- | :--- |
| `0..7` | `magic` | 8 byte | ASCII sabit | `"NILKEY1\0"` (`4E 49 4C 4B 45 59 31 00`) |
| `8..9` | `version` | 2 byte | `uint16_t` (LE) | Format sürümü; V1 için `1` |
| `10..13` | `kdf_mem_kib` | 4 byte | `uint32_t` (LE) | Argon2id bellek maliyeti (KiB) |
| `14..17` | `kdf_iterations` | 4 byte | `uint32_t` (LE) | Argon2id geçiş (iterasyon) sayısı |
| `18..21` | `kdf_parallelism` | 4 byte | `uint32_t` (LE) | Argon2id paralellik (`libsodium` V1 için `1`) |
| `22..37` | `salt` | 16 byte | Ham baytlar | Argon2id tuzu (`init` / `passwd`'de yenilenir) |
| `38..61` | `nonce` | 24 byte | Ham baytlar | XChaCha20-Poly1305 nonce (her kayıtta yenilenir) |
| `62..65` | `payload_len` | 4 byte | `uint32_t` (LE) | `Ciphertext + 16B Auth Tag` toplam bayt uzunluğu |

### 5.2 Şifreli Yük (`offset 66..end`)
* `payload_len >= 16` (en az 16 byte Poly1305 etiketi).
* `payload_len <= (16 * 1024 * 1024) + 16`.
* Dosyanın toplam boyutu **kesin olarak** `66 + payload_len` değerine eşit olmalıdır; kesilmiş (truncated) veya fazladan (trailing) bayt içeren dosyalar reddedilir.

---

## 6. Şifreli Yük İç Formatı (Bağımlılıksız İkili TLV)

Şifre çözme başarılı olduktan sonra elde edilen açık metin bellekte aşağıdaki çerçeve yapısını takip eder:

### 6.1 Üst Düzey Zarf
```text
[record_count: uint32_t LE]
[record_0_len: uint32_t LE][record_0_tlv_bytes...]
[record_1_len: uint32_t LE][record_1_tlv_bytes...]
...
```

### 6.2 Alan (Field) TLV Yapısı
Her kayıt ardışık TLV alanlarından oluşur:
```text
[type: uint8_t (1B)][length: uint32_t LE (4B)][value: length byte]
```

| Tip Kodu | Alan Adı | Zorunlu mu? | Veri Formatı |
| :--- | :--- | :--- | :--- |
| `0x01` | `name` | Evet (benzersiz) | UTF-8 metin (boş olamaz) |
| `0x02` | `username` | Hayır | UTF-8 metin |
| `0x03` | `password` | Evet | Ham bayt dizisi / UTF-8 (güvenli bellekte işlenir) |
| `0x04` | `url` | Hayır | UTF-8 metin |
| `0x05` | `notes` | Hayır | UTF-8 metin (çok satırlı olabilir) |
| `0x06` | `created_at` | Evet | 8 byte `int64_t` LE (Unix zaman damgası, sn) |
| `0x07` | `updated_at` | Evet | 8 byte `int64_t` LE (Unix zaman damgası, sn) |

### 6.3 Ayrıştırıcı Güvenlik Kuralları
* Her okuma öncesinde tamsayı taşması (integer overflow) ve kalan tampon boyutu (`remaining >= length`) doğrulanır.
* Tanınmayan `type` kodları, `length` değeri kayıt sınırları içindeyse güvenle atlanır (ileriye dönük uyumluluk).
* Aynı kayıtta yinelenen alan kodu veya kasa genelinde yinelenen `name` tespit edilirse dosya tutarsız kabul edilip reddedilir.
* Kayıt/alan sayısı ve alan uzunlukları için makul üst sınırlar uygulanır (sayılar §6.4'te).

### 6.4 Faz 3 Uygulama Kararları

**Uygulama kararları** (`include/nilkey/tlv.hpp`, `vault.hpp`):
* **Limitler:** en fazla 100.000 kayıt, kayıt başına en fazla 64 alan, `name` en fazla 1024 bayt. Toplam yük 16 MiB'ı aşamaz (4 baytlık `record_count` ve her kaydın 4 baytlık `record_len` öneki dahil).
* **Yinelenen alan kodu** bilinmeyen tipler için de reddedilir. Kayıtlar artan tip sırasında yazılır; ayrıştırıcı sıra aramaz.
* **İsteğe bağlı alanlar:** yok ile boş aynıdır; boş `username`/`url`/`notes` yazılmaz. `password` alanı zorunludur ama boş olabilir; boş parolanın engellenmesi CLI'ya aittir (Faz 4'te yapıldı: `ReadSecret` boş satırı reddeder, bkz. §9.4).
* **UTF-8:** `name`/`username`/`url`/`notes` hem yazarken hem ayrıştırırken katı RFC 3629 doğrulamasından geçer (overlong, surrogate ve U+10FFFF üstü reddedilir, NUL geçerlidir). `password` ham bayttır. `name` karşılaştırması bayt bayttır, Unicode normalizasyonu yoktur (NFC ve NFD ayrı adlardır).
* **Bilinmeyen alanlar:** dokunulmayan kayıtlar bayt bayt kopyalanır; `Update` eski kaydın bilinmeyen alanlarını yeni kayda taşır, böylece daha yeni bir sürümün yazdığı veri kaybolmaz. Taşıma sonrası alan sayısı 64'ü aşacaksa `kOutOfRange` döner (yazılan kayıt geri okunamazdı).
* **`Vault` modeli:** açık yük tek bir `SecureBuffer`'da, kayıt konumları gizli olmayan bir indekste tutulur. Her değişiklik yeni yükü tahsisten önce boyutlandırır, yazar, yeniden ayrıştırır ve ancak ondan sonra takas eder; hata yolunda kasa değişmez. Zaman damgası dışarıdan (`now`) verilir. `Update` tüm kullanıcı alanlarını değiştirir (yeniden adlandırma dahil), `created_at` korunur. Açık bir `VaultReader` varken değişiklik `kInvalidArgument` döner.

**Bilinen sınırlamalar:**
* **~2× kilitli bellek:** değişiklik sırasında eski ve yeni yük aynı anda bellektedir. Tipik 8 MiB `RLIMIT_MEMLOCK` değerinde yaklaşık 4 MiB üstü bir kasa açılabilir ama değiştirilemez; politika fail-closed kalır (§7.3).
* **Doğrusal arama:** `Find` doğrusaldır ve her değişiklik O(n)'dir; 100.000 kayıtla bile pratiktir.
* **Katı UTF-8 ve kilitlenme:** ayrıştırmadaki katı doğrulama, başka bir yazardan gelen tek bir bozuk alanın tüm kasayı açılmaz kılmasına yol açar.
* **Saat ve kilit:** `Vault` saat okumaz ve dosya kilidi tutmaz (bkz. §8).

---

## 7. Bellek Güvenliği ve Linux İşletim Sistemi Sertleştirmesi

### 7.1 Süreç Başlangıç Sertleştirmesi (`main` girişi)
Uygulama herhangi bir kasa veya parola verisini okumadan önce sırasıyla şunları çalıştırır:
1. `sodium_init()` çağrılır (`< 0` ise derhal çıkış).
2. `prctl(PR_SET_DUMPABLE, 0)` ile core dump ve yetkisiz `ptrace` bağlantıları kapatılır.
3. `setrlimit(RLIMIT_CORE, {0, 0})` ile core dosya boyutu sıfırlanır.
4. `umask(0077)` ile yeni oluşturulan tüm dosyaların yalnızca kullanıcıya özel olması garanti altına alınır.

### 7.2 RAII Güvenli Bellek Tamponu (`SecureBuffer`)
* **Kopyalama Yasağı:** `SecureBuffer(const SecureBuffer&) = delete` ve `operator=(const SecureBuffer&) = delete`. Yalnızca sahiplik devri (move semantics) desteklenir.
* **Korumalı Bellek Ayırma:** `sodium_malloc(size)` kullanılır (guard pages + canary + `MADV_DONTDUMP`).
* **Bitişik Ayırma Prensibi:** `sodium_malloc()` her çağrıda fazladan 3-4 sanal bellek sayfası tükettiğinden her küçük alan için ayrı ayrı çağrılmaz; anahtar ve açık TLV tamponları az sayıda bitişik blok halinde ayrılır.
* **Erişim Koruması:** Kullanılmadığı anlarda `sodium_mprotect_noaccess()` uygulanır; okuma/yazma yalnızca kapsamlı RAII bekçileri (`ScopedReadGuard`, `ScopedWriteGuard`) ile geçici olarak açılır.
* **Yıkıcı Temizliği:** `sodium_free()` ile canary kontrolü, güvenli sıfırlama, kilit açma ve serbest bırakma otomatik gerçekleştirilir.
* **Yığın (Stack) Hijyeni:** Açık parolalar, anahtarlar ve açık TLV verileri asla `std::string` veya standart `std::vector` içinde tutulmaz. Hassas işlem bloklarından sonra yerel kalıntılar `sodium_memzero()` ve `sodium_stackzero(4096)` ile temizlenir.

### 7.3 Hibrit `RLIMIT_MEMLOCK` Hata Politikası
`sodium_malloc()` kilitleme başarısız olduğunda sessizce kilitlenmemiş bellek döndürebildiğinden, her hassas ayırma sonrasında `sodium_mlock()` dönüş değeri açıkça kontrol edilir:
* **Varsayılan Mod (Katı / Fail-Closed):** `sodium_mlock()` `-1` (`ENOMEM` / `EPERM`) döndürürse işlem derhal durdurulur, hassas tampon serbest bırakılır ve `stderr`'e `RLIMIT_MEMLOCK` limitinin yetersiz olduğunu açıklayan, kullanıcıyı `nilkey doctor` komutuna (ve `ulimit -l` kontrolüne) yönlendiren net bir hata basılır.
* **Bilinçli Geçersiz Kılma (`--allow-unlocked-memory`):** Kullanıcı bu global bayrağı açıkça verirse, `stderr`'e belleğin swap dışına kilitlenemediğine dair görünür bir uyarı yazılarak çalışmaya devam edilir.

**Bilinen Sınırlama (Argon2 Çalışma Belleği):** `libsodium` Argon2id çalışma belleğini (`mem_kib`, varsayılan 64 MiB) kendi içinde ayırır ve en-iyi-çaba `mlock` dener; başarısızlığı yutar. Bu bellek son anahtarı üreten blokları içerdiğinden, yukarıdaki fail-closed politikası bu alanı **kapsamaz**. Azaltım: `nilkey doctor`, `RLIMIT_MEMLOCK` değerinin `mem_kib` için yeterli olup olmadığını raporlar; **Faz 2 kararı:** `NewVaultKey` ve `DeriveVaultKey`, `RLIMIT_MEMLOCK` değeri `mem_kib` baytından küçükse `stderr`'e uyarı yazar ve devam eder; hata dönmez ve `--allow-unlocked-memory` bayrağından bağımsızdır. Gerekçe: anahtarın kendisi zaten fail-closed `SecureBuffer` içindedir; bu ön kontrol fail-closed olsaydı varsayılan 64 MiB ile tipik 8 MiB limitli sistemlerde `nilkey` kullanılamaz olurdu. Ayrıca 16 MiB'a kadar yük, tipik 8 MiB `RLIMIT_MEMLOCK` değerinde fail-closed modda açılamayabilir. Değişiklikler (ekle/güncelle/sil) eski ve yeni yükü aynı anda tuttuğundan bu sınır yaklaşık yarıya iner (§6.4).

### 7.4 Faz 1 Uygulama Kararları ve Bilinen Sınırlamalar

**Uygulama kararları** (`include/nilkey/secure_buffer.hpp`, `hardening.hpp`):
* Kilit politikası global değil, `SecureBuffer::Create(size, MemlockPolicy)` parametresidir; `--allow-unlocked-memory` bayrağını CLI (Faz 4) buraya bağlar.
* Bir tampon üzerinde aynı anda yalnızca bir guard açık olabilir; ikinci `Open()` `kInvalidArgument` döner (referans sayımı yok).
* Guard açıkken tamponu taşımak (move) `abort()` eder; guard taşınmış tampona işaret etmiş olurdu.
* Guard, tamponu yeniden `PROT_NONE` yapamazsa `abort()` eder; devam etmek sırrı okunabilir bırakırdı.

**Bilinen sınırlamalar:**
* **Sanitizer altında kilit hatası simüle edilemez:** ASan/UBSan `mlock()` çağrısını yakalar ve her zaman başarı döndürür. Bu yüzden §10 madde 7'nin kilit politikası testi (`tests/test_memlock_policy.cpp`) yalnızca sanitizer kapalıyken kaydedilir ve CI'ın release profilinde koşar. Bu, "tüm testler sanitizer altında çalışır" kuralının bilinçli bir istisnasıdır.
* **Root / `CAP_IPC_LOCK`:** Bu yetkiyle `RLIMIT_MEMLOCK` yok sayılır; kilit politikası testi `SKIP` yazıp yeşil geçer.
* **Test edilmeyenler:** `mprotect` ihlali (SIGSEGV) ve canary bozulması (ASan altında sinyal davranışı kırılgan); `HardenProcess()` içindeki `prctl`/`setrlimit` hata yolları (başarısız kılınamaz).

**Sonraki fazlara bırakılanlar:**
* `sodium_stackzero` çağrısı parola okuma akışında: Faz 4'te yapıldı (`ReadSecret` sonunda çağrılır). KDF ve şifre çözme akışlarında Faz 2'de eklendi (§7.5).
* `main()` içindeki sertleştirme hata dalı: Faz 4'te değişmedi; hata iletisini yazıp çıkış kodu 1 verir, yeniden düzenleme gerekmedi.

### 7.5 Faz 2 Uygulama Kararları

* `sodium_stackzero(4096)`, anahtar türetme (`DeriveKey`) ve şifre çözme (`Open`) başarıyla tamamlandığında çağrılır; hata dönüş yollarında çağrılmaz. *(Faz 4, dış inceleme düzeltmesi: başarısız `crypto_pwhash` ve kimlik doğrulama hatası yollarında da çağrılır; bkz. §9.4.)*
* `Seal` her çağrıda yeni rastgele nonce üretir; aynı (anahtar, nonce) çifti hiç yeniden kullanılmaz.

---

## 8. Atomik Dosya Kaydı ve İzin Politikası

Kasa dosyası her zaman `0600` (yalnızca sahip okuma/yazma) izinleriyle tutulur.

### Atomik Yazma Akışı
1. Hedef `.vault` dosyasıyla **aynı dizinde** benzersiz bir geçici dosya oluşturulur (`O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW`, mod `0600`).
2. Tüm başlık ve şifreli yük (kısmi yazma ve `EINTR` durumları işlenerek) dosyaya yazılır.
3. `fsync(temp_fd)` ile verinin kalıcı depolamaya indirildiği doğrulanır ve `close(temp_fd)` dönüş değeri kontrol edilir.
4. `rename(temp_path, vault_path)` ile eski dosya atomik olarak yenisiyle değiştirilir.
5. Üst dizin (`O_RDONLY | O_DIRECTORY`) açılır, `fsync(dir_fd)` çağrılır ve kapatılır.
6. `rename` öncesinde herhangi bir hata oluşursa geçici dosya `unlink` ile silinir ve mevcut kasa dosyasına hiç dokunulmaz.

**Faz 2 Kararları:**
* **Symlink:** Kasa yolu bir symlink ise yazma ve okuma `kSymlinkRejected` ile reddedilir (`lstat` ile yazmadan önce, `O_NOFOLLOW` ile okurken). Symlink izlenmez, `realpath` ile çözülmez.
* **Eşzamanlı yazma (bilinen sınırlama):** `atomic_file` katmanı dosya kilidi kullanmaz; iki `nilkey` süreci aynı kasayı aynı anda okuyup değiştirirse son yazan kazanır. Kilit (`flock`), okuma-değiştir-yaz döngüsünü sahiplenen üst katmanda (Faz 4, CLI) ele alınır. *(Faz 4: kilit `VaultLock` (`<vault>.lock` üzerinde `flock`) ile komut katmanında ele alındı; bkz. §9.4.)*
* **Okuma:** `ReadVaultFile` yalnızca düzenli dosyaları kabul eder ve `66 + 16 MiB + 16 B` üstündeki dosyaları bellek ayırmadan reddeder; başlık/boyut tutarlılığı `OpenWithPassword` içinde doğrulanır.
* **Dizin `fsync` hatası:** `rename` sonrası dizin `fsync` başarısız olursa `kIoError` döner, ancak yeni dosya yerindedir.

---

## 9. CLI Arayüzü ve Pano (Clipboard) Politikası

### 9.1 Global Bayraklar
* `--vault <path>`: Hedef kasa dosyası yolu (varsayılan: `$NILKEY_PATH` veya `~/.local/share/nilkey/default.vault`).
* `--allow-unlocked-memory`: Hibrit bellek kilitleme politikasında bilinçli geçersiz kılma.
* `--help`, `--version`: Kullanım ve sürüm bilgisi.

### 9.2 Alt Komutlar

| Komut | İşlev | Güvenlik Kuralı |
| :--- | :--- | :--- |
| `nilkey init` | Yeni kasa dosyası oluşturur | Ana parolayı iki kez etkileşimli alır, `0600` izinle atomik kaydeder. |
| `nilkey add <name>` | Yeni kayıt ekler | Parolayı echo kapalı terminalden okur veya `--generate` ile CSPRNG üzerinden üretir. |
| `nilkey get <name>` | Kaydı getirir | Varsayılan olarak `stdout`'a basmaz; panoya kopyalar ve 15 sn sonra temizler (`--print` ile açık yazdırma, `--timeout <sn>` ile süre ayarı). |
| `nilkey list` | Kayıt adlarını listeler | Parolaları yazdırma akışına sokmaz; yalnızca `name` (ve opsiyonel `username` / `updated_at`) gösterir. Terminalde başlıklı ve hizalı, boru/dosyada sekmeyle ayrılmış (§9.4). |
| `nilkey update <name>` | Mevcut kaydı günceller | Yeni 24 byte nonce ile yeniden şifreler ve atomik kaydeder. |
| `nilkey delete <name>` | Kaydı siler | Etkileşimli onay ister (`--yes` ile atlanabilir), yeni nonce ile atomik kaydeder. |
| `nilkey generate` | Kriptografik parola üretir | `randombytes_uniform` ile önyargısız (unbiased) karakter seçimi yapar; uzunluk ve karakter seti bayraklarını destekler. |
| `nilkey passwd` | Ana parolayı değiştirir | Mevcut parolayı doğrular, **yeni 16 byte salt** ve **yeni 24 byte nonce** ile tüm kasayı yeniden şifreleyip atomik kaydeder. |
| `nilkey doctor` | Güvenlik ve ortam denetimi | Dosya izinleri (`0600`), dizin izinleri, `RLIMIT_MEMLOCK`, `PR_SET_DUMPABLE` / `RLIMIT_CORE`, `/proc/swaps` durumu ve pano aracını raporlar. |

### 9.3 Terminal Parola Okuma ve Pano Güvenliği
* **CLI Argüman Yasağı:** Ana parola ve kayıt şifreleri asla komut satırı argümanı olarak kabul edilmez (`ps` ve kabuk geçmişi sızıntısını önlemek için).
* **Echo Kapatma:** Etkileşimli giriş `/dev/tty` üzerinden `termios` ile `ECHO` bayrağı kapatılarak doğrudan `SecureBuffer` içine alınır; terminal ayarları RAII bekçisiyle hata veya sinyal durumlarında bile eski haline döndürülür.
* **Pano Aracı Tespiti:** `WAYLAND_DISPLAY` tanımlıysa `wl-copy`/`wl-paste`, aksi halde `DISPLAY` altında `xclip` veya `xsel` kullanılır.
* **`fork()` Güvenliği ve 15 Saniye Akıllı Temizleme:**
  * `mlock(2)` kilitleri `fork()` sonrası alt sürece aktarılmadığı ve Copy-on-Write riski oluşturduğu için temizleyici alt süreç, kasanın tüm açık bellek tamponları sıfırlanıp serbest bırakıldıktan sonra başlatılır.
  * Alt sürece açık şifre aktarılmaz; yalnızca kopyalanan şifrenin `BLAKE2b` (`crypto_generichash`) özeti aktarılır.
  * Süre dolduğunda panodaki güncel verinin özeti hesaplanır ve `sodium_memcmp` ile karşılaştırılır; yalnızca hala aynı şifre duruyorsa pano temizlenir.

Faz 4'ün uygulama kararları ve bilinen sınırlamaları §9.4'tedir.

### 9.4 Faz 4 Uygulama Kararları ve Bilinen Sınırlamalar

**Uygulama kararları** (`include/nilkey/commands.hpp`, `terminal.hpp`, `store.hpp`, `clipboard.hpp`, `doctor.hpp`):

*Komutlar ve akış*
* **Sıra:** komut satırı doğrulanır → parola gerektirmeyen denetimler yapılır (kasa var mı, `--notes-stdin`) → tüm istemler sorulur → kilit alınır → değiştirilir → kaydedilir. Böylece kullanıcı yazarken kilit tutulmaz ve hatalı bir komut satırı için kimseye parola yazdırılmaz. `add`, `update` ve `passwd`, ana parola istemi bittiği anda kasayı bir kez açıp (kilitsiz, sonucu atarak) parolayı doğrular; yanlışsa sonraki istemler hiç sorulmaz. Bedeli komut başına bir ek anahtar türetmedir. Kilit altındaki açış hâlâ belirleyicidir: açık kasa ve anahtar istemler boyunca tutulmaz (kullanıcı yazarken dosya değişebilir).
* **Çıkış kodları:** 0 başarı; 1 komut çalıştı ve başarısız oldu; 2 hatalı komut satırı (iletide `--help`'e yönlendirme); 130 kullanıcı vazgeçti (Ctrl-C, satır başında Ctrl-D).
* **Parola girişi:** yalnızca `/dev/tty` (stdin ve stdout'a dokunulmaz), `ECHO` kapalı, en fazla 1024 bayt; boş satır `kEmptyInput` ile reddedilir (§6.4'te CLI'ya bırakılan boş parola kuralı budur). Hiçbir seçenek parola almaz. `--notes-stdin` notları stdin'den okur (en fazla 64 KiB); kayıt parolası iki kez yazılır ya da `--generate` ile üretilir (20 karakter, dört sınıf).
* **Kilit:** kasayı değiştiren komutlar `<vault>.lock` üzerinde `flock` alır ve oku-değiştir-yaz döngüsünün tamamında tutar (§8'in Faz 2'de ertelenen kilidi). Ana parola kasa açılır açılmaz yok edilir. `list` ve `get` kilitsizdir: kayıt `rename` ile yapıldığından her zaman bütün bir sürüm görürler. Kilit tutulurken hiçbir şey `fork` etmez (çocuk kilidi miras alırdı).
* **`delete`:** onay, ana parola isteminden **önce** sorulur (parolayı yazıp vazgeçen olmasın); soruda kayıt adı yoktur (komut satırından gelen metin denetimsiz terminale çıkmasın); "hayır" `kNotConfirmed` ile çıkış 1 verir; `--yes` soruyu atlar.
* **`passwd`:** yeni anahtar, mevcut parola kasayı açtıktan **sonra** ve kilit altında türetilir (yanlış parola bir anahtar türetmeye mal olur, iki değil); yeni salt ve yeni nonce (§10 madde 4).
* **`update`:** dokunulmayan alanlar kasa tamponundan yeni yüke doğrudan taşınır, gizli bir kopya çıkarılmaz (`Vault::Patch`).
* **`list`:** çıktı bir terminale gidiyorsa (`isatty`) başlıklı ve hizalıdır: `NAME`, `USERNAME` ve `UPDATED` başlıkları; ad ve kullanıcı adı sütunları en uzun girdi kadar geniştir ve aralarında iki boşluk vardır. Genişlik terminal hücresiyle ölçülür (`PrintableWidth`: Doğu Asya ve emoji karakterleri 2, birleştirici işaretler ve birleştiriciler 0, `?` ile değiştirilen karakter 1). Boş kasada hiçbir şey yazılmaz. Boruya ya da dosyaya giderken satırlar eskisi gibi `ad\tkullanıcı\tzaman`'dır; adlarda boşluk olabildiğinden bir betik yalnızca sekmeyle güvenle bölebilir. Metin kesilmez: 1024 baytlık bir ad tüm satırları genişletir.
* **`generate`:** sabit 88 karakterlik alfabe (26 küçük, 26 büyük, 10 rakam, 26 sembol: `!@#$%^&*()-_=+[]{};:,.<>/?`), `randombytes_uniform`; uzunluk 8..1024 (varsayılan 20), sınıflar `--no-lower`, `--no-upper`, `--no-digits`, `--no-symbols` ile kapatılır; hiçbir sınıf kalmazsa kullanım hatası.
* **Çıktı güvenliği:** hata iletileri statik metindir, kullanıcı girdisi yankılanmaz. Komut satırından ya da kasadan gelen ad ve metinler yalnızca `WritePrintable` ile (denetim karakterleri `?` olur) terminale yazılır. Sırlar stdio tamponundan geçmez, doğrudan dosya tanımlayıcısına yazılır; çıktı bir terminal değilse sona satır sonu eklenmez (`nilkey generate | xclip` panoya `\n` koymaz).
* **Yeni metinde denetim karakteri yok:** `add`'de ad, `--username` ve `--url`; `update`'te `--rename`, `--username` ve `--url`, ekranda yazıldığı gibi görünmüyorsa (`ShowsAsWritten`: `WritePrintable`'ın `?` yapacağı her şey; C0/C1 denetimleri, DEL, yön ve satır denetimleri, geçersiz UTF-8) kullanım hatasıdır (çıkış 2, parola istenmeden önce). Kural `WritePrintable` ile aynı `NextPiece` üzerinden yürüdüğünden ikisi ayrışamaz. Yalnızca **yazılan** metin denetlenir: `update`, `get` ve `delete`'in konumsal kayıt adı bir aramadır ve eski davranışta (UTF-8 denetimi) kalır; böylece eski bir sürümün ya da başka bir yazarın bıraktığı, adında denetim karakteri olan kayıt bulunabilir, yeniden adlandırılabilir ve silinebilir. Notlar ve parolalar etkilenmez (notlar satır sonu taşıyabilir).
* **Yeni ana parola en az 12 karakter:** `init` ve `passwd`'nin yeni ana parolası (`ReadNewSecret`, `kMinMasterCharacters = 12`) bayt değil **karakter** olarak sayılır (`CountCharacters`: UTF-8 devam baytı olmayan her bayt bir karakter; geçersiz bayt da birer karakter sayılır). Sayım ilk girişte, tekrar istemi gösterilmeden yapılır; kısa parola `kMasterTooShort` (`the new master password must be at least 12 characters`, çıkış 1) ile reddedilir. 12 Türkçe harf kabul, 11 ret. Mevcut bir kasanın ana parolası açılışta denetlenmez: 12 karakterden kısa eski bir parola kasayı yine açar, yalnızca `passwd` ile yeni parola 12+ olmalıdır. Kayıt parolaları etkilenmez.
* **Bellek uyarısı:** `--allow-unlocked-memory` ile kilitlenemeyen bellek uyarısı süreç başına bir kez yazılır.

*`get` ve pano*
* **Seçenekler:** `--field password|username|url|notes` (varsayılan `password`), `--print`, `--timeout <sn>` (1..3600, varsayılan 15). `--print` ile `--timeout` birlikte kullanım hatasıdır. Boş alan panoya `kFieldEmpty` ile reddedilir (pano dokunulmaz); `--print` ile boş çıktı ve çıkış 0 verir. Değer kasa tamponundan doğrudan araca ya da çıktıya yazılır, ara kopya çıkarılmaz.
* **Araç tespiti (§9.3):** `WAYLAND_DISPLAY` doluysa `wl-copy` **ve** `wl-paste`; aksi halde `DISPLAY` doluysa `xclip`, ardından `xsel` (her zaman `--clipboard`; yoksa PRIMARY kullanılırdı). Aileler arası geri düşme yoktur: Wayland oturumunda `wl-clipboard` yoksa XWayland'e sessizce geçilmez, `kNoClipboardTool` döner; kullanıcı `--print`'i kendisi seçer. Araç yalnızca `PATH`'in **mutlak** girdilerinde aranır (göreli ya da boş girdi, geçerli dizinden çalıştırmayı önlemek için yok sayılır). Araç, ana parola istenmeden **önce** bulunur.
* **Araç çağrısı:** kabuk yok; `posix_spawn` ile mutlak yoldan, ortam (`DISPLAY`, `XAUTHORITY`, `WAYLAND_DISPLAY`, `XDG_RUNTIME_DIR`) aktarılarak; değer aracın stdin'ine yazılır (argüman ya da geçici dosya yok), aracın stdout/stderr'i `/dev/null`'dır. Yazma ve bekleme birlikte 5 saniyeyle sınırlıdır; takılan araç öldürülür. Okumayan araç `SIGPIPE` yoluyla süreci öldüremez (`SIGPIPE` yazma süresince yok sayılır).
* **Temizleyici süreç:** kasa tamponları ve anahtar yok edildikten, yığın `sodium_stackzero` ile sıfırlandıktan ve `fflush`'tan sonra `fork` edilir; çocuğa yalnızca düz veri (araç, BLAKE2b özeti ve uzunluk, süre) geçer. Çocuk yeni bir oturum açar (`setsid`), `SIGHUP`/`SIGINT`/`SIGQUIT`/`SIGTSTP` yok sayar, standart akışları `/dev/null`'a bağlar ve diğer tanımlayıcıları kapatır. Ebeveyn `fork` öncesi `SIGHUP`'ı bloklar (çocuk kendi oturumuna geçene kadar eski süreç grubundadır) ve çocuğun "hazırım" baytını (en fazla 2 sn) görmeden "N saniye sonra temizlenir" demez; çocuk başlamazsa ebeveyn panoyu hemen kendisi temizler ve hata verir.
* **Temizleme kararı:** süre `CLOCK_BOOTTIME` ile ölçülür (makine askıdayken de akar). Süre dolunca pano geri okunur (en fazla kopyalanan uzunluk kadar), uzunluk ve özet `sodium_memcmp` ile karşılaştırılır; yalnızca ikisi de eşitse temizlenir. Farklı içerik ya da okunamayan pano dokunulmadan bırakılır. Çocuk özet sayfasını `mlock` ile kilitler; kilitlenemezse (`kRequire`) hiç başlamaz.
* **xclip ile temizleme:** xclip'in temizleme seçeneği yoktur; boş stdin ile `xclip -selection clipboard -in` seçimi devralır ve eski sahibi çıkarır (gerçek xclip'te doğrulandı). `xsel` için `--clipboard --clear`, Wayland için `wl-copy --clear` kullanılır.

*`doctor`*
* Her kontrol bir satırdır: `ok`, `note` (bu makineye özgü bilgi) ya da `problem` (nilkey'in dayandığı bir varsayımı bozar). Çıkış kodu yalnızca `problem` varsa 1'dir. Parola istemez, `SecureBuffer` ayırmaz, kilit almaz, dosya yazmaz.
* Kontroller: kasa ve `.lock` dosyasının modu (tam `0600`), sahibi ve sembolik bağ olmaması; üst dizinin sahibi ve modu (grup/diğer yazabiliyorsa `problem`, yalnızca okuyabiliyorsa `note`); `RLIMIT_MEMLOCK`; `PR_GET_DUMPABLE` ve `RLIMIT_CORE`; `/proc/swaps`; pano aracı.
* `RLIMIT_MEMLOCK` üç satırdır ve §7.3'ün ayrımını izler. Kasa için gereken kilitli bellek iki satırdır: **okuma** (`list`, `get`: yük bir kez, sayfalara yuvarlanmış, artı 32 KiB) ve **değiştirme** (`add`, `update`, `delete`, `passwd`: yük iki kez, sayfalara yuvarlanmış, artı 256 KiB). Sığmayan satır `problem`'dir (nilkey o komutları reddeder); okumaya yeten ama değiştirmeye yetmeyen bir limit bu yüzden `ok` ve `problem` verir, çıkış kodu 1'dir. Üçüncü satır: Argon2id çalışma belleği sığmıyorsa `note` (nilkey yalnızca uyarır). Kasa başlığı parolasız okunur. Sabitler, sanitizer'sız release derlemesinde her komutun çalıştığı en küçük limitin ikili aramayla bulunmasıyla ölçüldü (glibc, 4 KiB sayfa; 4 KiB adım): okuma yük + 10 ila 12 KiB, `add`/`update` 2 × yük + 12 KiB, 64 KiB notlu `add` (en kötü durum) 2 × yük + 132 KiB. Sabitler payla seçilmiştir. Sayılar bu makine ve derleme içindir; `doctor` bir tahmin olarak kalır.

**Bilinen sınırlamalar:**
* **Pano:**
  * Wayland (`wl-clipboard`) ve `xsel` yolları gerçek araçla doğrulanmadı; geliştirme makinesinde yalnızca X11 ve `xclip` vardı. Yalnızca argüman kalıpları sahte araçla sınandı. `wl-copy`'nin stdin'den okurken `$XDG_RUNTIME_DIR` altında geçici dosya kullanıp kullanmadığı ve `xsel --output`'un sona satır sonu ekleyip eklemediği bilinmiyor; ekliyorsa temizleyici özeti eşleştiremez ve panoyu hiç silmez.
  * Masaüstü pano geçmişi yöneticileri kopyayı tutabilir; gerçek bir masaüstünde pano seçimini hemen devraldı. nilkey yalnızca seçimi temizler.
  * Pano aracının kendi süreç belleği `mlock`'suzdur ve sıfırlanmaz.
  * Temizleyici `SIGKILL` ya da oturum kapanışıyla ölürse pano temizlenmez.
  * Yalnızca CLIPBOARD seçimi kullanılır, PRIMARY değil. Seçilen alan (kullanıcı adı, URL, notlar) aynı süre ve aynı yolla işlenir.
  * Temizleyici özeti bekleme boyunca bellekte tutar (imzasız BLAKE2b; zayıf bir parola çevrimdışı tahmin edilebilir). Özetin sayfası kilitlidir ama çocuğun ebeveynden miras aldığı öteki sayfalar değildir.
  * Araç ve hazır borusu zaman aşımları `CLOCK_MONOTONIC` kullanır; makine askıdayken uzar. Kullanıcıya verilen süre sözü `CLOCK_BOOTTIME` ile tutulur.
  * `get --print` kayıt adı dışındaki alanları (parola, kullanıcı adı, URL, notlar) terminale ham bayt olarak yazar; kaçış dizisi taşıyan bir alan terminali etkileyebilir. nilkey'in oluşturduğu kayıtlar adda, kullanıcı adında ve URL'de kaçış dizisi taşıyamaz (yukarıdaki kural); taşıyabilecekler eski sürümlerden ya da başka yazarlardan gelen kayıtlar, notlar ve parolalardır. Boru ve dosyada tam değerin korunması için bu bilinçli bırakıldı; alan yalnızca kasa sahibinin kendi verisidir.
* **Komutlar:**
  * `add`'de var olan bir ad, `update`'te olmayan bir kayıt ve `update --rename`'de dolu bir ad, kayıt parolası yazıldıktan **sonra** anlaşılır. Tüm istemler kilit alınmadan önce bitirildiğinden (kullanıcı yazarken kilit tutulmaz) bu denetimler kilit altında, istemlerden sonra yapılır. Yanlış ana parola bunların dışındadır: istemlerden önce yakalanır (yukarıdaki "Sıra").
  * Ana parola için yalnızca uzunluk denetlenir, güç denetlenmez: `aaaaaaaaaaaa` geçer. Uzun ama tahmin edilebilir bir parola kabul edilir.
  * `passwd` yeni anahtarı kilit tutarken türetir; bu sırada öteki yazarlar bekler.
  * `list`'in hizalaması terminalin karakter genişliğini tahmin eder. Genişlik tabloları glibc 2.39'un `wcwidth()` çıktısından bir kez üretildi; nilkey çalışma zamanında `wcwidth()` çağırmaz ve yerele bağlı değildir. Birkaç kod noktasının tek resim olarak çizildiği diziler (bayrak, aile, ten tonlu emoji) kod noktası kod noktası sayılır ve bir terminalde birkaç hücre kayabilir.
  * Reddedilen `delete` çıkış 1 verir (betiklerde "başarısız" ile "vazgeçti" ayrılmaz).
  * Silinen ya da değiştirilen kaydın eski şifreli sürümleri yedeklerde ve disk artıklarında kalabilir.
  * `<vault>.lock` dosyası dizinde kalır (silmek yarışı yeniden açardı). Bazı ağ dosya sistemlerinde `flock` zayıftır.
  * Kayıt adlarında Unicode normalizasyonu yoktur (§6.4).
* **Terminal:** `SIGKILL` ve çökmede terminal ayarları geri yüklenmez; `ECHO` kapalı kalırsa `stty sane`.
* **`doctor`:** swap'ın şifreli olup olmadığına ve hibernasyon yapılandırmasına bakılmaz, yalnızca etkin swap alanı sayılır; `ptrace_scope` ve `core_pattern` raporlanmaz; yalnızca kasanın doğrudan üst dizini denetlenir; pano satırı aracın kurulu olduğunu gösterir, çalıştığını değil; kilitli bellek ihtiyacı bir tahmindir ve yalnızca bu sürecin sınırına bakar.

**Teste dayanmayanlar** (tasarıma ve incelemeye dayanır):
* Temizleyici sürecin belleğinde parola bulunmaması: `dumpable=0` yüzünden `/proc/<pid>/mem` okunamaz. Güvence yapıdadır (`StartCleaner` yalnızca düz veri alır, çağıran kapsam daha önce bitmiştir).
* `fork` öncesi `fflush` ve `sodium_stackzero`'nun etkisi, hata yollarındaki `sodium_stackzero` ve özet kopyalarının silinmesi: bellek içeriği dışarıdan gözlenemez.
* `SIGHUP` maskesi: hazır borusu ebeveynin pencere içinde çıkmasını zaten engellediğinden testle ayırt edilemez.
* `fork` hatası ve hazır borusu zaman aşımı yolları (güvenilir biçimde tetiklenemez), makinenin askıya girmesi (`CLOCK_BOOTTIME`).
* `doctor`'ın sertleştirme `problem` dalı (ikili her zaman kendini sertleştirir) ve `/proc/swaps` okunamadığı dal.
* Çocuğun `mlock` kontrolü (`VmLck`) ve tek uyarı testi yalnızca sanitizer'sız derlemede çalışır; ASan/UBSan `mlock()`'u yakalayıp başarı döndürür (§7.4).

**Test altyapısı:** sözde terminalli (pty) bir koşum düzeneği, gerçek bir ekran ve pano yerine sahte `xclip` betiği, ucuz Argon2id maliyetli `nilkey_e2e` ikilisi (üretim ikilisi bu makroyu hiç tanımlamaz) ve üretim maliyetleriyle koşan, `slow` etiketli bir duman testi. Mutasyon doğrulaması elle yapıldı; CI'da koşmaz.

**Dış inceleme (2026-11-22):** tüm `src` ve `include` üzerinde bir model incelemesi (`/code-review high`) yapıldı; bellek güvenliği, kripto ya da dosya formatı hatası bulmadı. Sekiz bulgu şöyle sonuçlandı:
* *Kodda düzeltildi:* temizleyicinin askıdaki süreyi saymaması; panoya yazmanın zaman aşımına bağlanmaması; başarısız anahtar türetme ve şifre çözme yollarında `sodium_stackzero` eksikliği; bellek kilidi uyarısının tekrarlanması; `doctor`'ın `/proc/swaps`'ı en fazla 8 KiB okuması (bulgu "kısa okuma" demişti, oysa `fread` döngüler; asıl hata 8 KiB sınırıydı).
* *Kısmen düzeltildi:* özet kopyaları (çocuktaki kopya kilitli, ama miras kalan sayfalar değil).
* *Yalnızca belge düzeltildi, davranış aynı:* `wl-copy`'nin geçici dosya iddiası.
* *Bilinçli sınır olarak bırakıldı:* `get --print`'in ham yazımı.
Bu tek bir model incelemesidir; insan ya da ikinci bir araçla yapılmış bağımsız denetimin yerine geçmez.

---

## 10. Zorunlu Otomatik Test Matrisi

Tüm testler `tests/test_framework.hpp` + `CTest` ile ve **ASan + UBSan** etkinleştirilmiş `-fno-exceptions` derlemesi altında eksiksiz geçmelidir:

1. **Bit-Flipping / Tampering:** 66-byte başlığın her alanı (magic, version, KDF parametreleri, salt, nonce, payload_len), ciphertext gövdesi ve 16-byte Auth Tag içindeki tek bitlik değişikliklerin tamamı reddedilmelidir. *Test maliyeti notu:* `kdf_mem_kib` içindeki bit çevirmeleri geçerli aralıkta çok büyük değerler üretebilir (ör. tek bit ~1 GiB Argon2 çalıştırır). Testler yalnızca test hedefine özel bir derleme zamanı üst sınır makrosu (ör. `NILKEY_TEST_MAX_KDF_MEM_KIB`) ile bu koşuları reddettirir; bu makro ana `nilkey` ikilisinde tanımlanmaz.
2. **Sıfır Bilgi Doğrulaması:** Yanlış ana parola verildiğinde hata dönmeli ve dışarıya sıfır bayt açık veri çıkarılmamalıdır.
3. **Nonce Benzersizliği:** Ardışık kayıt/güncelleme işlemlerinde dosya başlığındaki 24 byte nonce değerinin her seferinde değiştiği doğrulanmalıdır.
4. **Re-Keying (`passwd`):** Ana parola değişikliği sonrasında hem 16 byte salt hem 24 byte nonce değişmeli, eski parola reddedilmeli ve yeni parola tüm kayıtları eksiksiz çözmelidir.
5. **Dosya Bütünlüğü ve İzinler:** Oluşturulan/güncellenen `.vault` dosyasının izinleri kesinlikle `0600` olmalıdır; kesilmiş (truncated), fazladan bayt eklenmiş (trailing) veya 16 MiB sınırını aşan dosyalar reddedilmelidir.
6. **TLV Sınır ve Bozulma Testleri:** Bozuk uzunluk alanları, tamsayı taşması (overflow) denemeleri, yinelenen alan/kayıt adları reddedilmeli; bilinmeyen TLV tip kodları güvenle atlanabilmeli; UTF-8 ve gömülü NUL baytı içeren parolalar sorunsuz yuvarlanabilmelidir (round-trip).
7. **Hibrit `RLIMIT_MEMLOCK` Testi:** Kilitleme başarısızlığı simülasyonunda varsayılan modun fail-closed davrandığı, `--allow-unlocked-memory` ile uyarı vererek devam ettiği doğrulanmalıdır.

---

## 11. Fazlı Geliştirme Yol Haritası

* **Faz 0 — Proje İskeleti ve Derleme Kapısı:** `CMakeLists.txt`, `libsodium` (>= 1.0.18) tespiti, `-Wall -Wextra -Werror -fno-exceptions -fno-rtti`, ASan/UBSan profili, `Result<T, Error>`, `tests/test_framework.hpp` ve ilk `CTest` koşusu.
* **Faz 1 — Güvenli Bellek ve Süreç Sertleştirme:** `SecureBuffer` (RAII + hibrit `sodium_mlock` + `sodium_mprotect` + guard sınıfları), `ProcessHardening` (`sodium_init`, `prctl`, `RLIMIT_CORE`, `umask`) ve birim testleri.
* **Faz 2 — Kriptografik Çekirdek ve Dosya Katmanı:** 66-byte başlık ayrıştırma/yazma (`"NILKEY1\0"`), `Argon2id` + `XChaCha20-Poly1305` (AAD), atomik dosya kaydı (`0600` + `fsync` + `rename` + dizin `fsync`) ve tüm bit-flipping/tampering testleri.
* **Faz 3 — İkili TLV Serileştirme ve Kasa Veri Modeli:** Bağımlılıksız TLV okuyucu/yazıcı, kayıt CRUD mantığı, sınır/taşma/UTF-8+NUL ve ileriye dönük uyumluluk testleri.
* **Faz 4 — CLI, Terminal Girişi, Pano ve `doctor`:** Alt komut yönlendiricisi, `termios` echo kapalı parola okuma, Wayland/X11 15 sn akıllı pano temizleyici, `doctor` denetimi ve uçtan uca entegrasyon testleri.