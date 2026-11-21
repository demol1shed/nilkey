# CLAUDE.md — `nilkey` Geliştirme Sözleşmesi ve Mühendislik Kuralları

Bu dosya, **`nilkey`** (Zero-Knowledge CLI Password Vault) açık kaynak C++20 projesinde çalışan yapay zekâ kodlama ajanları (Claude Code) için bağlayıcı çalışma kurallarını tanımlar.

Teknik gereksinimler, ikili dosya formatı, kriptografik parametreler ve test matrisi için tek doğruluk kaynağı (Single Source of Truth) proje kökündeki **`SPEC.md`** dosyasıdır. `SPEC.md` ile çelişen hiçbir varsayım yapma; belirsizlik görürsen kod yazmadan önce kullanıcıya sor.

---

## 1. Rol, İletişim ve Çalışma Akışı (Zorunlu)

* **Rol Dağılımı:** Sen kıdemli bir C++ sistem/güvenlik geliştiricisi olarak uygularsın; kullanıcı ise mimar ve güvenlik denetçisidir (code reviewer). Bu projenin temel hedeflerinden biri, güvenlik açısından kritik her satırın insan tarafından kolayca okunup denetlenebilmesidir.
* **Dil Kuralı:**
  * Kullanıcıyla tüm plan, açıklama, soru ve kod inceleme (review) iletişimi **Türkçe** yürütülür.
  * Açık kaynak hijyeni gereği tüm kaynak kod, tanımlayıcılar, yorum satırları, CLI yardım/hata mesajları, test adları ve `README.md` **İngilizce** yazılır.
* **Plan-First Onay Kapısı:**
  1. Herhangi bir fazda veya görevde **kod yazmadan önce** mutlaka kısa bir uygulama planı ve oluşturulacak/değiştirilecek dosyaların listesini sun.
  2. **Kullanıcı açık onay vermeden** dosya oluşturma veya kod değiştirme.
* **Tek Faz Kuralı:** Tek seferde yalnızca aktif faz (`SPEC.md` Bölüm 11) üzerinde çalış. Bir fazın tüm testleri ASan + UBSan altında sıfır uyarıyla geçmeden ve kullanıcı onaylamadan sonraki faza geçme.
* **Sadelik Kuralı:** Aşırı karmaşık template meta-programlama, gereksiz soyutlama katmanları veya "akıllı" tek satırlık hileler yazma. Açık, düz, okunabilir ve öngörülebilir C++20 yaz.

---

## 2. Kesin Yasaklar (C++20 Güvenlik Korkulukları)

Aşağıdaki kuralların ihlali kesinlikle kabul edilmez:

1. **C++ İstisna Yasağı (`-fno-exceptions -fno-rtti`):**
   * Kod tabanında ve testlerde `try`, `catch`, `throw` **ASLA** kullanma.
   * Tüm hata dönebilen fonksiyonlar `[[nodiscard]] nilkey::Result<T, Error>` veya `[[nodiscard]] nilkey::Status` döndürmelidir.
   * İstisna fırlatabilecek STL işlemlerinden (ör. `std::stoi`, sınır dışı `.at()`) kaçın; `std::from_chars` ve açık sınır kontrolleri kullan.
2. **Hassas Veri İçin Standart Kap (Container) Yasağı:**
   * Ana parola, türetilmiş anahtar, kayıt parolası veya şifresi çözülmüş TLV tamponları için `std::string`, `std::vector`, `std::stringstream` **ASLA** kullanma.
   * Tüm hassas veriler yalnızca kopyalamaya kapalı RAII `nilkey::SecureBuffer` sınıfında tutulur.
3. **C-String / `strlen` Yasağı (Parolalarda):**
   * Parolalar Unicode karakterler ve gömülü `\0` (NUL) baytları içerebilir. Parola uzunlukları için asla `strlen` veya null-terminated C string varsayımı kullanma; her zaman uzunluk bilgisini taşıyan `SecureBuffer` / `std::span<const std::byte>` kullan.
4. **Özel Kriptografi ve Zayıf RNG Yasağı:**
   * Hiçbir şifreleme, KDF, MAC veya hash algoritmasını sıfırdan yazma.
   * Rastgele veri üretimi için `std::rand`, `rand()`, `std::mt19937` veya `std::random_device` **ASLA** kullanma. Yalnızca `libsodium`'un `randombytes_buf()` ve önyargısız seçim için `randombytes_uniform()` fonksiyonlarını kullan.
5. **Zamanlama Saldırısı (Timing Attack) Yasağı:**
   * Anahtar, özet (hash), parola veya doğrulama verilerini karşılaştırırken `==`, `!=` veya `std::memcmp` **ASLA** kullanma. Yalnızca sabit zamanlı `sodium_memcmp()` kullan.
6. **Dönüş Değeri Yoksayma Yasağı:**
   * `sodium_init`, `sodium_mlock`, `sodium_mprotect_*`, `crypto_pwhash`, `crypto_aead_*`, `prctl`, `setrlimit`, `open`, `read`, `write`, `fsync`, `close`, `rename`, `unlink` çağrılarının dönüş değerleri **ASLA** yoksayılmaz.
   * `read`/`write` çağrıları kısmi okuma/yazma ve `EINTR` döngülerini doğru biçimde işlemelidir.
7. **Hassas Veri Loglama / Hata Sızıntısı Yasağı:**
   * `Error` yapılarına, `stderr`/`stdout` çıktısına veya başarısız test mesajlarına asla parola, anahtar, nonce/plain TLV içeriği yazdırma.
8. **Harici Bağımlılık Yasağı:**
   * `libsodium` (>= 1.0.18) dışında üçüncü parti kütüphane (JSON, CLI kütüphanesi, Catch2, GoogleTest, OpenSSL vb.) **ASLA** ekleme. Testler kendi tek dosyalık `tests/test_framework.hpp` çerçevemiz ve `CTest` ile yazılır.

---

## 3. Mimari Uygulama İncelikleri

* **`SecureBuffer` Bitişik Ayırma:** `sodium_malloc()` her ayırmada guard page nedeniyle 3-4 ekstra sanal bellek sayfası harcar. Küçük her kayıt alanı için ayrı `sodium_malloc` çağırmak yerine, açık TLV yükünü ve anahtarları az sayıda bitişik blokta yönet.
* **Hibrit `RLIMIT_MEMLOCK` Kontrolü:** `sodium_malloc()` kilitleme başarısız olsa bile kilitlenmemiş bellek döndürebilir; bu nedenle `sodium_mlock()` dönüş değeri ayrıca doğrulanmalıdır. Varsayılan davranış **fail-closed** (hata ver + `nilkey doctor`'a yönlendir); yalnızca `--allow-unlocked-memory` açıkça verildiğinde `stderr`'e uyarı yazarak devam edilir.
* **Yığın (Stack) Hijyeni:** Hassas anahtar türetme, şifre çözme ve parola okuma akışlarının sonunda `sodium_stackzero(4096)` çağır.
* **`libsodium` Argon2id Paralellik Notu:** `crypto_pwhash()` dahili olarak `p = 1` kullanır. V1 dosya başlığında `kdf_parallelism = 1` yazılır; okuma sırasında `kdf_parallelism != 1` görülürse hata döndürülür.
* **`fork()` Öncesi Bellek Temizliği:** Pano temizleyici alt süreç başlatılmadan önce tüm açık kasa tamponları ve anahtarlar sıfırlanıp serbest bırakılmış olmalıdır; alt sürece açık parola değil yalnızca `BLAKE2b` özeti aktarılır.
* **KDF Test Maliyeti:** Üretim kodu `mem_kib >= 19456` ve `iterations >= 2` alt sınırını zorunlu tutar. Birim testlerin hızlı çalışması için yalnızca test hedefine özel derleme zamanı makrosu (`NILKEY_ALLOW_TEST_KDF`) tanımlanabilir; ana `nilkey` ikilisinde bu makro ASLA tanımlanmaz.

---

## 4. Derleme ve Doğrulama Kapısı (Definition of Done)

Bir fazı veya değişikliği "tamamlandı" olarak bildirmeden önce aşağıdaki komutları **bizzat çalıştır** ve sonuçlarını özetle:

```bash
# 1. Debug + ASan + UBSan + -Werror ile yapılandırma
cmake -B build-debug \
  -DCMAKE_BUILD_TYPE=Debug \
  -DNILKEY_ENABLE_SANITIZERS=ON

# 2. Sıfır uyarı ile derleme
cmake --build build-debug -j

# 3. Tüm testlerin sanitizer altında çalıştırılması
ctest --test-dir build-debug --output-on-failure
```

Release sertleştirme derlemesinin de bozulmadığını gerektiğinde doğrula:
```bash
cmake -B build-release -DCMAKE_BUILD_TYPE=Release -DNILKEY_ENABLE_SANITIZERS=OFF
cmake --build build-release -j
```

**Kabul Kriterleri:**
* Derleyici uyarısı sayısı: **0** (`-Wall -Wextra -Werror -Wpedantic -Wconversion -Wshadow`).
* ASan / UBSan bulgu sayısı: **0**.
* Başarısız test sayısı: **0**.

**Sanitizer ve test kuralları:**
* Sanitizer derlemesi `-fno-sanitize-recover=all` ile yapılır; aksi halde UBSan bulguyu yazıp çıkış kodu 0 ile devam eder ve "0 bulgu" kriteri CTest'te zorlanmaz. CTest ortamı `ASAN_OPTIONS` / `UBSAN_OPTIONS` değerlerini CMake'ten alır, elle ayarlanmaz.
* `Result`/`Status` erişimi `std::get_if` ile yapılır; `std::get` kullanılmaz (`-fno-exceptions` altında yanlış alternatifte sessizce `abort` eder).
* Test çatısı hata mesajına değer basmaz (yalnızca ifade metni ve `dosya:satır`); sır içeren baytlar `sodium_memcmp` tabanlı makroyla karşılaştırılır.
* Yeni davranış yeni test gerektirir. Yeni test dosyası `CMakeLists.txt` içindeki ilgili hedefe eklenir.

---

## 5. Faz Sonu Güvenlik Öz-Denetim Raporu

Her fazın kodlaması ve test koşusu bittikten sonra kullanıcıya kısa bir **Güvenlik Öz-Denetim Özeti** sun:
1. Oluşturulan/değiştirilen dosyalar ve kısa görevleri.
2. Bellek güvenliği kontrolü (hangi tamponlar `SecureBuffer` ile yönetildi, sıfırlama ve `mprotect` akışı).
3. Sınır/taşma ve hata yolu kontrolleri (hangi POSIX/`libsodium` dönüş değerleri ve tamsayı taşmaları denetlendi).
4. Test ve ASan/UBSan koşu çıktısı özeti.

---

## 6. Faz Takibi

* **Mevcut Faz:** Faz 4 (CLI, Terminal Girişi, Pano ve `doctor`)
* **Tamamlanan Fazlar:** Faz 0 (Proje İskeleti ve Derleme Kapısı), PR #2; Faz 1 (Güvenli Bellek ve Süreç Sertleştirme), PR #5 ve #6; Faz 2 (Kriptografik Çekirdek ve Dosya Katmanı), PR #10, #11, #12 ve #13; Faz 3 (İkili TLV Serileştirme ve Kasa Veri Modeli), PR #15, #16 ve #17.

---

## 7. Git İş Akışı

Geçmiş temiz tutulur: mantıksal noktalarda küçük, açıklayıcı commitler; tek commit = tek mantıksal değişiklik. Refactor, davranış değişikliği ve testler ayrı commit'lerdir ki inceleyen kod parça parça okuyabilsin. Commit mesajları ve PR metinleri **İngilizce**'dir.

* `main`'e doğrudan commit veya push **yok**. `<tür>/<kısa-açıklama>` biçiminde topic branch (ör. `build/phase-0-skeleton`, `docs/project-conventions`) → push → `gh pr create` (Summary + Test plan) → CI geçince PR ile merge → branch sil. Bir PR tek kaygı taşır.
* **Merge yöntemi: rebase-merge** (doğrusal geçmiş, atomik commitler korunur). İstisna: PR'ın commitleri dağınık/WIP ise squash-merge; squash mesajı da aşağıdaki formata uymalıdır. Düz merge commit kullanılmaz.
* Commit'lemeden önce kullanıcıya sor; push, tag ve release dışa dönük işlemlerdir, yalnızca kullanıcı isterse yapılır.
* Her commit tek mantıksal değişikliktir, derlenir ve testleri geçer. PR'da WIP/fixup commit bırakılmaz (push öncesi `--amend`).
* Asla secret, anahtar, `.vault` dosyası veya derleme çıktısı commit'lenmez; ilgisiz biçimlendirme değişikliği yapılmaz.

### Commit mesajları

Conventional Commits 1.0:

* Konu: `<tür>(<opsiyonel-kapsam>): <emir kipi özet>`. Emir kipi ("add", "added" değil), iki noktadan sonra küçük harf, en fazla 72 karakter, sonda nokta yok. Kapsam modül/alanı belirtir (ör. `core`, `crypto`, `cli`).
* Türler: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `build`, `ci`, `chore`, `style`, `revert`.
* Gövde (boş satırdan sonra, ~72 sütun): ne ve **neden**, nasıl değil. Önemsiz tek satırlıklar dışında zorunlu.
* Kırıcı değişiklik: tür/kapsamdan sonra `!` ve `BREAKING CHANGE:` altbilgisi. Issue'lar altbilgide (`Fixes #123`, `Refs #123`).
* PR başlığı aynı formatı izler; PR gövdesi **Summary** (ne ve neden) ve **Test plan** (çalıştırılan derleme/ctest komutları) içerir.

### Sürümler

* SemVer 2.0 `MAJOR.MINOR.PATCH`: `feat` → MINOR, `fix`/`perf` → PATCH, kırıcı değişiklik → MAJOR (1.0.0 öncesinde MINOR). Ön sürümler `-rc.1`, `-beta.1`. Vault dosya formatı sürümü (`version` alanı) uygulama sürümünden bağımsızdır.
* Tag: `vX.Y.Z` annotated (`git tag -a v1.2.0 -m "v1.2.0"`), yalnızca release PR'ı merge edildikten sonra varsayılan dalda. Yayımlanmış tag asla taşınmaz/silinmez; yeni patch çıkarılır.
* `CHANGELOG.md`: Keep a Changelog biçimi (`Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`; en yeni üstte, `Unreleased` en üstte), son tag'den bu yana Conventional Commits'ten türetilir.
* Release PR'ı: `chore(release): vX.Y.Z` başlıklı, yalnızca sürümü yükseltir ve `Unreleased`'ı yeni sürüm bölümüne taşır.
* GitHub Release: `gh release create vX.Y.Z --title "vX.Y.Z" --notes-file <notes>`; ön sürümlerde `--prerelease`. Tag/release yalnızca kullanıcı isterse.
