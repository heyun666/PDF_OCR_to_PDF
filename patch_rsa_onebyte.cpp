// =============================================================================
//  PatchRSA OneByte - Cross-platform C++ reproduction
//  Reverse-engineered from PatchRSA_OneByte_Cpp.exe
//
//  Build (MSVC, C++11):  cl /std:c++11 /EHsc /D_CRT_SECURE_NO_WARNINGS patch_rsa_onebyte.cpp
//  Build (MinGW, C++11):  g++ -std=c++11 -O2 -lbcrypt -o patch_rsa_onebyte.exe patch_rsa_onebyte.cpp
//  Build (Linux, C++11):  g++ -std=c++11 -O2 -lpthread -o patch_rsa_onebyte patch_rsa_onebyte.cpp
//
//  Dependencies: OpenSSL (libcrypto) for RSA key parse / PEM generation,
//                GMP (libgmp) for arbitrary-precision arithmetic.
// =============================================================================
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <array>
#include <atomic>
#include <mutex>
#include <thread>
#include <chrono>
#include <algorithm>
#include <memory>
#include <fstream>
#include <sstream>
#include <iostream>

// ---------------------------------------------------------------------------
//  Compatibility shims
// ---------------------------------------------------------------------------

// C++11 make_unique replacement (removes C++14 dependency)
#if __cplusplus < 201402L
namespace std11 {
template <typename T, typename... Args>
std::unique_ptr<T> make_unique(Args&&... args) {
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}
}
using std11::make_unique;
#endif

// GMP
#include <gmp.h>

// OpenSSL
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

// ---------------------------------------------------------------------------
//  Platform portability layer for file I/O (UTF-16 on Windows)
// ---------------------------------------------------------------------------

#if defined(_WIN32)
  #include <windows.h>
  #include <io.h>
  #include <fcntl.h>
  #include <direct.h>

  // Open a file with a UTF-8 path on Windows by converting to UTF-16.
  // This replaces the ccs=UTF-8 fopen mode and fixes Chinese-path issues.
  static FILE* fopen_utf8(const char* path, const char* mode) {
      int wlen = MultiByteToWideChar(CP_UTF8, 0, path, -1, nullptr, 0);
      int mlen = MultiByteToWideChar(CP_UTF8, 0, mode, -1, nullptr, 0);
      if (wlen <= 0 || mlen <= 0) return nullptr;
      std::vector<wchar_t> wpath(wlen);
      std::vector<wchar_t> wmode(mlen);
      MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath.data(), wlen);
      MultiByteToWideChar(CP_UTF8, 0, mode, -1, wmode.data(), mlen);
      return _wfopen(wpath.data(), wmode.data());
  }

  // _mkdir with UTF-8 path
  static int mkdir_utf8(const char* path) {
      int wlen = MultiByteToWideChar(CP_UTF8, 0, path, -1, nullptr, 0);
      if (wlen <= 0) return -1;
      std::vector<wchar_t> wpath(wlen);
      MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath.data(), wlen);
      return _wmkdir(wpath.data());
  }

  #define MKDIR_ONE(p) mkdir_utf8(p)

  // Recursive mkdir using Win32 W API (no <filesystem>)
  static void mkdir_recursive(const std::string& path) {
      if (path.empty()) return;
      // Convert to wide
      int wlen = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
      if (wlen <= 0) return;
      std::vector<wchar_t> wpath(wlen);
      MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, wpath.data(), wlen);
      std::wstring ws(wpath.data());
      // Walk through and create each directory level
      for (size_t i = 1; i < ws.size(); ++i) {
          if (ws[i] == L'\\' || ws[i] == L'/') {
              std::wstring sub = ws.substr(0, i);
              CreateDirectoryW(sub.c_str(), nullptr);
          }
      }
      CreateDirectoryW(ws.c_str(), nullptr);
  }

#else
  // POSIX
  #include <sys/stat.h>
  #include <sys/types.h>
  #include <unistd.h>
  #include <dlfcn.h>

  static FILE* fopen_utf8(const char* path, const char* mode) {
      return fopen(path, mode);
  }
  #define MKDIR_ONE(p) ::mkdir(p, 0755)

  static void mkdir_recursive(const std::string& path) {
      if (path.empty()) return;
      std::string cur;
      for (size_t i = 0; i < path.size(); ++i) {
          if (path[i] == '/') {
              if (!cur.empty()) MKDIR_ONE(cur.c_str());
          }
          cur += path[i];
      }
      MKDIR_ONE(path.c_str());
  }
#endif

// std::ofstream doesn't support UTF-8 paths on MinGW/MSVC before C++17.
// Provide a helper that opens via fopen_utf8 and wraps as stream.
static std::string read_file_utf8(const std::string& path) {
    FILE* f = fopen_utf8(path.c_str(), "rb");
    if (!f) return "";
    std::string data;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz > 0) {
        data.resize(sz);
        fread(&data[0], 1, sz, f);
    }
    fclose(f);
    return data;
}

static bool write_file_utf8(const std::string& path, const std::string& data) {
    FILE* f = fopen_utf8(path.c_str(), "wb");
    if (!f) return false;
    fwrite(data.data(), 1, data.size(), f);
    fclose(f);
    return true;
}

// ---------------------------------------------------------------------------
//  Base64 helpers
// ---------------------------------------------------------------------------

static std::string base64_encode(const unsigned char* data, size_t len) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, data, (int)len);
    BIO_flush(b64);
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(b64, &bptr);
    std::string out(bptr->data, bptr->length);
    BIO_free_all(b64);
    return out;
}

static std::vector<unsigned char> base64_decode(const std::string& input) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(input.data(), (int)input.size());
    b64 = BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    std::vector<unsigned char> out(input.size());
    int n = BIO_read(b64, out.data(), (int)out.size());
    if (n > 0) out.resize(n);
    else out.clear();
    BIO_free_all(b64);
    return out;
}

// ---------------------------------------------------------------------------
//  BigNumber wrapper around GMP
// ---------------------------------------------------------------------------

struct BigNum {
    mpz_t v;
    BigNum() { mpz_init(v); }
    ~BigNum() { mpz_clear(v); }
    BigNum(const BigNum& o) { mpz_init_set(v, o.v); }
    BigNum& operator=(const BigNum& o) { mpz_set(v, o.v); return *this; }

    void set_str(const std::string& s, int base) { mpz_set_str(v, s.c_str(), base); }
    std::string to_hex() const {
        char* h = mpz_get_str(nullptr, 16, v);
        std::string r(h);
        free(h);
        return r;
    }
    std::string to_dec() const {
        char* h = mpz_get_str(nullptr, 10, v);
        std::string r(h);
        free(h);
        return r;
    }
    size_t byte_size() const {
        size_t bits = mpz_sizeinbase(v, 2);
        return (bits + 7) / 8;
    }
    // Export as big-endian bytes
    std::vector<unsigned char> to_bytes_be() const {
        size_t n = byte_size();
        std::vector<unsigned char> buf(n);
        // mpz_export gives little-endian
        size_t written = 0;
        mpz_export(buf.data(), &written, 1, 1, 0, 0, v);
        // pad to n
        if (written < n) buf.insert(buf.begin() + written, n - written, 0);
        buf.resize(n);
        // reverse to big-endian
        std::reverse(buf.begin(), buf.end());
        return buf;
    }
    void from_bytes_be(const unsigned char* data, size_t len) {
        std::vector<unsigned char> tmp(data, data + len);
        std::reverse(tmp.begin(), tmp.end());
        mpz_import(v, tmp.size(), 1, 1, 0, 0, tmp.data());
    }
    bool is_zero() const { return mpz_sgn(v) == 0; }
};

// ---------------------------------------------------------------------------
//  RSA key parsing: PEM / headerless base64 / raw N / OpenSSH / file path
//  Reproduces sub_140028C90 -> sub_1400267C0 / sub_140026AB0
// ---------------------------------------------------------------------------

struct RsaKeyInfo {
    std::string n_hex;
    std::string e_hex;
    std::string mode;   // "rsa" or "factor"
};

// Parse a SubjectPublicKeyInfo PEM or DER into N, e
static bool parse_spki(const std::string& pem_text, std::string& n_hex, std::string& e_hex) {
    BIO* bio = BIO_new_mem_buf(pem_text.data(), (int)pem_text.size());
    if (!bio) return false;
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) return false;
    BIGNUM* n_bn = nullptr;
    BIGNUM* e_bn = nullptr;
    RSA* rsa = EVP_PKEY_get1_RSA(pkey);
    EVP_PKEY_free(pkey);
    if (!rsa) return false;
    RSA_get0_key(rsa, (const BIGNUM**)&n_bn, (const BIGNUM**)&e_bn, nullptr);
    if (!n_bn || !e_bn) { RSA_free(rsa); return false; }
    char* n_str = BN_bn2hex(n_bn);
    char* e_str = BN_bn2hex(e_bn);
    n_hex = n_str;
    e_hex = e_str;
    OPENSSL_free(n_str);
    OPENSSL_free(e_str);
    RSA_free(rsa);
    return true;
}

// Parse OpenSSH public key format
static bool parse_openssh(const std::string& line, std::string& n_hex, std::string& e_hex) {
    // Format: ssh-rsa AAAAB3Nza...
    auto sp = line.find(' ');
    if (sp == std::string::npos) return false;
    std::string b64part = line.substr(sp + 1);
    // trim
    while (!b64part.empty() && (b64part.back() == '\n' || b64part.back() == '\r' || b64part.back() == ' '))
        b64part.pop_back();
    auto decoded = base64_decode(b64part);
    if (decoded.empty()) return false;
    // Parse SSH wire format
    size_t pos = 0;
    auto read_u32 = [&](uint32_t& out) -> bool {
        if (pos + 4 > decoded.size()) return false;
        out = (decoded[pos]<<24)|(decoded[pos+1]<<16)|(decoded[pos+2]<<8)|decoded[pos+3];
        pos += 4;
        return true;
    };
    auto read_mpint = [&](std::vector<unsigned char>& out) -> bool {
        uint32_t len;
        if (!read_u32(len)) return false;
        if (pos + len > decoded.size()) return false;
        out.assign(decoded.begin() + pos, decoded.begin() + pos + len);
        pos += len;
        return true;
    };
    uint32_t klen;
    if (!read_u32(klen)) return false;
    if (pos + klen > decoded.size()) return false;
    std::string ktype(decoded.begin() + pos, decoded.begin() + pos + klen);
    pos += klen;
    if (ktype != "ssh-rsa") return false;
    std::vector<unsigned char> e_bytes, n_bytes;
    if (!read_mpint(e_bytes)) return false;
    if (!read_mpint(n_bytes)) return false;
    // Convert to hex
    BigNum e_val, n_val;
    if (!e_bytes.empty()) e_val.from_bytes_be(e_bytes.data(), e_bytes.size());
    if (!n_bytes.empty()) n_val.from_bytes_be(n_bytes.data(), n_bytes.size());
    n_hex = n_val.to_hex();
    e_hex = e_val.to_hex();
    return true;
}

// Parse raw N hex (no PEM header)
static bool parse_raw_n(const std::string& input, std::string& n_hex) {
    // strip whitespace
    std::string s;
    for (char c : input) {
        if (isxdigit((unsigned char)c)) s += tolower(c);
    }
    if (s.empty()) return false;
    n_hex = s;
    return true;
}

// Main parse function - handles all input types
// Reproduces sub_140023B50 logic
static bool parse_public_key(const std::string& input, std::string& n_hex, std::string& e_hex) {
    n_hex.clear();
    e_hex.clear();

    // 1) Try to read as file path (if short enough and looks like a path)
    std::string content = input;
    {
        FILE* f = fopen_utf8(input.c_str(), "rb");
        if (f) {
            // It's a file - read contents
            fseek(f, 0, SEEK_END);
            long sz = ftell(f);
            fseek(f, 0, SEEK_SET);
            content.resize(sz);
            fread(&content[0], 1, sz, f);
            fclose(f);
        }
    }

    // 2) Check for PEM header (-----BEGIN)
    if (content.find("-----BEGIN") != std::string::npos) {
        if (parse_spki(content, n_hex, e_hex)) return true;
    }

    // 3) Check for OpenSSH (ssh-rsa prefix)
    if (content.substr(0, 7) == "ssh-rsa") {
        return parse_openssh(content, n_hex, e_hex);
    }

    // 4) Try headerless base64 -> DER -> SPKI
    {
        auto der = base64_decode(content);
        if (!der.empty()) {
            // Try as DER SPKI
            BIO* bio = BIO_new_mem_buf(der.data(), (int)der.size());
            EVP_PKEY* pkey = d2i_PUBKEY_bio(bio, nullptr);
            BIO_free(bio);
            if (pkey) {
                RSA* rsa = EVP_PKEY_get1_RSA(pkey);
                EVP_PKEY_free(pkey);
                if (rsa) {
                    const BIGNUM *n_bn, *e_bn;
                    RSA_get0_key(rsa, &n_bn, &e_bn, nullptr);
                    char* n_str = BN_bn2hex(n_bn);
                    char* e_str = BN_bn2hex(e_bn);
                    n_hex = n_str;
                    e_hex = e_str;
                    OPENSSL_free(n_str);
                    OPENSSL_free(e_str);
                    RSA_free(rsa);
                    return true;
                }
            }
        }
    }

    // 5) Treat as raw N hex (with default e=0x10001)
    if (parse_raw_n(content, n_hex)) {
        e_hex = "10001";
        return true;
    }

    return false;
}

// ---------------------------------------------------------------------------
//  N/e hex validation and BigNum conversion
//  Reproduces sub_14002B8A0
// ---------------------------------------------------------------------------

static bool validate_n_e(const std::string& n_hex, const std::string& e_hex,
                         BigNum& N, BigNum& E) {
    if (n_hex.empty() || e_hex.empty()) return false;
    N.set_str(n_hex, 16);
    E.set_str(e_hex, 16);
    return !N.is_zero() && !E.is_zero();
}

// ---------------------------------------------------------------------------
//  Small prime sieve
//  Reproduces sub_14002C2E0 (Sieve of Eratosthenes up to limit)
// ---------------------------------------------------------------------------

static std::vector<uint32_t> sieve_primes(uint32_t limit) {
    std::vector<uint32_t> primes;
    if (limit < 2) return primes;
    // Bitset sieve (matches the original bit-bucket implementation)
    std::vector<uint32_t> bits((limit + 1 + 31) / 32, 0xFFFFFFFF);
    auto get_bit = [&](size_t i) -> bool { return (bits[i >> 5] >> (i & 31)) & 1; };
    auto clr_bit = [&](size_t i) { bits[i >> 5] &= ~(1u << (i & 31)); };

    bits[0] &= ~2u;  // clear 0
    bits[0] &= ~1u;  // clear 1
    for (uint32_t p = 2; (uint64_t)p * p <= limit; ++p) {
        if (get_bit(p)) {
            for (uint64_t i = (uint64_t)p * p; i <= limit; i += p)
                clr_bit(i);
        }
    }
    for (uint32_t i = 2; i <= limit; ++i)
        if (get_bit(i)) primes.push_back(i);
    return primes;
}

// ---------------------------------------------------------------------------
//  Candidate byte generation
//  Reproduces sub_140022200
//
//  Given original byte value and mode, produce list of replacement byte values.
//  - half_nibble mode (a3=1): only swap one nibble, keep the other.
//  - full byte mode (a3=0): all 256 values minus original (complete byte replacement).
// ---------------------------------------------------------------------------

static std::vector<int> generate_candidates(int orig_byte, bool half_nibble_only) {
    std::vector<int> result;
    int hi = orig_byte & 0xF0;
    int lo = orig_byte & 0x0F;

    if (half_nibble_only) {
        // Swap low nibble, keep high nibble
        for (int v = 0; v <= 0xF0; v += 0x10) {
            if (v != hi) result.push_back(hi | v);
        }
        // Swap high nibble, keep low nibble
        for (int v = 0; v < 16; ++v) {
            if (v != lo) result.push_back(lo | (v << 4));
        }
    } else {
        // Full byte replacement: all 256 values except original
        std::vector<unsigned char> present(256, 0);
        // First add the half-nibble candidates (same as above)
        for (int v = 0; v <= 0xF0; v += 0x10) {
            if (v != hi) { result.push_back(hi | v); present[hi | v] = 1; }
        }
        for (int v = 0; v < 16; ++v) {
            if (v != lo) { result.push_back(lo | (v << 4)); present[lo | (v << 4)] = 1; }
        }
        present[orig_byte] = 1;
        // Then all remaining values
        for (int i = 0; i < 256; ++i) {
            if (!present[i]) result.push_back(i);
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
//  Trial division / factorization test
//  Reproduces sub_140022880 + sub_140028B30
//
//  Tests a modified N against small primes and ECM.
//  Returns true if N can be factored, filling in the factor and quotient.
// ---------------------------------------------------------------------------

// Trial division by small primes (the "small prime set" from the sieve)
static bool trial_divide(const BigNum& N, const std::vector<uint32_t>& primes,
                          BigNum& factor, BigNum& quotient) {
    for (uint32_t p : primes) {
        if (mpz_divisible_ui_p(N.v, p)) {
            mpz_set_ui(factor.v, p);
            mpz_divexact_ui(quotient.v, N.v, p);
            return true;
        }
    }
    return false;
}

// Miller-Rabin primality test
static bool is_probable_prime(const BigNum& N) {
    return mpz_probab_prime_p(N.v, 25) > 0;
}

// GCD-based factor recovery (reproduces sub_140028B30 logic)
// Given modified N, original N, and a found factor candidate,
// verify: gcd(N_modified, factor) > 1 and N_modified/factor gives valid p
static bool verify_factor(const BigNum& N_mod, const BigNum& N_orig,
                           const BigNum& factor_candidate, BigNum& p, BigNum& q) {
    BigNum g;
    mpz_gcd(g.v, N_mod.v, factor_candidate.v);
    if (g.is_zero()) return false;
    // N_mod / g should give the other factor
    if (!mpz_divisible_p(N_mod.v, g.v)) return false;
    mpz_divexact(q.v, N_mod.v, g.v);
    mpz_set(p.v, g.v);
    // Verify: p * q == N_mod
    BigNum check;
    mpz_mul(check.v, p.v, q.v);
    return mpz_cmp(check.v, N_mod.v) == 0;
}

// Pollard's rho for medium factors (ECM equivalent for our reproduction)
static bool pollard_rho(const BigNum& N, BigNum& factor, BigNum& quotient) {
    if (mpz_even_p(N.v)) {
        mpz_set_ui(factor.v, 2);
        mpz_divexact_ui(quotient.v, N.v, 2);
        return true;
    }
    BigNum x, y, c, d, diff;
    gmp_randstate_t rstate;
    gmp_randinit_default(rstate);
    gmp_randseed_ui(rstate, (unsigned long)time(nullptr));

    for (int attempt = 0; attempt < 20; ++attempt) {
        mpz_urandomm(x.v, rstate, N.v);
        mpz_set(y.v, x.v);
        mpz_urandomm(c.v, rstate, N.v);
        mpz_set_ui(d.v, 1);
        int iter = 0;
        while (mpz_cmp_ui(d.v, 1) == 0 && iter < 1000000) {
            // x = (x*x + c) mod N
            mpz_mul(x.v, x.v, x.v);
            mpz_add(x.v, x.v, c.v);
            mpz_mod(x.v, x.v, N.v);
            // y = f(f(y))
            mpz_mul(y.v, y.v, y.v);
            mpz_add(y.v, y.v, c.v);
            mpz_mod(y.v, y.v, N.v);
            mpz_mul(y.v, y.v, y.v);
            mpz_add(y.v, y.v, c.v);
            mpz_mod(y.v, y.v, N.v);
            // d = gcd(|x-y|, N)
            mpz_sub(diff.v, x.v, y.v);
            mpz_abs(diff.v, diff.v);
            mpz_gcd(d.v, diff.v, N.v);
            iter++;
        }
        if (mpz_cmp_ui(d.v, 1) > 0 && mpz_cmp(d.v, N.v) < 0) {
            mpz_set(factor.v, d.v);
            mpz_divexact(quotient.v, N.v, d.v);
            gmp_randclear(rstate);
            return true;
        }
    }
    gmp_randclear(rstate);
    return false;
}

// Full factorization test: try small primes, then Pollard rho, then primality
struct FactorResult {
    bool success;
    std::string type;   // "prime" or "factor"
    BigNum factor_val;
    BigNum quotient_val;
    BigNum remainder;
};

static FactorResult try_factorize(const BigNum& N,
                                   const std::vector<uint32_t>& primes,
                                   const std::string& mode,
                                   bool try_prime_mode) {
    FactorResult r;
    r.success = false;

    // 1. Trial division by small primes
    BigNum f, q;
    if (trial_divide(N, primes, f, q)) {
        r.success = true;
        r.type = "factor";
        r.factor_val = f;
        r.quotient_val = q;
        return r;
    }

    // 2. If mode == "factor" or "both", try Pollard rho
    if (mode == "factor" || mode == "both") {
        if (pollard_rho(N, f, q)) {
            r.success = true;
            r.type = "factor";
            r.factor_val = f;
            r.quotient_val = q;
            return r;
        }
    }

    // 3. Check if N itself is prime (for "prime" or "both" mode)
    if (try_prime_mode || mode == "prime" || mode == "both") {
        if (is_probable_prime(N)) {
            r.success = true;
            r.type = "prime";
            r.factor_val = N;
            return r;
        }
    }

    return r;
}

// ---------------------------------------------------------------------------
//  RSA key reconstruction from N, e, p, q
// ---------------------------------------------------------------------------

struct RsaSolution {
    int position;           // byte position in N
    int orig_byte;
    int new_byte;
    std::string type;       // "prime" or "factor"
    BigNum N_new;
    BigNum P;
    BigNum Q;
    BigNum D;
    std::string n_pem;
    std::string d_pem;
};

static bool build_rsa_key(const BigNum& N, const BigNum& E, const BigNum& P,
                          RsaSolution& sol) {
    // Q = N / P
    if (!mpz_divisible_p(N.v, P.v)) return false;
    mpz_divexact(sol.Q.v, N.v, P.v);
    sol.P = P;

    // phi = (P-1)(Q-1)
    BigNum phi, p1, q1;
    mpz_sub_ui(p1.v, P.v, 1);
    mpz_sub_ui(q1.v, sol.Q.v, 1);
    mpz_mul(phi.v, p1.v, q1.v);

    // D = e^-1 mod phi
    if (mpz_invert(sol.D.v, E.v, phi.v) == 0) return false;

    sol.N_new = N;
    return true;
}

// Generate SPKI PEM from N, e
static std::string generate_public_pem(const BigNum& N, const BigNum& E) {
    RSA* rsa = RSA_new();
    BIGNUM* n_bn = BN_new();
    BIGNUM* e_bn = BN_new();
    BN_hex2bn(&n_bn, N.to_hex().c_str());
    BN_hex2bn(&e_bn, E.to_hex().c_str());
    RSA_set0_key(rsa, n_bn, e_bn, nullptr);

    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(bio, rsa);
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(bio, &bptr);
    std::string out(bptr->data, bptr->length);
    BIO_free(bio);
    RSA_free(rsa);
    return out;
}

// Generate PKCS#1 private PEM from N, e, d, p, q
static std::string generate_private_pem(const BigNum& N, const BigNum& E,
                                         const BigNum& D, const BigNum& P,
                                         const BigNum& Q) {
    RSA* rsa = RSA_new();
    BIGNUM *n_bn = BN_new(), *e_bn = BN_new(), *d_bn = BN_new();
    BIGNUM *p_bn = BN_new(), *q_bn = BN_new();
    BN_hex2bn(&n_bn, N.to_hex().c_str());
    BN_hex2bn(&e_bn, E.to_hex().c_str());
    BN_hex2bn(&d_bn, D.to_hex().c_str());
    BN_hex2bn(&p_bn, P.to_hex().c_str());
    BN_hex2bn(&q_bn, Q.to_hex().c_str());

    // Compute dp, dq, qinv
    BIGNUM *dp_bn = BN_new(), *dq_bn = BN_new(), *qi_bn = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    BN_sub(dp_bn, p_bn, BN_value_one());
    BN_mod(dp_bn, d_bn, dp_bn, ctx);  // d mod (p-1)
    BN_sub(dq_bn, q_bn, BN_value_one());
    BN_mod(dq_bn, d_bn, dq_bn, ctx);  // d mod (q-1)
    BN_mod_inverse(qi_bn, q_bn, p_bn, ctx);
    BN_CTX_free(ctx);

    RSA_set0_key(rsa, n_bn, e_bn, d_bn);
    RSA_set0_factors(rsa, p_bn, q_bn);
    RSA_set0_crt_params(rsa, dp_bn, dq_bn, qi_bn);

    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio, rsa, nullptr, nullptr, 0, nullptr, nullptr);
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(bio, &bptr);
    std::string out(bptr->data, bptr->length);
    BIO_free(bio);
    RSA_free(rsa);
    return out;
}

// ---------------------------------------------------------------------------
//  Scanner: one-byte / half-nibble replacement scan
//  Reproduces sub_14002BA40 (the per-thread worker) + sub_140029610 (orchestrator)
// ---------------------------------------------------------------------------

struct ScanParams {
    std::string mode;           // "prime", "factor", "both"
    uint32_t small_prime_limit; // 2~251
    uint32_t thread_count;      // e.g. 8
    bool fast30;                // half-nibble only
    bool stop_first;             // stop at first solution
    bool gen_pem;               // generate PEM in details
    int half_nibble_max;         // max half-nibble solutions, 0=unlimited
    int full_byte_max;           // max full-byte solutions, 0=unlimited
};

struct ScanContext {
    BigNum N_orig;
    BigNum E;
    std::vector<unsigned char> N_bytes;  // big-endian bytes of N
    ScanParams params;
    std::vector<uint32_t> primes;
    std::mutex results_mutex;
    std::vector<RsaSolution> results;
    std::atomic<bool> stop_flag{false};
    std::atomic<uint64_t> attempts{0};
    std::atomic<uint64_t> found_nibble{0};
    std::atomic<uint64_t> found_full{0};
};

// Check if a solution is a half-nibble replacement
static bool is_half_nibble(int orig, int repl) {
    if (orig == repl) return false;
    int diff = orig ^ repl;
    return ((diff & 0xF0) == 0) || ((diff & 0x0F) == 0);
}

// Check whether to continue scanning (reproduces sub_1400220E0)
static bool should_continue(ScanContext& ctx) {
    // Check stop flag
    if (ctx.stop_flag.load()) return false;

    // Check solution limits
    int nibble_count = 0, full_count = 0;
    {
        std::lock_guard<std::mutex> lk(ctx.results_mutex);
        for (auto& s : ctx.results) {
            if (is_half_nibble(s.orig_byte, s.new_byte))
                nibble_count++;
            else
                full_count++;
        }
    }
    if (ctx.params.half_nibble_max > 0 && nibble_count >= ctx.params.half_nibble_max)
        return false;
    if (ctx.params.full_byte_max > 0 && full_count >= ctx.params.full_byte_max)
        return false;

    return true;
}

// Worker function for one byte position range
// Reproduces sub_14002BA40
static void scan_worker(ScanContext& ctx, size_t byte_start, size_t byte_end) {
    std::vector<unsigned char> N_copy = ctx.N_bytes;
    bool try_prime = (ctx.params.mode == "prime" || ctx.params.mode == "both");

    for (size_t pos = byte_start; pos < byte_end; ++pos) {
        if (ctx.stop_flag.load()) break;
        if (!should_continue(ctx)) break;

        int orig_byte = N_copy[pos];

        // Generate candidates for this byte position
        bool half_only = ctx.params.fast30;
        auto candidates = generate_candidates(orig_byte, half_only);

        size_t local_found = 0;

        for (int new_byte : candidates) {
            if (ctx.stop_flag.load()) break;
            if (!should_continue(ctx)) break;

            // Apply replacement
            N_copy[pos] = (unsigned char)new_byte;

            // Convert to BigNum
            BigNum N_mod;
            N_mod.from_bytes_be(N_copy.data(), N_copy.size());

            ctx.attempts.fetch_add(1);

            // Try to factorize
            bool try_prime_mode = try_prime;
            auto fr = try_factorize(N_mod, ctx.primes, ctx.params.mode, try_prime_mode);
            if (!fr.success) continue;

            // Verify and build key
            BigNum P, Q;
            if (fr.type == "factor") {
                if (!verify_factor(N_mod, ctx.N_orig, fr.factor_val, P, Q))
                    continue;
            } else {
                // prime mode: the factor IS P
                P = fr.factor_val;
                if (!mpz_divisible_p(N_mod.v, P.v)) continue;
                mpz_divexact(Q.v, N_mod.v, P.v);
            }

            RsaSolution sol;
            sol.position = (int)pos;
            sol.orig_byte = orig_byte;
            sol.new_byte = new_byte;
            sol.type = fr.type;

            if (build_rsa_key(N_mod, ctx.E, P, sol)) {
                bool is_nib = is_half_nibble(orig_byte, new_byte);

                // Check limits
                {
                    std::lock_guard<std::mutex> lk(ctx.results_mutex);
                    int nc = 0, fc = 0;
                    for (auto& s : ctx.results) {
                        if (is_half_nibble(s.orig_byte, s.new_byte)) nc++;
                        else fc++;
                    }
                    bool ok = true;
                    if (is_nib && ctx.params.half_nibble_max > 0 && nc >= ctx.params.half_nibble_max) ok = false;
                    if (!is_nib && ctx.params.full_byte_max > 0 && fc >= ctx.params.full_byte_max) ok = false;

                    if (ok) {
                        if (ctx.params.gen_pem) {
                            sol.n_pem = generate_public_pem(sol.N_new, ctx.E);
                            sol.d_pem = generate_private_pem(sol.N_new, ctx.E, sol.D, sol.P, sol.Q);
                        }
                        ctx.results.push_back(sol);
                        if (is_nib) ctx.found_nibble.fetch_add(1);
                        else ctx.found_full.fetch_add(1);

                        if (ctx.params.stop_first) {
                            ctx.stop_flag.store(true);
                        }
                        local_found++;
                    }
                }
            }

            // If stop_first and we found something, break inner loop
            if (ctx.params.stop_first && local_found > 0) break;
        }

        // Restore original byte
        N_copy[pos] = (unsigned char)orig_byte;
    }
}

// Main scan orchestrator (reproduces sub_140029610)
static void run_scan(ScanContext& ctx) {
    // Generate small primes
    ctx.primes = sieve_primes(ctx.params.small_prime_limit);

    // Get N bytes (big-endian)
    ctx.N_bytes = ctx.N_orig.to_bytes_be();

    // Determine thread count
    size_t nthreads = ctx.params.thread_count;
    if (nthreads < 1) nthreads = 1;
    size_t total_bytes = ctx.N_bytes.size();
    if (nthreads > total_bytes) nthreads = total_bytes;
    if (nthreads < 1) nthreads = 1;

    // Divide byte positions among threads
    std::vector<std::thread> threads;
    size_t chunk = (total_bytes + nthreads - 1) / nthreads;
    if (chunk == 0) chunk = 1;

    for (size_t i = 0; i < nthreads; ++i) {
        size_t start = i * chunk;
        size_t end = std::min(start + chunk, total_bytes);
        if (start >= total_bytes) break;
        threads.emplace_back(scan_worker, std::ref(ctx), start, end);
    }

    for (auto& t : threads) t.join();
}

// ---------------------------------------------------------------------------
//  Output / export functions
//  Reproduce sub_140012A60 (export) and sub_1400189A0 (report)
// ---------------------------------------------------------------------------

static void print_solution(const RsaSolution& sol, const BigNum& N_orig, const BigNum& E) {
    printf("#  pos=%d  %02X->%02X  type=%s  mode=%s  P=%s\n",
           sol.position, sol.orig_byte, sol.new_byte,
           sol.type.c_str(),
           is_half_nibble(sol.orig_byte, sol.new_byte) ? "half" : "full",
           sol.P.to_hex().c_str());
    printf("    N_new = %s\n", sol.N_new.to_hex().c_str());
    printf("    P = %s\n", sol.P.to_hex().c_str());
    printf("    Q = %s\n", sol.Q.to_hex().c_str());
    printf("    D = %s\n", sol.D.to_hex().c_str());

    // Show N diff (highlight changed byte)
    auto orig_bytes = N_orig.to_bytes_be();
    auto new_bytes = sol.N_new.to_bytes_be();
    printf("    N diff: ");
    for (size_t i = 0; i < new_bytes.size(); ++i) {
        if (i < orig_bytes.size() && orig_bytes[i] != new_bytes[i])
            printf("[%02X]", new_bytes[i]);  // changed byte highlighted
        else
            printf("%02X", new_bytes[i]);
    }
    printf("\n");
}

static void export_keys(const RsaSolution& sol, const BigNum& E,
                        const std::string& out_prefix) {
    // Public key PEM
    std::string pub_pem = generate_public_pem(sol.N_new, E);
    std::string pub_path = out_prefix + "_pub.pem";
    write_file_utf8(pub_path, pub_pem);
    printf("  Public key  -> %s\n", pub_path.c_str());

    // Private key PEM
    std::string priv_pem = generate_private_pem(sol.N_new, E, sol.D, sol.P, sol.Q);
    std::string priv_path = out_prefix + "_priv.pem";
    write_file_utf8(priv_path, priv_pem);
    printf("  Private key -> %s\n", priv_path.c_str());

    // Info file
    std::string info_path = out_prefix + "_info.txt";
    std::ostringstream oss;
    oss << "Position: " << sol.position << "\n";
    oss << "Original byte: 0x" << std::hex << sol.orig_byte << "\n";
    oss << "New byte: 0x" << sol.new_byte << "\n";
    oss << "Type: " << sol.type << "\n";
    oss << "Mode: " << (is_half_nibble(sol.orig_byte, sol.new_byte) ? "half-nibble" : "full-byte") << "\n";
    oss << "N_new (hex): " << sol.N_new.to_hex() << "\n";
    oss << "P (hex): " << sol.P.to_hex() << "\n";
    oss << "Q (hex): " << sol.Q.to_hex() << "\n";
    oss << "D (hex): " << sol.D.to_hex() << "\n";
    write_file_utf8(info_path, oss.str());
    printf("  Info        -> %s\n", info_path.c_str());
}

// ---------------------------------------------------------------------------
//  CLI argument parsing
// ---------------------------------------------------------------------------

static void usage(const char* prog) {
    printf("PatchRSA OneByte - Cross-platform RSA one-byte patcher\n");
    printf("Usage: %s [options] <public_key_input>\n", prog);
    printf("\n");
    printf("Options:\n");
    printf("  -k <input>      Public key input (PEM / headerless base64 / raw N hex / OpenSSH / file path)\n");
    printf("  --mode <m>      Factorization mode: prime | factor | both (default: factor)\n");
    printf("  --primes <n>    Small prime limit 2~251 (default: 251)\n");
    printf("  --threads <n>   Thread count (default: 8)\n");
    printf("  --fast30        Half-nibble replacement only\n");
    printf("  --stop-first     Stop at first solution\n");
    printf("  --gen-pem       Generate PEM in details\n");
    printf("  --nibble-max <n>  Max half-nibble solutions, 0=unlimited (default: 5)\n");
    printf("  --byte-max <n>   Max full-byte solutions, 0=unlimited (default: 5)\n");
    printf("  --export <dir>   Export keys to directory\n");
    printf("  --parse-only    Only parse public key, show N and e\n");
    printf("\n");
    printf("Example:\n");
    printf("  %s -k \"-----BEGIN PUBLIC KEY-----\\n...\" --mode both --primes 251 --threads 8\n", prog);
    printf("  %s -k duDe1rHc22OLeI9tElSw... --mode factor --fast30 --stop-first\n", prog);
}

int main(int argc, char* argv[]) {
    // On Windows, convert argv to UTF-8 if needed (CLI11 ensure_utf8 equivalent)
    // This handles the Chinese-path encoding issue described in the requirements.
#if defined(_WIN32)
    // Get wide command line and convert each arg to UTF-8
    int wargc;
    LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
    if (wargv) {
        for (int i = 0; i < argc && i < wargc; ++i) {
            int len = WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, nullptr, 0, nullptr, nullptr);
            if (len > 0) {
                char* buf = new char[len];
                WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, buf, len, nullptr, nullptr);
                argv[i] = buf;  // leak intentionally for simplicity (process lifetime)
            }
        }
        LocalFree(wargv);
    }
#endif

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    std::string key_input;
    ScanParams params;
    params.mode = "factor";
    params.small_prime_limit = 251;
    params.thread_count = 8;
    params.fast30 = false;
    params.stop_first = false;
    params.gen_pem = false;
    params.half_nibble_max = 5;
    params.full_byte_max = 5;
    std::string export_dir;
    bool parse_only = false;

    // Simple argument parsing
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") { usage(argv[0]); return 0; }
        else if (arg == "-k" && i + 1 < argc) { key_input = argv[++i]; }
        else if (arg == "--mode" && i + 1 < argc) { params.mode = argv[++i]; }
        else if (arg == "--primes" && i + 1 < argc) { params.small_prime_limit = (uint32_t)atoi(argv[++i]); }
        else if (arg == "--threads" && i + 1 < argc) { params.thread_count = (uint32_t)atoi(argv[++i]); }
        else if (arg == "--fast30") { params.fast30 = true; }
        else if (arg == "--stop-first") { params.stop_first = true; }
        else if (arg == "--gen-pem") { params.gen_pem = true; }
        else if (arg == "--nibble-max" && i + 1 < argc) { params.half_nibble_max = atoi(argv[++i]); }
        else if (arg == "--byte-max" && i + 1 < argc) { params.full_byte_max = atoi(argv[++i]); }
        else if (arg == "--export" && i + 1 < argc) { export_dir = argv[++i]; }
        else if (arg == "--parse-only") { parse_only = true; }
        else if (arg[0] != '-' && key_input.empty()) { key_input = arg; }
    }

    if (key_input.empty()) {
        fprintf(stderr, "Error: no public key input provided. Use -k <input>.\n\n");
        usage(argv[0]);
        return 1;
    }

    // Step 1: Parse public key
    printf("[*] Parsing public key...\n");
    std::string n_hex, e_hex;
    if (!parse_public_key(key_input, n_hex, e_hex)) {
        fprintf(stderr, "[!] Failed to parse public key input.\n");
        return 1;
    }

    // Show bit length
    BigNum N, E;
    if (!validate_n_e(n_hex, e_hex, N, E)) {
        fprintf(stderr, "[!] Invalid N/e values.\n");
        return 1;
    }

    size_t n_bits = mpz_sizeinbase(N.v, 2);
    size_t e_bits = mpz_sizeinbase(E.v, 2);
    printf("    N (%zu bit) = %s\n", n_bits, n_hex.c_str());
    printf("    e (%zu bit) = %s\n", e_bits, e_hex.c_str());

    if (parse_only) return 0;

    // Step 2: Run scan
    printf("\n[*] Starting scan (mode=%s, primes<=%u, threads=%u, fast30=%d)...\n",
           params.mode.c_str(), params.small_prime_limit, params.thread_count,
           (int)params.fast30);

    ScanContext ctx;
    ctx.N_orig = N;
    ctx.E = E;
    ctx.params = params;

    auto t0 = std::chrono::steady_clock::now();
    run_scan(ctx);
    auto t1 = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(t1 - t0).count();

    // Count solutions
    int nib = 0, full = 0;
    for (auto& s : ctx.results) {
        if (is_half_nibble(s.orig_byte, s.new_byte)) nib++;
        else full++;
    }

    printf("\n[*] Scan complete: %d solutions (half %d / full %d), %llu attempts, %.2fs\n",
           (int)ctx.results.size(), nib, full,
           (unsigned long long)ctx.attempts.load(), elapsed);

    // Step 3: Print solutions
    for (int i = 0; i < (int)ctx.results.size(); ++i) {
        printf("\n--- Solution #%d ---\n", i + 1);
        print_solution(ctx.results[i], N, E);
    }

    // Step 4: Export
    if (!export_dir.empty() && !ctx.results.empty()) {
        mkdir_recursive(export_dir);
        for (int i = 0; i < (int)ctx.results.size(); ++i) {
            std::string prefix = export_dir + "/patched_" + std::to_string(i + 1);
            printf("\n[*] Exporting solution #%d...\n", i + 1);
            export_keys(ctx.results[i], E, prefix);
        }
    }

    EVP_cleanup();
    return 0;
}
