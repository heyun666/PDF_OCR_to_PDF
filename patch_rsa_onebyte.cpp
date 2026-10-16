// =============================================================================
//  PatchRSA OneByte - Cross-platform C++ reproduction (OpenSSL BIGNUM only)
//  Reverse-engineered from PatchRSA_OneByte_Cpp.exe
//
//  Build (MSVC, C++17):  cl /std:c++17 /EHsc /D_CRT_SECURE_NO_WARNINGS patch_rsa_onebyte.cpp libcrypto.lib ws2_32.lib
//  Build (MinGW, C++17): g++ -std=c++17 -O2 -o patch_rsa_onebyte.exe patch_rsa_onebyte.cpp -lcrypto -lws2_32
//  Build (Linux, C++17): g++ -std=c++17 -O2 -lpthread -o patch_rsa_onebyte patch_rsa_onebyte.cpp -lcrypto
//
//  Dependencies: OpenSSL (libcrypto) only.
// =============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cctype>
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

// OpenSSL
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// ---------------------------------------------------------------------------
//  Platform portability layer for file I/O (UTF-16 on Windows)
// ---------------------------------------------------------------------------

#if defined(_WIN32)
  #include <windows.h>
  #include <io.h>
  #include <fcntl.h>
  #include <direct.h>

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

  static int mkdir_utf8(const char* path) {
      int wlen = MultiByteToWideChar(CP_UTF8, 0, path, -1, nullptr, 0);
      if (wlen <= 0) return -1;
      std::vector<wchar_t> wpath(wlen);
      MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath.data(), wlen);
      return _wmkdir(wpath.data());
  }

  #define MKDIR_ONE(p) mkdir_utf8(p)

  static void mkdir_recursive(const std::string& path) {
      if (path.empty()) return;
      int wlen = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
      if (wlen <= 0) return;
      std::vector<wchar_t> wpath(wlen);
      MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, wpath.data(), wlen);
      std::wstring ws(wpath.data());
      for (size_t i = 1; i < ws.size(); ++i) {
          if (ws[i] == L'\\' || ws[i] == L'/') {
              std::wstring sub = ws.substr(0, i);
              CreateDirectoryW(sub.c_str(), nullptr);
          }
      }
      CreateDirectoryW(ws.c_str(), nullptr);
  }

#else
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
//  BigNum wrapper around OpenSSL BIGNUM (RAII + copy semantics)
// ---------------------------------------------------------------------------

class BigNum {
public:
    BIGNUM* b = nullptr;

    BigNum() { b = BN_new(); }
    ~BigNum() { if (b) BN_free(b); }

    BigNum(const BigNum& o) {
        b = BN_new();
        BN_copy(b, o.b);
    }
    BigNum& operator=(const BigNum& o) {
        if (this != &o) BN_copy(b, o.b);
        return *this;
    }
    BigNum(BigNum&& o) noexcept : b(o.b) { o.b = nullptr; }
    BigNum& operator=(BigNum&& o) noexcept {
        if (this != &o) { if (b) BN_free(b); b = o.b; o.b = nullptr; }
        return *this;
    }

    void set_zero() { BN_zero(b); }
    void set_ui(unsigned long v) { BN_set_word(b, v); }

    // Set from a string in the given base ("16" or "10"). Leading '0x' accepted.
    bool set_str(const std::string& s, int base) {
        if (base == 16) {
            // BN_hex2bn handles "0x" prefix? No. Strip it.
            const char* p = s.c_str();
            if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) p = s.c_str() + 2;
            return BN_hex2bn(&b, p) != 0;
        } else {
            return BN_dec2bn(&b, s.c_str()) != 0;
        }
    }

    std::string to_hex() const {
        char* h = BN_bn2hex(b);
        if (!h) return "";
        std::string r(h);
        OPENSSL_free(h);
        // BN_bn2hex uses uppercase; original GMP output was lowercase.
        for (auto& c : r) c = (char)tolower((unsigned char)c);
        return r;
    }
    std::string to_dec() const {
        char* h = BN_bn2dec(b);
        if (!h) return "";
        std::string r(h);
        OPENSSL_free(h);
        return r;
    }

    size_t byte_size() const { return (size_t)BN_num_bytes(b); }

    // Export as big-endian bytes
    std::vector<unsigned char> to_bytes_be() const {
        size_t n = byte_size();
        std::vector<unsigned char> buf(n);
        if (n > 0) BN_bn2bin(b, buf.data());
        return buf;
    }

    void from_bytes_be(const unsigned char* data, size_t len) {
        BN_bin2bn(data, (int)len, b);
    }

    bool is_zero() const { return BN_is_zero(b); }
    bool is_even() const { return BN_is_bit_set(b, 0) == 0; }
    int  cmp(const BigNum& o) const { return BN_cmp(b, o.b); }
};

// Convenience helpers ---------------------------------------------------------

static bool bn_is_probable_prime(const BigNum& N, int checks) {
    BN_CTX* ctx = BN_CTX_new();
    int r = BN_is_prime_ex(N.b, checks, ctx, nullptr);
    BN_CTX_free(ctx);
    return r == 1;
}

// q = a / b (exact) -- returns false if not divisible
static bool bn_divexact(BigNum& q, const BigNum& a, const BigNum& b) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* rem = BN_new();
    bool ok = false;
    if (BN_div(q.b, rem, a.b, b.b, ctx) && BN_is_zero(rem)) ok = true;
    BN_free(rem);
    BN_CTX_free(ctx);
    return ok;
}

static bool bn_divisible(const BigNum& a, const BigNum& b) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* rem = BN_new();
    BN_div(nullptr, rem, a.b, b.b, ctx);
    bool ok = BN_is_zero(rem);
    BN_free(rem);
    BN_CTX_free(ctx);
    return ok;
}

static bool bn_divisible_ui(const BigNum& a, unsigned long v) {
    BN_ULONG rem = BN_mod_word(a.b, v);
    return rem == 0;
}

// ---------------------------------------------------------------------------
//  RSA key parsing
// ---------------------------------------------------------------------------

struct RsaKeyInfo {
    std::string n_hex;
    std::string e_hex;
    std::string mode;
};

// Extract N, e from an EVP_PKEY (handles RSA and RSA-PSS in OpenSSL 3).
static bool extract_n_e_from_pkey(EVP_PKEY* pkey, std::string& n_hex, std::string& e_hex) {
    BIGNUM* n_bn = nullptr;
    BIGNUM* e_bn = nullptr;
    // OpenSSL 3 path
    if (EVP_PKEY_get_bn_param(pkey, "n", &n_bn) == 1 &&
        EVP_PKEY_get_bn_param(pkey, "e", &e_bn) == 1) {
        char* ns = BN_bn2hex(n_bn);
        char* es = BN_bn2hex(e_bn);
        n_hex = ns; e_hex = es;
        for (auto& c : n_hex) c = (char)tolower((unsigned char)c);
        for (auto& c : e_hex) c = (char)tolower((unsigned char)c);
        OPENSSL_free(ns);
        OPENSSL_free(es);
        BN_free(n_bn);
        BN_free(e_bn);
        return true;
    }
    if (n_bn) BN_free(n_bn);
    if (e_bn) BN_free(e_bn);
    // Fallback for OpenSSL 1.1
    RSA* rsa = EVP_PKEY_get1_RSA(pkey);
    if (!rsa) return false;
    const BIGNUM *rn = nullptr, *re = nullptr;
    RSA_get0_key(rsa, &rn, &re, nullptr);
    if (!rn || !re) { RSA_free(rsa); return false; }
    char* ns = BN_bn2hex(rn);
    char* es = BN_bn2hex(re);
    n_hex = ns; e_hex = es;
    for (auto& c : n_hex) c = (char)tolower((unsigned char)c);
    for (auto& c : e_hex) c = (char)tolower((unsigned char)c);
    OPENSSL_free(ns);
    OPENSSL_free(es);
    RSA_free(rsa);
    return true;
}

static bool parse_spki(const std::string& pem_text, std::string& n_hex, std::string& e_hex) {
    BIO* bio = BIO_new_mem_buf(pem_text.data(), (int)pem_text.size());
    if (!bio) return false;
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) return false;
    bool ok = extract_n_e_from_pkey(pkey, n_hex, e_hex);
    EVP_PKEY_free(pkey);
    return ok;
}

static bool parse_openssh(const std::string& line, std::string& n_hex, std::string& e_hex) {
    auto sp = line.find(' ');
    if (sp == std::string::npos) return false;
    std::string b64part = line.substr(sp + 1);
    while (!b64part.empty() && (b64part.back() == '\n' || b64part.back() == '\r' || b64part.back() == ' '))
        b64part.pop_back();
    auto decoded = base64_decode(b64part);
    if (decoded.empty()) return false;

    size_t pos = 0;
    auto read_u32 = [&](uint32_t& out) -> bool {
        if (pos + 4 > decoded.size()) return false;
        out = ((uint32_t)decoded[pos]<<24)|((uint32_t)decoded[pos+1]<<16)|((uint32_t)decoded[pos+2]<<8)|decoded[pos+3];
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

    BigNum e_val, n_val;
    if (!e_bytes.empty()) e_val.from_bytes_be(e_bytes.data(), e_bytes.size());
    if (!n_bytes.empty()) n_val.from_bytes_be(n_bytes.data(), n_bytes.size());
    n_hex = n_val.to_hex();
    e_hex = e_val.to_hex();
    return true;
}

static bool parse_raw_n(const std::string& input, std::string& n_hex) {
    std::string s;
    for (char c : input) {
        if (isxdigit((unsigned char)c)) s += (char)tolower((unsigned char)c);
    }
    if (s.empty()) return false;
    n_hex = s;
    return true;
}

static bool parse_public_key(const std::string& input, std::string& n_hex, std::string& e_hex) {
    n_hex.clear();
    e_hex.clear();

    std::string content = input;
    {
        FILE* f = fopen_utf8(input.c_str(), "rb");
        if (f) {
            fseek(f, 0, SEEK_END);
            long sz = ftell(f);
            fseek(f, 0, SEEK_SET);
            content.resize(sz > 0 ? sz : 0);
            if (sz > 0) fread(&content[0], 1, sz, f);
            fclose(f);
        }
    }

    if (content.find("-----BEGIN") != std::string::npos) {
        if (parse_spki(content, n_hex, e_hex)) return true;
    }

    if (content.size() >= 7 && content.compare(0, 7, "ssh-rsa") == 0) {
        return parse_openssh(content, n_hex, e_hex);
    }

    {
        auto der = base64_decode(content);
        if (!der.empty()) {
            const unsigned char* p = der.data();
            EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &p, (long)der.size());
            if (pkey) {
                bool ok = extract_n_e_from_pkey(pkey, n_hex, e_hex);
                EVP_PKEY_free(pkey);
                if (ok) return true;
            }
        }
    }

    if (parse_raw_n(content, n_hex)) {
        e_hex = "10001";
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
//  N/e hex validation
// ---------------------------------------------------------------------------

static bool validate_n_e(const std::string& n_hex, const std::string& e_hex,
                         BigNum& N, BigNum& E) {
    if (n_hex.empty() || e_hex.empty()) return false;
    if (!N.set_str(n_hex, 16)) return false;
    if (!E.set_str(e_hex, 16)) return false;
    return !N.is_zero() && !E.is_zero();
}

// ---------------------------------------------------------------------------
//  Small prime sieve
// ---------------------------------------------------------------------------

static std::vector<uint32_t> sieve_primes(uint32_t limit) {
    std::vector<uint32_t> primes;
    if (limit < 2) return primes;
    std::vector<uint32_t> bits((limit + 1 + 31) / 32, 0xFFFFFFFFu);
    auto get_bit = [&](size_t i) -> bool { return (bits[i >> 5] >> (i & 31)) & 1; };
    auto clr_bit = [&](size_t i) { bits[i >> 5] &= ~(1u << (i & 31)); };

    bits[0] &= ~2u;
    bits[0] &= ~1u;
    for (uint32_t p = 2; (uint64_t)p * p <= limit; ++p) {
        if (get_bit(p)) {
            for (uint64_t i = (uint64_t)p * p; i <= limit; i += p)
                clr_bit((size_t)i);
        }
    }
    for (uint32_t i = 2; i <= limit; ++i)
        if (get_bit(i)) primes.push_back(i);
    return primes;
}

// ---------------------------------------------------------------------------
//  Candidate byte generation
// ---------------------------------------------------------------------------

static std::vector<int> generate_candidates(int orig_byte, bool half_nibble_only) {
    std::vector<int> result;
    int hi = orig_byte & 0xF0;
    int lo = orig_byte & 0x0F;

    if (half_nibble_only) {
        for (int v = 0; v <= 0xF0; v += 0x10) {
            if (v != hi) result.push_back(hi | v);
        }
        for (int v = 0; v < 16; ++v) {
            if (v != lo) result.push_back(lo | (v << 4));
        }
    } else {
        std::vector<unsigned char> present(256, 0);
        for (int v = 0; v <= 0xF0; v += 0x10) {
            if (v != hi) { result.push_back(hi | v); present[hi | v] = 1; }
        }
        for (int v = 0; v < 16; ++v) {
            if (v != lo) { result.push_back(lo | (v << 4)); present[lo | (v << 4)] = 1; }
        }
        present[orig_byte] = 1;
        for (int i = 0; i < 256; ++i) {
            if (!present[i]) result.push_back(i);
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
//  Factorization helpers
// ---------------------------------------------------------------------------

static bool trial_divide(const BigNum& N, const std::vector<uint32_t>& primes,
                          BigNum& factor, BigNum& quotient) {
    for (uint32_t p : primes) {
        if (bn_divisible_ui(N, p)) {
            factor.set_ui(p);
            BN_div(quotient.b, nullptr, N.b, factor.b, BN_CTX_new());
            // NOTE: leaks the ctx above -- acceptable for a one-shot; but let's
            // rewrite cleanly to avoid the leak.
            return true;
        }
    }
    return false;
}

// Cleaner trial division (no ctx leak).
static bool trial_divide_clean(const BigNum& N, const std::vector<uint32_t>& primes,
                                BigNum& factor, BigNum& quotient) {
    BN_CTX* ctx = BN_CTX_new();
    bool found = false;
    for (uint32_t p : primes) {
        if (BN_mod_word(N.b, p) == 0) {
            factor.set_ui(p);
            BN_div(quotient.b, nullptr, N.b, factor.b, ctx);
            found = true;
            break;
        }
    }
    BN_CTX_free(ctx);
    return found;
}

// Pollard's rho (Brent-style) using OpenSSL BIGNUM.
static bool pollard_rho(const BigNum& N, BigNum& factor, BigNum& quotient) {
    if (N.is_even()) {
        factor.set_ui(2);
        BN_div(quotient.b, nullptr, N.b, factor.b, BN_CTX_new());
        return true;
    }
    if (BN_cmp(N.b, BN_value_one()) <= 0) return false;

    BN_CTX* ctx = BN_CTX_new();
    BigNum x, y, c, d, diff, tmp, x2;
    BigNum n_minus_1;
    BN_sub_word(BN_copy(n_minus_1.b, N.b), 1);

    bool ok = false;
    const int max_attempts = 20;
    const int max_iters = 1000000;

    for (int attempt = 0; attempt < max_attempts && !ok; ++attempt) {
        // x = random in [0, N-1]
        BN_rand_range(x.b, N.b);
        BN_copy(y.b, x.b);
        BN_rand_range(c.b, N.b);
        d.set_ui(1);

        int iter = 0;
        while (BN_is_one(d.b) && iter < max_iters) {
            // x = x^2 + c mod N
            BN_mod_mul(tmp.b, x.b, x.b, N.b, ctx);
            BN_mod_add(x.b, tmp.b, c.b, N.b, ctx);
            // y = f(f(y))
            BN_mod_mul(tmp.b, y.b, y.b, N.b, ctx);
            BN_mod_add(y.b, tmp.b, c.b, N.b, ctx);
            BN_mod_mul(tmp.b, y.b, y.b, N.b, ctx);
            BN_mod_add(y.b, tmp.b, c.b, N.b, ctx);
            // d = gcd(|x-y|, N)
            BN_mod_sub(diff.b, x.b, y.b, N.b, ctx);
            BN_gcd(d.b, diff.b, N.b, ctx);
            ++iter;
        }
        if (!BN_is_one(d.b) && BN_cmp(d.b, N.b) < 0) {
            BN_copy(factor.b, d.b);
            BN_div(quotient.b, nullptr, N.b, factor.b, ctx);
            ok = true;
        }
    }
    BN_CTX_free(ctx);
    return ok;
}

// ---------------------------------------------------------------------------
//  Full factorization test
// ---------------------------------------------------------------------------

struct FactorResult {
    bool success = false;
    std::string type;        // "prime" or "factor"
    BigNum factor_val;
    BigNum quotient_val;
    BigNum remainder;
};

static FactorResult try_factorize(const BigNum& N,
                                  const std::vector<uint32_t>& primes,
                                  const std::string& mode,
                                  bool try_prime_mode) {
    FactorResult r;

    // 1. Trial division by small primes
    {
        BigNum f, q;
        if (trial_divide_clean(N, primes, f, q)) {
            r.success = true;
            r.type = "factor";
            r.factor_val = f;
            r.quotient_val = q;
            return r;
        }
    }

    // 2. Pollard rho
    if (mode == "factor" || mode == "both") {
        BigNum f, q;
        if (pollard_rho(N, f, q)) {
            r.success = true;
            r.type = "factor";
            r.factor_val = f;
            r.quotient_val = q;
            return r;
        }
    }

    // 3. Primality
    if (try_prime_mode || mode == "prime" || mode == "both") {
        if (bn_is_probable_prime(N, 25)) {
            r.success = true;
            r.type = "prime";
            r.factor_val = N;
            return r;
        }
    }

    return r;
}

// ---------------------------------------------------------------------------
//  RSA key reconstruction
// ---------------------------------------------------------------------------

struct RsaSolution {
    int position = 0;
    int orig_byte = 0;
    int new_byte = 0;
    std::string type;
    BigNum N_new;
    BigNum P;
    BigNum Q;
    BigNum D;
    std::string n_pem;
    std::string d_pem;
};

static bool build_rsa_key(const BigNum& N_mod, const BigNum& E, const BigNum& P,
                          RsaSolution& sol) {
    if (!bn_divisible(N_mod, P)) return false;

    BigNum Q;
    if (!bn_divexact(Q, N_mod, P)) return false;

    BigNum phi, p1, q1;
    BN_sub_word(BN_copy(p1.b, P.b), 1);
    BN_sub_word(BN_copy(q1.b, Q.b), 1);
    BN_mul(phi.b, p1.b, q1.b, BN_CTX_new());

    BigNum D;
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* inv = BN_mod_inverse(nullptr, E.b, phi.b, ctx);
    BN_CTX_free(ctx);
    if (!inv) return false;
    BN_copy(D.b, inv);
    BN_free(inv);

    sol.N_new = N_mod;
    sol.P = P;
    sol.Q = Q;
    sol.D = D;
    return true;
}

// ---------------------------------------------------------------------------
//  PEM generation
// ---------------------------------------------------------------------------

static std::string generate_public_pem(const BigNum& N, const BigNum& E) {
    RSA* rsa = RSA_new();
    BIGNUM* n_bn = BN_dup(N.b);
    BIGNUM* e_bn = BN_dup(E.b);
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

static std::string generate_private_pem(const BigNum& N, const BigNum& E,
                                         const BigNum& D, const BigNum& P,
                                         const BigNum& Q) {
    RSA* rsa = RSA_new();
    BIGNUM* n_bn = BN_dup(N.b);
    BIGNUM* e_bn = BN_dup(E.b);
    BIGNUM* d_bn = BN_dup(D.b);
    BIGNUM* p_bn = BN_dup(P.b);
    BIGNUM* q_bn = BN_dup(Q.b);

    BIGNUM* dp_bn = BN_new();
    BIGNUM* dq_bn = BN_new();
    BIGNUM* qi_bn = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* pm1 = BN_dup(p_bn);
    BIGNUM* qm1 = BN_dup(q_bn);
    BN_sub_word(pm1, 1);
    BN_sub_word(qm1, 1);
    BN_mod(dp_bn, d_bn, pm1, ctx);
    BN_mod(dq_bn, d_bn, qm1, ctx);
    BN_mod_inverse(qi_bn, q_bn, p_bn, ctx);
    BN_free(pm1);
    BN_free(qm1);
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
//  Scanner
// ---------------------------------------------------------------------------

struct ScanParams {
    std::string mode = "factor";
    uint32_t small_prime_limit = 251;
    uint32_t thread_count = 8;
    bool fast30 = false;
    bool stop_first = false;
    bool gen_pem = false;
    int half_nibble_max = 5;
    int full_byte_max = 5;
};

struct ScanContext {
    BigNum N_orig;
    BigNum E;
    std::vector<unsigned char> N_bytes;
    ScanParams params;
    std::vector<uint32_t> primes;
    std::mutex results_mutex;
    std::vector<RsaSolution> results;
    std::atomic<bool> stop_flag{false};
    std::atomic<uint64_t> attempts{0};
    std::atomic<uint64_t> found_nibble{0};
    std::atomic<uint64_t> found_full{0};
};

static bool is_half_nibble(int orig, int repl) {
    if (orig == repl) return false;
    int diff = orig ^ repl;
    return ((diff & 0xF0) == 0) || ((diff & 0x0F) == 0);
}

static bool should_continue(ScanContext& ctx) {
    if (ctx.stop_flag.load()) return false;
    int nibble_count = 0, full_count = 0;
    {
        std::lock_guard<std::mutex> lk(ctx.results_mutex);
        for (auto& s : ctx.results) {
            if (is_half_nibble(s.orig_byte, s.new_byte)) nibble_count++;
            else full_count++;
        }
    }
    if (ctx.params.half_nibble_max > 0 && nibble_count >= ctx.params.half_nibble_max)
        return false;
    if (ctx.params.full_byte_max > 0 && full_count >= ctx.params.full_byte_max)
        return false;
    return true;
}

static void scan_worker(ScanContext& ctx, size_t byte_start, size_t byte_end) {
    std::vector<unsigned char> N_copy = ctx.N_bytes;
    bool try_prime = (ctx.params.mode == "prime" || ctx.params.mode == "both");

    for (size_t pos = byte_start; pos < byte_end; ++pos) {
        if (ctx.stop_flag.load()) break;
        if (!should_continue(ctx)) break;

        int orig_byte = N_copy[pos];
        bool half_only = ctx.params.fast30;
        auto candidates = generate_candidates(orig_byte, half_only);

        size_t local_found = 0;

        for (int new_byte : candidates) {
            if (ctx.stop_flag.load()) break;
            if (!should_continue(ctx)) break;

            N_copy[pos] = (unsigned char)new_byte;

            BigNum N_mod;
            N_mod.from_bytes_be(N_copy.data(), N_copy.size());

            ctx.attempts.fetch_add(1);
