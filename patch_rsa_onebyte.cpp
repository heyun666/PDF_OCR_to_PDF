// =============================================================================
//  PatchRSA OneByte - Cross-platform C++ reproduction + Win32 GUI
// =============================================================================
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS

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
//  Compatibility shims
// ---------------------------------------------------------------------------
#if __cplusplus < 201402L
namespace std11 {
template <typename T, typename... Args>
std::unique_ptr<T> make_unique(Args&&... args) {
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}
}
using std11::make_unique;
#endif

// ---------------------------------------------------------------------------
//  Platform portability layer (UTF-8 file I/O on Windows)
// ---------------------------------------------------------------------------
#if defined(_WIN32)
  #include <windows.h>
  #include <commctrl.h>
  #include <shellapi.h>
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
          if (path[i] == '/') { if (!cur.empty()) MKDIR_ONE(cur.c_str()); }
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
    if (sz > 0) { data.resize(sz); fread(&data[0], 1, sz, f); }
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
//  Base64
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
    if (n > 0) out.resize(n); else out.clear();
    BIO_free_all(b64);
    return out;
}

// ---------------------------------------------------------------------------
//  BigNum wrapper
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
        std::string r(h); free(h); return r;
    }
    std::string to_dec() const {
        char* h = mpz_get_str(nullptr, 10, v);
        std::string r(h); free(h); return r;
    }
    size_t byte_size() const {
        size_t bits = mpz_sizeinbase(v, 2);
        return (bits + 7) / 8;
    }
    std::vector<unsigned char> to_bytes_be() const {
        size_t n = byte_size();
        std::vector<unsigned char> buf(n);
        size_t written = 0;
        mpz_export(buf.data(), &written, 1, 1, 0, 0, v);
        if (written < n) buf.insert(buf.begin() + written, n - written, 0);
        buf.resize(n);
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
//  RSA key parsing
// ---------------------------------------------------------------------------
struct RsaKeyInfo {
    std::string n_hex;
    std::string e_hex;
    std::string mode;
};

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
    BigNum e_val, n_val;
    if (!e_bytes.empty()) e_val.from_bytes_be(e_bytes.data(), e_bytes.size());
    if (!n_bytes.empty()) n_val.from_bytes_be(n_bytes.data(), n_bytes.size());
    n_hex = n_val.to_hex();
    e_hex = e_val.to_hex();
    return true;
}

static bool parse_raw_n(const std::string& input, std::string& n_hex) {
    std::string s;
    for (char c : input) if (isxdigit((unsigned char)c)) s += tolower(c);
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
            content.resize(sz);
            fread(&content[0], 1, sz, f);
            fclose(f);
        }
    }

    if (content.find("-----BEGIN") != std::string::npos) {
        if (parse_spki(content, n_hex, e_hex)) return true;
    }
    if (content.substr(0, 7) == "ssh-rsa") {
        return parse_openssh(content, n_hex, e_hex);
    }
    {
        auto der = base64_decode(content);
        if (!der.empty()) {
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
    if (parse_raw_n(content, n_hex)) {
        e_hex = "10001";
        return true;
    }
    return false;
}

static bool validate_n_e(const std::string& n_hex, const std::string& e_hex,
                         BigNum& N, BigNum& E) {
    if (n_hex.empty() || e_hex.empty()) return false;
    N.set_str(n_hex, 16);
    E.set_str(e_hex, 16);
    return !N.is_zero() && !E.is_zero();
}

// ---------------------------------------------------------------------------
//  Sieve, candidates, factorization  (unchanged from your original)
// ---------------------------------------------------------------------------
static std::vector<uint32_t> sieve_primes(uint32_t limit) {
    std::vector<uint32_t> primes;
    if (limit < 2) return primes;
    std::vector<uint32_t> bits((limit + 1 + 31) / 32, 0xFFFFFFFF);
    auto get_bit = [&](size_t i) -> bool { return (bits[i >> 5] >> (i & 31)) & 1; };
    auto clr_bit = [&](size_t i) { bits[i >> 5] &= ~(1u << (i & 31)); };
    bits[0] &= ~2u;
    bits[0] &= ~1u;
    for (uint32_t p = 2; (uint64_t)p * p <= limit; ++p)
        if (get_bit(p))
            for (uint64_t i = (uint64_t)p * p; i <= limit; i += p)
                clr_bit(i);
    for (uint32_t i = 2; i <= limit; ++i)
        if (get_bit(i)) primes.push_back(i);
    return primes;
}

static std::vector<int> generate_candidates(int orig_byte, bool half_nibble_only) {
    std::vector<int> result;
    int hi = orig_byte & 0xF0;
    int lo = orig_byte & 0x0F;
    if (half_nibble_only) {
        for (int v = 0; v <= 0xF0; v += 0x10) if (v != hi) result.push_back(hi | v);
        for (int v = 0; v < 16; ++v) if (v != lo) result.push_back(lo | (v << 4));
    } else {
        std::vector<unsigned char> present(256, 0);
        for (int v = 0; v <= 0xF0; v += 0x10) if (v != hi) { result.push_back(hi | v); present[hi | v] = 1; }
        for (int v = 0; v < 16; ++v) if (v != lo) { result.push_back(lo | (v << 4)); present[lo | (v << 4)] = 1; }
        present[orig_byte] = 1;
        for (int i = 0; i < 256; ++i) if (!present[i]) result.push_back(i);
    }
    return result;
}

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

static bool is_probable_prime(const BigNum& N) {
    return mpz_probab_prime_p(N.v, 25) > 0;
}

static bool verify_factor(const BigNum& N_mod, const BigNum& N_orig,
                           const BigNum& factor_candidate, BigNum& p, BigNum& q) {
    BigNum g;
    mpz_gcd(g.v, N_mod.v, factor_candidate.v);
    if (g.is_zero()) return false;
    if (!mpz_divisible_p(N_mod.v, g.v)) return false;
    mpz_divexact(q.v, N_mod.v, g.v);
    mpz_set(p.v, g.v);
    BigNum check;
    mpz_mul(check.v, p.v, q.v);
    return mpz_cmp(check.v, N_mod.v) == 0;
}

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
            mpz_mul(x.v, x.v, x.v); mpz_add(x.v, x.v, c.v); mpz_mod(x.v, x.v, N.v);
            mpz_mul(y.v, y.v, y.v); mpz_add(y.v, y.v, c.v); mpz_mod(y.v, y.v, N.v);
            mpz_mul(y.v, y.v, y.v); mpz_add(y.v, y.v, c.v); mpz_mod(y.v, y.v, N.v);
            mpz_sub(diff.v, x.v, y.v); mpz_abs(diff.v, diff.v);
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

struct FactorResult {
    bool success;
    std::string type;
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
    BigNum f, q;
    if (trial_divide(N, primes, f, q)) {
        r.success = true; r.type = "factor"; r.factor_val = f; r.quotient_val = q;
        return r;
    }
    if (mode == "factor" || mode == "both") {
        if (pollard_rho(N, f, q)) {
            r.success = true; r.type = "factor"; r.factor_val = f; r.quotient_val = q;
            return r;
        }
    }
    if (try_prime_mode || mode == "prime" || mode == "both") {
        if (is_probable_prime(N)) {
            r.success = true; r.type = "prime"; r.factor_val = N;
            return r;
        }
    }
    return r;
}

// ---------------------------------------------------------------------------
//  RSA key reconstruction
// ---------------------------------------------------------------------------
struct RsaSolution {
    int position;
    int orig_byte;
    int new_byte;
    std::string type;
    BigNum N_new;
    BigNum P;
    BigNum Q;
    BigNum D;
    std::string n_pem;
    std::string d_pem;
};

static bool build_rsa_key(const BigNum& N, const BigNum& E, const BigNum& P,
                          RsaSolution& sol) {
    if (!mpz_divisible_p(N.v, P.v)) return false;
    mpz_divexact(sol.Q.v, N.v, P.v);
    sol.P = P;
    BigNum phi, p1, q1;
    mpz_sub_ui(p1.v, P.v, 1);
    mpz_sub_ui(q1.v, sol.Q.v, 1);
    mpz_mul(phi.v, p1.v, q1.v);
    if (mpz_invert(sol.D.v, E.v, phi.v) == 0) return false;
    sol.N_new = N;
    return true;
}

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
    BIGNUM *dp_bn = BN_new(), *dq_bn = BN_new(), *qi_bn = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    BN_sub(dp_bn, p_bn, BN_value_one());
    BN_mod(dp_bn, d_bn, dp_bn, ctx);
    BN_sub(dq_bn, q_bn, BN_value_one());
    BN_mod(dq_bn, d_bn, dq_bn, ctx);
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
//  Scan core
// ---------------------------------------------------------------------------
struct ScanParams {
    std::string mode;
    uint32_t small_prime_limit;
    uint32_t thread_count;
    bool fast30;
    bool stop_first;
    bool gen_pem;
    int half_nibble_max;
    int full_byte_max;
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
    if (ctx.params.half_nibble_max > 0 && nibble_count >= ctx.params.half_nibble_max) return false;
    if (ctx.params.full_byte_max > 0 && full_count >= ctx.params.full_byte_max) return false;
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

            bool try_prime_mode = try_prime;
            auto fr = try_factorize(N_mod, ctx.primes, ctx.params.mode, try_prime_mode);
            if (!fr.success) continue;

            BigNum P, Q;
            if (fr.type == "factor") {
                if (!verify_factor(N_mod, ctx.N_orig, fr.factor_val, P, Q)) continue;
            } else {
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
                    if (ctx.params.stop_first) ctx.stop_flag.store(true);
                    local_found++;
                }
            }
            if (ctx.params.stop_first && local_found > 0) break;
        }
        N_copy[pos] = (unsigned char)orig_byte;
    }
}

static void run_scan(ScanContext& ctx) {
    ctx.primes = sieve_primes(ctx.params.small_prime_limit);
    ctx.N_bytes = ctx.N_orig.to_bytes_be();
    size_t nthreads = ctx.params.thread_count;
    if (nthreads < 1) nthreads = 1;
    size_t total_bytes = ctx.N_bytes.size();
    if (nthreads > total_bytes) nthreads = total_bytes;
    if (nthreads < 1) nthreads = 1;
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
//  Export helpers
// ---------------------------------------------------------------------------
static void export_keys(const RsaSolution& sol, const BigNum& E,
                        const std::string& out_prefix) {
    std::string pub_pem = generate_public_pem(sol.N_new, E);
    write_file_utf8(out_prefix + "_pub.pem", pub_pem);
    std::string priv_pem = generate_private_pem(sol.N_new, E, sol.D, sol.P, sol.Q);
    write_file_utf8(out_prefix + "_priv.pem", priv_pem);
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
    write_file_utf8(out_prefix + "_info.txt", oss.str());
}

// ===========================================================================
//  GUI (Win32 native)
// ===========================================================================
#if defined(_WIN32)

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

// Control IDs
#define IDC_EDIT_INPUT        1001
#define IDC_BTN_PARSE         1002
#define IDC_LABEL_N           1003
#define IDC_LABEL_E           1004
#define IDC_RADIO_PRIME       1005
#define IDC_RADIO_FACTOR      1006
#define IDC_RADIO_BOTH        1007
#define IDC_EDIT_PRIMES       1008
#define IDC_EDIT_THREADS      1009
#define IDC_CHK_FAST30        1010
#define IDC_CHK_STOPFIRST     1011
#define IDC_CHK_GENPEM        1012
#define IDC_EDIT_NIBMAX       1013
#define IDC_EDIT_BYTEMAX      1014
#define IDC_BTN_SCAN          1015
#define IDC_LIST_SOLUTIONS    1016
#define IDC_BTN_EXPORT_ALL    1017
#define IDC_BTN_SAVE_REPORT   1018
#define IDC_BTN_EXPORT_PUB    1019
#define IDC_BTN_EXPORT_PRIV   1020
#define IDC_TAB_DETAIL        1021
#define IDC_EDIT_DETAIL       1022
#define IDC_STATIC_STATUS     1023

static HINSTANCE g_hInst = nullptr;
static HWND g_hMain = nullptr;
static HWND g_hEditInput = nullptr;
static HWND g_hLabelN = nullptr;
static HWND g_hLabelE = nullptr;
static HWND g_hRadioPrime = nullptr;
static HWND g_hRadioFactor = nullptr;
static HWND g_hRadioBoth = nullptr;
static HWND g_hEditPrimes = nullptr;
static HWND g_hEditThreads = nullptr;
static HWND g_hChkFast30 = nullptr;
static HWND g_hChkStopFirst = nullptr;
static HWND g_hChkGenPem = nullptr;
static HWND g_hEditNibMax = nullptr;
static HWND g_hEditByteMax = nullptr;
static HWND g_hListSolutions = nullptr;
static HWND g_hTabDetail = nullptr;
static HWND g_hEditDetail = nullptr;
static HWND g_hStatus = nullptr;

// Parsed state
static std::string g_n_hex, g_e_hex;
static std::vector<RsaSolution> g_solutions;
static BigNum g_N, g_E;
static bool g_have_key = false;

static std::wstring to_w(const std::string& s) {
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring ws(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &ws[0], len);
    if (!ws.empty() && ws.back() == 0) ws.pop_back();
    return ws;
}
static std::string to_u8(const std::wstring& ws) {
    if (ws.empty()) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string s(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, &s[0], len, nullptr, nullptr);
    if (!s.empty() && s.back() == 0) s.pop_back();
    return s;
}
static std::string get_text_u8(HWND h) {
    int len = GetWindowTextLengthW(h);
    std::wstring ws(len + 1, 0);
    GetWindowTextW(h, &ws[0], len + 1);
    ws.resize(len);
    return to_u8(ws);
}
static void set_text_u8(HWND h, const std::string& s) {
    SetWindowTextW(h, to_w(s).c_str());
}
static void set_status(const std::string& s) {
    set_text_u8(g_hStatus, s);
}

// -------- Detail view: build the three tabs' text content --------
static std::string build_detail_params(int idx) {
    if (idx < 0 || idx >= (int)g_solutions.size()) return "";
    auto& s = g_solutions[idx];
    std::ostringstream oss;
    oss << "位置: " << s.position << "\r\n";
    oss << "原字节: 0x" << std::hex << s.orig_byte << "  新字节: 0x" << s.new_byte << "\r\n";
    oss << "类型: " << s.type << "\r\n";
    oss << "模式: " << (is_half_nibble(s.orig_byte, s.new_byte) ? "half-nibble" : "full-byte") << "\r\n\r\n";
    oss << "N (hex):\r\n" << s.N_new.to_hex() << "\r\n\r\n";
    oss << "P (hex):\r\n" << s.P.to_hex() << "\r\n\r\n";
    oss << "Q (hex):\r\n" << s.Q.to_hex() << "\r\n\r\n";
    oss << "D (hex):\r\n" << s.D.to_hex() << "\r\n";
    return oss.str();
}

static std::string build_detail_ndiff(int idx) {
    if (idx < 0 || idx >= (int)g_solutions.size()) return "";
    auto& s = g_solutions[idx];
    auto orig = g_N.to_bytes_be();
    auto nnew = s.N_new.to_bytes_be();
    std::ostringstream oss;
    oss << "N 差异（变化的字节用 [XX] 标出）:\r\n\r\n";
    oss << "原 N:\r\n";
    for (size_t i = 0; i < orig.size(); ++i) {
        char buf[8];
        snprintf(buf, sizeof(buf), "%02X", orig[i]);
        oss << buf;
        if ((i + 1) % 32 == 0) oss << "\r\n";
    }
    oss << "\r\n\r\n新 N:\r\n";
    for (size_t i = 0; i < nnew.size(); ++i) {
        char buf[8];
        if (i < orig.size() && orig[i] != nnew[i]) {
            snprintf(buf, sizeof(buf), "[%02X]", nnew[i]);
        } else {
            snprintf(buf, sizeof(buf), "%02X", nnew[i]);
        }
        oss << buf;
        if ((i + 1) % 16 == 0) oss << "\r\n";
    }
    oss << "\r\n";
    return oss.str();
}

static std::string build_detail_pem(int idx) {
    if (idx < 0 || idx >= (int)g_solutions.size()) return "";
    auto& s = g_solutions[idx];
    std::string pub = generate_public_pem(s.N_new, g_E);
    std::ostringstream oss;
    oss << "原 N 对应的公钥 PEM（N 未修改，仅供参考）:\r\n";
    oss << "（下方为新 N 对应公钥 PEM）\r\n\r\n";
    oss << "新公钥 PEM:\r\n" << pub << "\r\n";
    return oss.str();
}

// -------- Parse button --------
static void on_parse() {
    std::string input = get_text_u8(g_hEditInput);
    if (input.empty()) {
        MessageBoxW(g_hMain, L"请输入公钥内容。", L"提示", MB_ICONINFORMATION);
        return;
    }
    std::string n_hex, e_hex;
    if (!parse_public_key(input, n_hex, e_hex)) {
        MessageBoxW(g_hMain, L"解析公钥失败。", L"错误", MB_ICONERROR);
        set_status("解析公钥失败");
        return;
    }
    if (!validate_n_e(n_hex, e_hex, g_N, g_E)) {
        MessageBoxW(g_hMain, L"N/e 无效。", L"错误", MB_ICONERROR);
        return;
    }
    g_n_hex = n_hex;
    g_e_hex = e_hex;
    g_have_key = true;
    set_text_u8(g_hLabelN, "N(hex): " + n_hex);
    set_text_u8(g_hLabelE, "e(hex): " + e_hex);
    size_t bits = mpz_sizeinbase(g_N.v, 2);
    set_status("解析成功，N 位数: " + std::to_string(bits) + " bit");
}

// -------- Scan worker thread --------
struct ScanThreadArg {
    ScanContext* ctx;
};
static DWORD WINAPI scan_thread_proc(LPVOID param) {
    ScanContext* ctx = (ScanContext*)param;
    run_scan(*ctx);
    return 0;
}

static void on_scan() {
    if (!g_have_key) {
        MessageBoxW(g_hMain, L"请先解析公钥。", L"提示", MB_ICONINFORMATION);
        return;
    }
    ScanParams p;
    if (Button_GetCheck(g_hRadioPrime) == BST_CHECKED) p.mode = "prime";
    else if (Button_GetCheck(g_hRadioBoth) == BST_CHECKED) p.mode = "both";
    else p.mode = "factor";

    p.small_prime_limit = (uint32_t)atoi(get_text_u8(g_hEditPrimes).c_str());
    if (p.small_prime_limit < 2) p.small_prime_limit = 2;
    if (p.small_prime_limit > 251) p.small_prime_limit = 251;

    p.thread_count = (uint32_t)atoi(get_text_u8(g_hEditThreads).c_str());
    if (p.thread_count < 1) p.thread_count = 1;

    p.fast30 = (Button_GetCheck(g_hChkFast30) == BST_CHECKED);
    p.stop_first = (Button_GetCheck(g_hChkStopFirst) == BST_CHECKED);
    p.gen_pem = (Button_GetCheck(g_hChkGenPem) == BST_CHECKED);
    p.half_nibble_max = atoi(get_text_u8(g_hEditNibMax).c_str());
    p.full_byte_max = atoi(get_text_u8(g_hEditByteMax).c_str());

    set_status("扫描中...");
    EnableWindow(GetDlgItem(g_hMain, IDC_BTN_SCAN), FALSE);

    ScanContext* ctx = new ScanContext();
    ctx->N_orig = g_N;
    ctx->E = g_E;
    ctx->params = p;

    HANDLE h = CreateThread(nullptr, 0, scan_thread_proc, ctx, 0, nullptr);
    if (!h) {
        delete ctx;
        MessageBoxW(g_hMain, L"无法创建扫描线程。", L"错误", MB_ICONERROR);
        EnableWindow(GetDlgItem(g_hMain, IDC_BTN_SCAN), TRUE);
        return;
    }

    // Pump messages while waiting
    DWORD wait;
    MSG msg;
    while ((wait = MsgWaitForMultipleObjects(1, &h, FALSE, INFINITE, QS_ALLINPUT)) != WAIT_OBJECT_0) {
        while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    CloseHandle(h);

    g_solutions = ctx->results;
    uint64_t attempts = ctx->attempts.load();
    delete ctx;

    // Fill listview
    ListView_DeleteAllItems(g_hListSolutions);
    int nib = 0, full = 0;
    for (int i = 0; i < (int)g_solutions.size(); ++i) {
        auto& s = g_solutions[i];
        bool is_nib = is_half_nibble(s.orig_byte, s.new_byte);
        if (is_nib) nib++; else full++;

        wchar_t buf[64];
        LVITEMW lvi = {};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = i;

        swprintf(buf, 64, L"%d", i + 1);
        lvi.iSubItem = 0; lvi.pszText = buf;
        ListView_InsertItem(g_hListSolutions, &lvi);

        swprintf(buf, 64, L"%d", s.position);
        ListView_SetItemText(g_hListSolutions, i, 1, buf);

        swprintf(buf, 64, L"%02X->%02X", s.orig_byte, s.new_byte);
        ListView_SetItemText(g_hListSolutions, i, 2, buf);

        ListView_SetItemText(g_hListSolutions, i, 3, (LPWSTR)to_w(s.type).c_str());
        ListView_SetItemText(g_hListSolutions, i, 4, (LPWSTR)(is_nib ? L"half" : L"full"));

        std::string p_short = s.P.to_hex();
        if (p_short.size() > 32) p_short = p_short.substr(0, 32) + "...";
        ListView_SetItemText(g_hListSolutions, i, 5, (LPWSTR)to_w(p_short).c_str());
    }

    set_status("扫描完成：" + std::to_string(g_solutions.size()) + " 个解（半 " +
               std::to_string(nib) + " / 整 " + std::to_string(full) + "），尝试 " +
               std::to_string(attempts) + " 次");

    EnableWindow(GetDlgItem(g_hMain, IDC_BTN_SCAN), TRUE);

    // Auto-select first
    if (!g_solutions.empty()) {
        ListView_SetItemState(g_hListSolutions, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        set_text_u8(g_hEditDetail, build_detail_params(0));
    }
}

// -------- List selection change --------
static void on_list_sel() {
    int sel = ListView_GetNextItem(g_hListSolutions, -1, LVNI_SELECTED);
    if (sel < 0 || sel >= (int)g_solutions.size()) return;
    // Show params tab by default
    set_text_u8(g_hEditDetail, build_detail_params(sel));
}

// -------- Export helpers --------
static void export_one(int idx, bool pub, bool priv, const std::string& prefix) {
    auto& s = g_solutions[idx];
    if (pub) {
        std::string pem = generate_public_pem(s.N_new, g_E);
        write_file_utf8(prefix + "_pub.pem", pem);
    }
    if (priv) {
        std::string pem = generate_private_pem(s.N_new, g_E, s.D, s.P, s.Q);
        write_file_utf8(prefix + "_priv.pem", pem);
    }
}

static std::string pick_folder() {
    // Simple approach: use SHBrowseForFolder
    BROWSEINFOW bi = {};
    bi.hwndOwner = g_hMain;
    bi.lpszTitle = L"选择导出目录";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (!pidl) return "";
    wchar_t path[MAX_PATH] = {};
    SHGetPathFromIDListW(pidl, path);
    CoTaskMemFree(pidl);
    return to_u8(path);
}

static void on_export_all() {
    if (g_solutions.empty()) { MessageBoxW(g_hMain, L"没有解可导出。", L"提示", MB_ICONINFORMATION); return; }
    std::string dir = pick_folder();
    if (dir.empty()) return;
    mkdir_recursive(dir);
    for (int i = 0; i < (int)g_solutions.size(); ++i) {
        std::string prefix = dir + "\\patched_" + std::to_string(i + 1);
        export_one(i, true, true, prefix);
    }
    set_status("已导出 " + std::to_string(g_solutions.size()) + " 组公私钥到 " + dir);
    MessageBoxW(g_hMain, L"导出完成。", L"提示", MB_ICONINFORMATION);
}

static void on_save_report() {
    if (g_solutions.empty()) { MessageBoxW(g_hMain, L"没有报告可保存。", L"提示", MB_ICONINFORMATION); return; }
    std::string dir = pick_folder();
    if (dir.empty()) return;
    std::ostringstream oss;
    oss << "PatchRSA OneByte Report\r\n";
    oss << "N(hex): " << g_n_hex << "\r\n";
    oss << "e(hex): " << g_e_hex << "\r\n";
    oss << "解数量: " << g_solutions.size() << "\r\n\r\n";
    for (int i = 0; i < (int)g_solutions.size(); ++i) {
        auto& s = g_solutions[i];
        oss << "--- 解 #" << (i + 1) << " ---\r\n";
        oss << "位置: " << s.position << "\r\n";
        oss << "字节: " << std::hex << s.orig_byte << " -> " << s.new_byte << std::dec << "\r\n";
        oss << "类型: " << s.type << "\r\n";
        oss << "模式: " << (is_half_nibble(s.orig_byte, s.new_byte) ? "half-nibble" : "full-byte") << "\r\n";
        oss << "N_new: " << s.N_new.to_hex() << "\r\n";
        oss << "P: " << s.P.to_hex() << "\r\n";
        oss << "Q: " << s.Q.to_hex() << "\r\n";
        oss << "D: " << s.D.to_hex() << "\r\n\r\n";
    }
    std::string path = dir + "\\report.txt";
    write_file_utf8(path, oss.str());
    set_status("报告已保存: " + path);
    MessageBoxW(g_hMain, L"报告已保存。", L"提示", MB_ICONINFORMATION);
}

static void on_export_pub_only() {
    int sel = ListView_GetNextItem(g_hListSolutions, -1, LVNI_SELECTED);
    if (sel < 0) { MessageBoxW(g_hMain, L"请先在解列表中选择一条。", L"提示", MB_ICONINFORMATION); return; }
    std::string dir = pick_folder();
    if (dir.empty()) return;
    std::string prefix = dir + "\\patched_" + std::to_string(sel + 1);
    export_one(sel, true, false, prefix);
    set_status("已导出公钥: " + prefix + "_pub.pem");
}

static void on_export_priv_only() {
    int sel = ListView_GetNextItem(g_hListSolutions, -1, LVNI_SELECTED);
    if (sel < 0) { MessageBoxW(g_hMain, L"请先在解列表中选择一条。", L"提示", MB_ICONINFORMATION); return; }
    std::string dir = pick_folder();
    if (dir.empty()) return;
    std::string prefix = dir + "\\patched_" + std::to_string(sel + 1);
    export_one(sel, false, true, prefix);
    set_status("已导出私钥: " + prefix + "_priv.pem");
}

// -------- Tab switch --------
static void on_tab_change() {
    int tab = TabCtrl_GetCurSel(g_hTabDetail);
    int sel = ListView_GetNextItem(g_hListSolutions, -1, LVNI_SELECTED);
    if (sel < 0) { set_text_u8(g_hEditDetail, ""); return; }
    switch (tab) {
        case 0: set_text_u8(g_hEditDetail, build_detail_params(sel)); break;
        case 1: set_text_u8(g_hEditDetail, build_detail_ndiff(sel)); break;
        case 2: set_text_u8(g_hEditDetail, build_detail_pem(sel)); break;
    }
}

// -------- Layout --------
static void layout(HWND h) {
    RECT rc; GetClientRect(h, &rc);
    int W = rc.right, H = rc.bottom;
    int pad = 8;
    int y = pad;
    int leftW = 480;

    // Left column: input + params
    MoveWindow(g_hEditInput, pad, y + 20, leftW, 90, TRUE);
    MoveWindow(GetDlgItem(h, IDC_BTN_PARSE), pad, y + 118, 100, 26, TRUE);
    MoveWindow(g_hLabelN, pad + 110, y + 118, leftW - 110, 26, TRUE);
    MoveWindow(g_hLabelE, pad + 110, y + 148, leftW - 110, 26, TRUE);
    y += 180;

    // Mode radios
    MoveWindow(g_hRadioFactor, pad, y, 110, 22, TRUE);
    MoveWindow(g_hRadioBoth, pad + 120, y, 110, 22, TRUE);
    MoveWindow(g_hRadioPrime, pad + 240, y, 110, 22, TRUE);
    y += 28;

    MoveWindow(GetDlgItem(h, IDC_EDIT_PRIMES), pad + 80, y, 60, 22, TRUE);
    MoveWindow(GetDlgItem(h, IDC_EDIT_THREADS), pad + 220, y, 60, 22, TRUE);
    y += 28;

    MoveWindow(g_hChkFast30, pad, y, 200, 22, TRUE);
    MoveWindow(g_hChkStopFirst, pad + 210, y, 200, 22, TRUE);
    y += 26;
    MoveWindow(g_hChkGenPem, pad, y, 200, 22, TRUE);
    y += 26;

    MoveWindow(GetDlgItem(h, IDC_EDIT_NIBMAX), pad + 100, y, 60, 22, TRUE);
    MoveWindow(GetDlgItem(h, IDC_EDIT_BYTEMAX), pad + 260, y, 60, 22, TRUE);
    y += 30;

    MoveWindow(GetDlgItem(h, IDC_BTN_SCAN), pad, y, 100, 28, TRUE);

    // Right column: list + detail
    int rightX = leftW + pad * 2;
    int rightW = W - rightX - pad;
    int listH = H / 2 - 40;

    MoveWindow(g_hListSolutions, rightX, pad + 20, rightW, listH, TRUE);

    // Buttons under list
    int by = pad + 20 + listH + 4;
    MoveWindow(GetDlgItem(h, IDC_BTN_EXPORT_ALL), rightX, by, 130, 26, TRUE);
    MoveWindow(GetDlgItem(h, IDC_BTN_SAVE_REPORT), rightX + 136, by, 100, 26, TRUE);
    MoveWindow(GetDlgItem(h, IDC_BTN_EXPORT_PUB), rightX + 242, by, 90, 26, TRUE);
    MoveWindow(GetDlgItem(h, IDC_BTN_EXPORT_PRIV), rightX + 338, by, 90, 26, TRUE);

    // Detail tab + edit
    int dy = by + 32;
    MoveWindow(g_hTabDetail, rightX, dy, rightW, H - dy - pad - 24, TRUE);
    RECT trc; GetClientRect(g_hTabDetail, &trc);
    MoveWindow(g_hEditDetail, rightX + 4, dy + 26, rightW - 8, H - dy - pad - 24 - 30, TRUE);

    // Status bar
    MoveWindow(g_hStatus, pad, H - 22, W - pad * 2, 20, TRUE);
}

// -------- Window proc --------
static LRESULT CALLBACK WndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g_hMain = h;
        HINSTANCE hi = g_hInst;

        CreateWindowW(L"STATIC", L"公钥输入（PEM / 无头 base64 / 裸 N / OpenSSH / 路径）：",
                      WS_CHILD | WS_VISIBLE, 8, 8, 400, 18, h, nullptr, hi, nullptr);

        g_hEditInput = CreateWindowW(L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL,
            8, 28, 460, 90, h, (HMENU)IDC_EDIT_INPUT, hi, nullptr);

        CreateWindowW(L"BUTTON", L"解析公钥",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            8, 126, 100, 26, h, (HMENU)IDC_BTN_PARSE, hi, nullptr);

        g_hLabelN = CreateWindowW(L"STATIC", L"N(hex): ",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            118, 128, 360, 24, h, (HMENU)IDC_LABEL_N, hi, nullptr);
        g_hLabelE = CreateWindowW(L"STATIC", L"e(hex): ",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            118, 156, 360, 24, h, (HMENU)IDC_LABEL_E, hi, nullptr);

        g_hRadioFactor = CreateWindowW(L"BUTTON", L"小素数分解",
            WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON | WS_GROUP,
            8, 190, 110, 22, h, (HMENU)IDC_RADIO_FACTOR, hi, nullptr);
        g_hRadioBoth = CreateWindowW(L"BUTTON", L"素数+分解",
            WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
            128, 190, 110, 22, h, (HMENU)IDC_RADIO_BOTH, hi, nullptr);
        g_hRadioPrime = CreateWindowW(L"BUTTON", L"仅素数",
            WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
            248, 190, 110, 22, h, (HMENU)IDC_RADIO_PRIME, hi, nullptr);
        Button_SetCheck(g_hRadioFactor, BST_CHECKED);

        CreateWindowW(L"STATIC", L"小素数集:",
            WS_CHILD | WS_VISIBLE, 8, 220, 70, 20, h, nullptr, hi, nullptr);
        g_hEditPrimes = CreateWindowW(L"EDIT", L"251",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_NUMBER,
            80, 218, 60, 22, h, (HMENU)IDC_EDIT_PRIMES, hi, nullptr);
        CreateWindowW(L"STATIC", L"线程:",
            WS_CHILD | WS_VISIBLE, 160, 220, 50, 20, h, nullptr, hi, nullptr);
        g_hEditThreads = CreateWindowW(L"EDIT", L"8",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_NUMBER,
            220, 218, 60, 22, h, (HMENU)IDC_EDIT_THREADS, hi, nullptr);

        g_hChkFast30 = CreateWindowW(L"BUTTON", L"仅半字节替换(fast30)",
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            8, 248, 200, 22, h, (HMENU)IDC_CHK_FAST30, hi, nullptr);
        g_hChkStopFirst = CreateWindowW(L"BUTTON", L"找到第一个解即停",
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            218, 248, 200, 22, h, (HMENU)IDC_CHK_STOPFIRST, hi, nullptr);
        g_hChkGenPem = CreateWindowW(L"BUTTON", L"详情中生成PEM",
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            8, 274, 200, 22, h, (HMENU)IDC_CHK_GENPEM, hi, nullptr);

        CreateWindowW(L"STATIC", L"半字节最多:",
            WS_CHILD | WS_VISIBLE, 8, 302, 90, 20, h, nullptr, hi, nullptr);
        g_hEditNibMax = CreateWindowW(L"EDIT", L"5",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_NUMBER,
            100, 300, 60, 22, h, (HMENU)IDC_EDIT_NIBMAX, hi, nullptr);
        CreateWindowW(L"STATIC", L"整字节最多:",
            WS_CHILD | WS_VISIBLE, 170, 302, 90, 20, h, nullptr, hi, nullptr);
        g_hEditByteMax = CreateWindowW(L"EDIT", L"5",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_NUMBER,
            260, 300, 60, 22, h, (HMENU)IDC_EDIT_BYTEMAX, hi, nullptr);
        CreateWindowW(L"STATIC", L"（0=不限）",
            WS_CHILD | WS_VISIBLE, 328, 302, 120, 20, h, nullptr, hi, nullptr);

        CreateWindowW(L"BUTTON", L"开始扫描",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            8, 330, 100, 28, h, (HMENU)IDC_BTN_SCAN, hi, nullptr);

        // List view (right)
        g_hListSolutions = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
            500, 28, 460, 260, h, (HMENU)IDC_LIST_SOLUTIONS, hi, nullptr);
        ListView_SetExtendedListViewStyle(g_hListSolutions,
            LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

        struct ColInfo { const wchar_t* name; int width; };
        ColInfo cols[] = {
            { L"#", 40 }, { L"位置", 60 }, { L"字节替换", 100 },
            { L"类型", 70 }, { L"模式", 70 }, { L"P", 200 },
        };
        LVCOLUMNW col = {};
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        for (int i = 0; i < 6; ++i) {
            col.iSubItem = i;
            col.pszText = (LPWSTR)cols[i].name;
            col.cx = cols[i].width;
            ListView_InsertColumn(g_hListSolutions, i, &col);
        }

        // Buttons under list
        CreateWindowW(L"BUTTON", L"一键导出公私钥",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            500, 294, 130, 26, h, (HMENU)IDC_BTN_EXPORT_ALL, hi, nullptr);
        CreateWindowW(L"BUTTON", L"保存报告",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            636, 294, 100, 26, h, (HMENU)IDC_BTN_SAVE_REPORT, hi, nullptr);
        CreateWindowW(L"BUTTON", L"仅公钥",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            742, 294, 90, 26, h, (HMENU)IDC_BTN_EXPORT_PUB, hi, nullptr);
        CreateWindowW(L"BUTTON", L"仅私钥",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            838, 294, 90, 26, h, (HMENU)IDC_BTN_EXPORT_PRIV, hi, nullptr);

        // Tab control for detail
        g_hTabDetail = CreateWindowExW(0, WC_TABCONTROLW, L"",
            WS_CHILD | WS_VISIBLE | TCS_TABS,
            500, 326, 460, 300, h, (HMENU)IDC_TAB_DETAIL, hi, nullptr);
        TCITEMW tie = {};
        tie.mask = TCIF_TEXT;
        tie.pszText = (LPWSTR)L"参数N/P/Q/D";
        TabCtrl_InsertItem(g_hTabDetail, 0, &tie);
        tie.pszText = (LPWSTR)L"N差异(标红)";
        TabCtrl_InsertItem(g_hTabDetail, 1, &tie);
        tie.pszText = (LPWSTR)L"公钥PEM对比(标红)";
        TabCtrl_InsertItem(g_hTabDetail, 2, &tie);

        g_hEditDetail = CreateWindowW(L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE |
            ES_AUTOVSCROLL | ES_AUTOHSCROLL | WS_VSCROLL | WS_HSCROLL | ES_READONLY,
            504, 354, 452, 260, h, (HMENU)IDC_EDIT_DETAIL, hi, nullptr);
        SendMessageW(g_hEditDetail, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);

        g_hStatus = CreateWindowW(L"STATIC", L"就绪",
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_SUNKEN,
            8, 400, 960, 20, h, (HMENU)IDC_STATIC_STATUS, hi, nullptr);

        return 0;
    }

    case WM_SIZE:
        layout(h);
        return 0;

    case WM_COMMAND: {
        int id = LOWORD(wp);
        int code = HIWORD(wp);
        switch (id) {
        case IDC_BTN_PARSE:
            if (code == BN_CLICKED) on_parse();
            break;
        case IDC_BTN_SCAN:
            if (code == BN_CLICKED) on_scan();
            break;
        case IDC_BTN_EXPORT_ALL:
            if (code == BN_CLICKED) on_export_all();
            break;
        case IDC_BTN_SAVE_REPORT:
            if (code == BN_CLICKED) on_save_report();
            break;
        case IDC_BTN_EXPORT_PUB:
            if (code == BN_CLICKED) on_export_pub_only();
            break;
        case IDC_BTN_EXPORT_PRIV:
            if (code == BN_CLICKED) on_export_priv_only();
            break;
        }
        return 0;
    }

    case WM_NOTIFY: {
        LPNMHDR nh = (LPNMHDR)lp;
        if (nh->idFrom == IDC_LIST_SOLUTIONS && nh->code == LVN_ITEMCHANGED) {
            on_list_sel();
        } else if (nh->idFrom == IDC_TAB_DETAIL && nh->code == TCN_SELCHANGE) {
            on_tab_change();
        }
        return 0;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

static int run_gui(HINSTANCE hInst, int nCmdShow) {
    g_hInst = hInst;

    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"PatchRSAGuiWnd";
    if (!RegisterClassExW(&wc)) return 1;

    HWND h = CreateWindowExW(0, L"PatchRSAGuiWnd", L"PatchRSA OneByte GUI",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1000, 620,
        nullptr, nullptr, hInst, nullptr);
    if (!h) return 1;

    ShowWindow(h, nCmdShow);
    UpdateWindow(h);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}

#endif // _WIN32

// ---------------------------------------------------------------------------
//  CLI entry (also used when launching GUI on Windows)
// ---------------------------------------------------------------------------
#if defined(_WIN32)
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nCmdShow) {
    // If command-line args exist (i.e. not a bare double-click), run CLI mode.
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    bool cli = (argc > 1);
    if (argv) LocalFree(argv);

    if (cli) {
        // Convert args to UTF-8 and call the original CLI main
        int wargc = 0;
        LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
        std::vector<std::string> args_utf8;
        std::vector<char*> args;
        for (int i = 0; i < wargc; ++i) {
            int len = WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, nullptr, 0, nullptr, nullptr);
            std::string s(len, 0);
            WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, &s[0], len, nullptr, nullptr);
            if (!s.empty() && s.back() == 0) s.pop_back();
            args_utf8.push_back(s);
        }
        if (wargv) LocalFree(wargv);
        for (auto& s : args_utf8) args.push_back(const_cast<char*>(s.c_str()));

        // Reuse the original CLI logic
        extern int cli_main(int argc, char* argv[]);
        return cli_main((int)args.size(), args.data());
    }

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    int rc = run_gui(hInst, nCmdShow);
    EVP_cleanup();
    return rc;
}

// Original CLI main renamed to cli_main
int cli_main(int argc, char* argv[]) {
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

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            printf("PatchRSA OneByte CLI\n");
            printf("Usage: %s -k <input> [--mode prime|factor|both] ...\n", argv[0]);
            return 0;
        }
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

    if (key_input.empty()) { fprintf(stderr, "No input.\n"); return 1; }

    std::string n_hex, e_hex;
    if (!parse_public_key(key_input, n_hex, e_hex)) { fprintf(stderr, "Parse failed.\n"); return 1; }
    BigNum N, E;
    if (!validate_n_e(n_hex, e_hex, N, E)) { fprintf(stderr, "Invalid N/e.\n"); return 1; }
    printf("N = %s\ne = %s\n", n_hex.c_str(), e_hex.c_str());
    if (parse_only) return 0;

    ScanContext ctx;
    ctx.N_orig = N; ctx.E = E; ctx.params = params;
    run_scan(ctx);
    printf("Solutions: %zu\n", ctx.results.size());
    for (size_t i = 0; i < ctx.results.size(); ++i) {
        auto& s = ctx.results[i];
        printf("#%zu pos=%d %02X->%02X type=%s\n", i + 1, s.position, s.orig_byte, s.new_byte, s.type.c_str());
        if (!export_dir.empty()) {
            mkdir_recursive(export_dir);
            std::string prefix = export_dir + "/patched_" + std::to_string(i + 1);
            export_keys(s, E, prefix);
        }
    }
    return 0;
}

#else
// Linux / macOS: keep original CLI main
int main(int argc, char* argv[]) {
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

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") { printf("Usage: %s -k <input>\n", argv[0]); return 0; }
        else if (arg == "-k" && i + 1 < argc) key_input = argv[++i];
        else if (arg == "--mode" && i + 1 < argc) params.mode = argv[++i];
        else if (arg == "--primes" && i + 1 < argc) params.small_prime_limit = (uint32_t)atoi(argv[++i]);
        else if (arg == "--threads" && i + 1 < argc) params.thread_count = (uint32_t)atoi(argv[++i]);
        else if (arg == "--fast30") params.fast30 = true;
        else if (arg == "--stop-first") params.stop_first = true;
        else if (arg == "--gen-pem") params.gen_pem = true;
        else if (arg == "--nibble-max" && i + 1 < argc) params.half_nibble_max = atoi(argv[++i]);
        else if (arg == "--byte-max" && i + 1 < argc) params.full_byte_max = atoi(argv[++i]);
        else if (arg == "--export" && i + 1 < argc) export_dir = argv[++i];
        else if (arg == "--parse-only") parse_only = true;
        else if (arg[0] != '-' && key_input.empty()) key_input = arg;
    }
    if (key_input.empty()) { fprintf(stderr, "No input.\n"); return 1; }

    std::string n_hex, e_hex;
    if (!parse_public_key(key_input, n_hex, e_hex)) { fprintf(stderr, "Parse failed.\n"); return 1; }
    BigNum N, E;
    if (!validate_n_e(n_hex, e_hex, N, E)) { fprintf(stderr, "Invalid N/e.\n"); return 1; }
    printf("N = %s\ne = %s\n", n_hex.c_str(), e_hex.c_str());
    if (parse_only) return 0;

    ScanContext ctx;
    ctx.N_orig = N; ctx.E = E; ctx.params = params;
    run_scan(ctx);
    printf("Solutions: %zu\n", ctx.results.size());
    for (size_t i = 0; i < ctx.results.size(); ++i) {
        auto& s = ctx.results[i];
        printf("#%zu pos=%d %02X->%02X type=%s\n", i + 1, s.position, s.orig_byte, s.new_byte, s.type.c_str());
        if (!export_dir.empty()) {
            mkdir_recursive(export_dir);
            std::string prefix = export_dir + "/patched_" + std::to_string(i + 1);
            export_keys(s, E, prefix);
        }
    }
    return 0;
}
#endif
