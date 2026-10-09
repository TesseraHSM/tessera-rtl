//----------------------------------------------------------------------------
// RSA predictor arithmetic helpers, included by RSA_env_pkg.



//
// Native wide arithmetic with square-and-multiply exponentiation.
// Widen products to 2N bits before reduction to avoid intermediate truncation.
//----------------------------------------------------------------------------

localparam int unsigned REF_MAX_WIDTH = 4096;

typedef bit [REF_MAX_WIDTH-1:0]   ref_word_t;
typedef bit [2*REF_MAX_WIDTH-1:0] ref_dword_t;

// (a * b) mod m
function automatic ref_word_t ref_mod_mul(input ref_word_t a,
                                          input ref_word_t b,
                                          input ref_word_t m);
  ref_dword_t prod;
  ref_dword_t modw;
  if (m == 0) return '0;
  prod = ref_dword_t'(a) * ref_dword_t'(b);   // full 2N-bit product
  modw = ref_dword_t'(m);
  return ref_word_t'(prod % modw);
endfunction

// (a + b) mod m
function automatic ref_word_t ref_mod_add(input ref_word_t a,
                                          input ref_word_t b,
                                          input ref_word_t m);
  ref_dword_t sum;
  if (m == 0) return '0;
  sum = ref_dword_t'(a) + ref_dword_t'(b);
  return ref_word_t'(sum % ref_dword_t'(m));
endfunction

// (a - b) mod m, result in [0, m)
function automatic ref_word_t ref_mod_sub(input ref_word_t a,
                                          input ref_word_t b,
                                          input ref_word_t m);
  ref_word_t ar, br;
  if (m == 0) return '0;
  ar = a % m;
  br = b % m;
  return (ar >= br) ? (ar - br) : (ar + m - br);
endfunction

// base ^ exp mod m, left-to-right square-and-multiply.
//
// exp_bits is a bit count; limiting the scan avoids costly leading-zero work.
function automatic ref_word_t ref_mod_exp(input ref_word_t base,
                                          input ref_word_t exp,
                                          input ref_word_t m,
                                          input int unsigned exp_bits);
  ref_word_t acc;
  ref_word_t b;
  int i;
  if (m == 0) return '0;
  if (m == 1) return '0;
  acc = 1;
  b   = base % m;
  for (i = exp_bits - 1; i >= 0; i--) begin
    acc = ref_mod_mul(acc, acc, m);
    if (exp[i]) acc = ref_mod_mul(acc, b, m);
  end
  return acc;
endfunction

// Modular inverse via the extended Euclidean algorithm, on signed 2N-bit
// values so the intermediate Bezout coefficients can go negative.
function automatic ref_word_t ref_mod_inv(input ref_word_t a,
                                          input ref_word_t m);
  logic signed [2*REF_MAX_WIDTH-1:0] t, newt, r, newr, q, tmp;
  if (m == 0) return '0;
  t = 0; newt = 1;
  r = ref_dword_t'(m); newr = ref_dword_t'(a % m);
  while (newr != 0) begin
    q = r / newr;
    tmp = t - q*newt; t = newt; newt = tmp;
    tmp = r - q*newr; r = newr; newr = tmp;
  end
  if (r > 1)  return '0;            // not invertible
  if (t < 0)  t = t + ref_dword_t'(m);
  return ref_word_t'(t);
endfunction

// Requires genuine primes p/q and matching dp/dq/qinv, not random odd factors.
// Valid CRT inputs yield a result below n without a final reduction.
//
// Garner / CRT recombination, matching what MODEXP_SEC_CRT computes:
//   mp = base^dp mod p
//   mq = base^dq mod q
//   h  = qinv * (mp - mq) mod p
//   m  = mq + h*q
//
// Use the programmed qinv: the hardware consumes it rather than deriving it.
function automatic ref_word_t ref_crt(input ref_word_t base,
                                      input ref_word_t p,
                                      input ref_word_t q,
                                      input ref_word_t dp,
                                      input ref_word_t dq,
                                      input ref_word_t qinv,
                                      input int unsigned half_bits);
  ref_word_t  mp, mq, h;
  ref_dword_t res;
  mp  = ref_mod_exp(base % p, dp, p, half_bits);
  mq  = ref_mod_exp(base % q, dq, q, half_bits);
  h   = ref_mod_mul(qinv, ref_mod_sub(mp, mq, p), p);
  res = ref_dword_t'(mq) + ref_dword_t'(h) * ref_dword_t'(q);
  return ref_word_t'(res);
endfunction
