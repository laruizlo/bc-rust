#!/usr/bin/env bash
# Prints the source lines the audit's documents cite, from the checkout this directory sits in,
# and checks each: every row carries a piece of text that must be found in the lines it names,
# so a row whose lines moved says STALE. Line numbers are those of the pin, 30cbbab; where a
# row answers a line the first pass cited at b7e46cb (gap register v1, findings log), that old
# place stands beside the new one.
#
# Covered: every line the review of the upstream response cites (claude/rsa-upstream-response-
# review.md, read at 98f284a; no cited line moved between 98f284a and 30cbbab), the lines plan
# v3.0 cites for its new obligations, and the first pass's citations mapped to where their
# subject is now.
#
#   audit/wp11_lines.sh              # everything, with the lines
#   audit/wp11_lines.sh --check      # one status line per row
#   audit/wp11_lines.sh F-01 N12     # some items
set -uo pipefail
cd "$(dirname "$0")/.."
check=0; [ "${1:-}" = "--check" ] && { check=1; shift; }
if sha256sum --quiet -c audit/baseline.sha256 >/dev/null 2>&1; then
    echo "baseline: all $(wc -l < audit/baseline.sha256) files match audit/baseline.sha256 (HEAD $(git rev-parse --short HEAD 2>/dev/null))"
else
    echo "BASELINE DRIFT: a file differs from audit/baseline.sha256; rows may be stale, and STALE says which"
fi
R=crypto/rsa/src
want() { [ $# -eq 0 ] && return 0; local i; for i in "$@"; do [ "$i" = "$item" ] && return 0; done; return 1; }
rows=0; stale=0
while IFS='|' read -r item file first last old anchor note; do
    case "$item" in ''|'#'*) continue ;; esac
    want "$@" || continue
    file=${file/\$R/$R}
    rows=$((rows+1))
    if sed -n "${first},${last}p" "$file" | grep -qF -- "$anchor"; then state=ok; else state=STALE; stale=$((stale+1)); fi
    span="$first"; [ "$first" = "$last" ] || span="$first-$last"
    was=""; [ "$old" = "-" ] || was="  (first pass: $old)"
    if [ $check -eq 1 ]; then
        printf '%-5s %-5s %s:%s%s  %s\n' "$state" "$item" "$file" "$span" "$was" "$note"
    else
        printf '\n--- %s  %s:%s%s  [%s]  %s\n' "$item" "$file" "$span" "$was" "$state" "$note"
        sed -n "${first},${last}p" "$file" | cut -c1-160
    fi
done <<'TABLE'
# item|file|first|last|first-pass place|text that must be in the lines|what the lines are
F-01|$R/modexp.rs|307|312|modexp.rs:257-265|pub fn for_secret_modulus|the constant-time constructor
F-01|$R/modexp.rs|91|98|modexp.rs:64-71|fn pow2_mod_ct|the masked doubling chain
F-01|$R/modexp.rs|321|329|modexp.rs:257-265|pub fn for_public_modulus|the variable-time constructor, kept for n
F-01|$R/modexp.rs|71|75|modexp.rs:56-60|fn double_mod_n_vartime|the branching doubling, renamed
F-01|$R/rsa_core.rs|237|239|rsa_core.rs:80-85|for_secret_modulus(q)|both CRT contexts from the constant-time constructor
F-01|$R/keygen.rs|440|440|keygen.rs:375|MontgomeryContext::for_secret_modulus(w)|the context over a candidate
F-01|$R/keygen.rs|731|731|keygen.rs:586|MontgomeryContext::for_secret_modulus(&p)|the context over the accepted p
F-01|$R/rsa_core.rs|51|52|-|for_public_modulus(n)|the one call of the variable-time constructor, on n
F-01|$R/modexp.rs|14|18|modexp.rs:14-16|The modulus is public when it is RSA's|doc claim: which constructor for which modulus
F-01|$R/modexp.rs|298|306|-|Constant time in `modulus`|doc claim on for_secret_modulus, and its precondition
F-01|$R/rsa_core.rs|143|144|rsa_core.rs:62-64|Constant time in the key and in `y`|doc claim on the checked CRT
F-01|$R/rsa_core.rs|217|219|rsa_core.rs:62-64|Constant time in the key: the two|doc claim on crt_exp
F-01|$R/size.rs|123|126|size.rs:115-116|constant|doc claim on the size marker's crt_exp
F-01|$R/rsaes_oaep.rs|306|306|rsaes_oaep.rs:227|constant time in the key|doc claim on OAEP decryption
F-01|$R/keygen.rs|23|25|-|constant-time ladder|doc claim in key generation
F-01|$R/lib.rs|362|362|lib.rs:330-333|Signing itself is unaffected|doc claim in the crate docs
F-02|$R/keys.rs|81|83|keys.rs:53-63|has_full_bit_length|the public constructor refuses a short modulus
F-02|$R/keys.rs|293|296|-|has_full_bit_length|the private side refuses it on p * q
F-02|$R/rsasve.rs|139|144|-|MIN_PUBLIC_EXPONENT|the KEM wrapper keeps only its exponent rule (public)
F-02|$R/rsasve.rs|192|197|-|MIN_PUBLIC_EXPONENT|the same (private)
F-03|$R/emsa_pkcs1_v1_5.rs|72|74|emsa_pkcs1_v1_5.rs:30-41|digest.len() != H::OUTPUT_LEN|v1.5 encode: the hash's length is an error
F-03|$R/emsa_pkcs1_v1_5.rs|180|182|-|digest.len() != H::OUTPUT_LEN|v1.5 verify: false
F-03|$R/emsa_pkcs1_v1_5.rs|39|39|emsa_pkcs1_v1_5.rs:34|debug_assert_eq!(h_len, H::OUTPUT_LEN|digest_info keeps its debug assertion, behind the check
F-03|$R/emsa_pss.rs|57|59|emsa_pss.rs:43-44|m_hash.len() != h_len|PSS encode: the hash's length
F-03|$R/emsa_pss.rs|60|62|-|salt.len() != s_len|PSS encode: the salt's length
F-03|$R/emsa_pss.rs|64|68|-|K_LEN < h_len + s_len + 2|RFC 8017 9.1.1 step 3 as EncodingError
F-03|$R/emsa_pss.rs|109|111|emsa_pss.rs:88|m_hash.len() != h_len|PSS verify: false
F-03|$R/rsassa.rs|407|409|rsassa.rs:340|m_hash.len() != A::Hash::OUTPUT_LEN|sign_from_hash checks before it draws
F-03|$R/rsassa.rs|451|453|rsassa.rs:381|m_hash.len() != A::Hash::OUTPUT_LEN|verify_from_hash reports the length
F-04|$R/rsasve.rs|255|255|rsasve.rs:326-328|K: RsaSigningSize|RSASVE encapsulation bounded by the signing sizes
F-04|$R/rsasve.rs|384|384|-|K: RsaSigningSize|the encapsulating key role
F-04|$R/rsasve_kdf.rs|148|148|rsasve_kdf.rs:175-178|K: RsaSigningSize|RSASVE-HKDF encapsulation
F-04|$R/rsasve_kdf.rs|269|269|-|K: RsaSigningSize|its key role
F-04|$R/rsaes_oaep.rs|226|226|-|K: RsaSigningSize|OAEP encryption
F-04|$R/rsaes_oaep.rs|366|366|rsaes_oaep.rs:352-354|K: RsaSigningSize|OAEP as a KEM, encapsulating
F-04|$R/rsaes_oaep.rs|438|438|-|K: RsaSigningSize|OAEP as a KEM, key role
F-04|$R/rsaes_oaep.rs|492|492|rsaes_oaep.rs:406-408|K: RsaSigningSize|OAEP key transport
F-04|$R/lib.rs|374|379|lib.rs:346-350|exposed for verification only|the docs: nothing encapsulates or transports toward them
F-05|$R/rsa_core.rs|240|240|rsa_core.rs:86|Step 2.b.1|step label, row 1
F-05|$R/rsa_core.rs|245|245|rsa_core.rs:91|Step 2.b.3|step label
F-05|$R/rsa_core.rs|250|250|rsa_core.rs:96|Step 2.b.4|step label
F-05|$R/size.rs|105|108|size.rs:99-100|GenericError|the documented error, row 2
F-05|$R/keygen.rs|304|308|keygen.rs:286-287|first eight bytes are limb 0|the limb order of fill_random, row 3
F-05|$R/keygen.rs|50|52|keygen.rs:49|about 84%|trial division's share, row 4
F-06|$R/modexp.rs|48|51|-|const fn check_widths|the relation, as a const fn
F-06|$R/modexp.rs|203|203|-|const { check_widths::<L, L2, L21>() }|in mul_mod
F-06|$R/modexp.rs|357|357|modexp.rs:274-279|const { check_widths::<L, L2, L21>() }|in mod_pow
F-06|$R/modexp.rs|417|417|-|const { check_widths::<L, L2, L21>() }|in mod_pow_public_exponent
F-06|$R/keygen.rs|387|387|-|const { check_widths::<N, N2, N21>() }|in is_probable_prime
F-06|$R/keygen.rs|615|615|keygen.rs:523|const { check_widths::<HALF, HALF2, HALF21>() }|in keygen_from_rng
F-06|crypto/ec/src/montgomery.rs|79|79|montgomery.rs:69|const { assert!(L2 == 2 * L|widening_mul
F-06|crypto/ec/src/montgomery.rs|133|133|-|const { assert!(L2 == 2 * L|widening_square
F-06|crypto/ec/src/montgomery.rs|191|194|montgomery.rs:169-170|assert!(L2 == 2 * L|redc
F-06|crypto/ec/src/barrett.rs|90|93|-|assert!(L2 == 2 * L|barrett::reduce
F-06|$R/rsassa_pkcs1_v1_5.rs|75|75|-|K_LEN == K::K_LEN|K_LEN is the size's, v1.5 verify
F-06|$R/rsassa_pkcs1_v1_5.rs|84|84|-|K_LEN == K::K_LEN|v1.5 encode
F-06|$R/rsassa_pss.rs|234|234|-|K_LEN == K::K_LEN|PSS verify
F-06|$R/rsassa_pss.rs|251|251|-|K_LEN == K::K_LEN|PSS encode, salted
F-06|$R/rsassa_pss.rs|263|263|-|K_LEN == K::K_LEN|PSS encode, unsalted
G2|$R/keygen.rs|737|741|keygen.rs:586-596|from_crt_components|key generation's last steps: the pair is built and returned, no pairwise test
G4|$R/rsassa_pkcs1_v1_5.rs|80|80|rsassa_pkcs1_v1_5.rs:43-54|CollisionResistantHash|which hashes sign under v1.5
G4|$R/rsassa_pss.rs|241|241|rsassa_pss.rs:126-150|CollisionResistantHash|which hashes sign under salted PSS
G4|$R/rsassa_pss.rs|258|258|-|CollisionResistantHash|and unsalted
G4|$R/rsassa_pss.rs|137|137|rsassa_pss.rs:126-150|a drawn salt is 1 to 64 bytes|the salt length is free up to 64, the mask's hash free
G5|$R/keys.rs|99|106|keys.rs:76-81|pub fn key<A: RsaSignatureAlgorithm<Size = K>>|components to a key of any algorithm (public)
G5|$R/keys.rs|328|336|keys.rs:196-201|pub fn key<A: RsaSignatureAlgorithm<Size = K>>|the same (private)
G6|$R/keys.rs|60|67|keys.rs:53-59|e < 3 || e & 1 == 0|any odd e >= 3, on both halves now
G6|$R/rsasve.rs|140|140|-|pk.e() < MIN_PUBLIC_EXPONENT|the KEM keys require 65537 (public)
G6|$R/rsasve.rs|193|193|-|sk.e() < MIN_PUBLIC_EXPONENT|and the private key's copy
G6|$R/lib.rs|397|399|-|limited to 64 bits|exponents of 2^64 and above cannot be held
G7|$R/keys.rs|263|296|keys.rs:143-166|check_public_exponent(e)?|what the private-key constructor checks, in order
G7|$R/lib.rs|348|358|-|composite `p`|the crate: a composite prime can pass the result check on some inputs
G8|$R/size.rs|403|403|size.rs:383|NonZeroUsize::new(5)|Miller-Rabin rounds, RSA-2048
G8|$R/size.rs|488|488|size.rs:461|NonZeroUsize::new(4)|RSA-3072
G8|$R/size.rs|573|573|size.rs:539|NonZeroUsize::new(4)|RSA-4096
G8|$R/size.rs|658|658|size.rs:617|NonZeroUsize::new(4)|RSA-8192
G8|$R/keygen.rs|382|394|keygen.rs:341|pub fn is_probable_prime|the public primality test with a caller's round count; wipes, checks widths
G8|$R/lib.rs|357|357|lib.rs:322-329|is_probable_prime` is available|the crate still points callers to it for imported primes
G10|$R/rsa_core.rs|151|213|rsa_core.rs:56-60|let ok = Condition::<u64>::is_zero(diff)|crt_exp_checked: the CRT, y^e, the comparison, the masked write
G10|$R/rsa_core.rs|70|74|rsa_core.rs:56-60|SignatureError::ComputationFault|rsasp1 refuses a result that failed its check
G10|$R/rsasve.rs|372|374|-|KEMError::DecapsulationFailed|RSASVE recovery does too
G10|$R/rsaes_oaep.rs|309|315|-|checked.select(0x00, 0xFF)|OAEP folds the failure into the padding failure, without a branch
G10|$R/lib.rs|315|322|lib.rs:314-321|not blinded|no blinding, as the crate says
G11|$R/rsassa.rs|163|163|rsassa.rs:117|fill_bytes(rng, &mut salt|PSS salt drawn, streaming signer: no strength gate
G11|$R/rsassa.rs|411|411|rsassa.rs:351|fill_bytes(rng, &mut salt|PSS salt drawn, from a hash
G11|$R/keygen.rs|292|302|-|written == out.len()|fill_bytes: a short count is an error, the buffer wiped
G12|$R/codec.rs|14|14|-|debug_assert_eq!(BYTES, 8 * L|still a debug assertion (crate-private)
G12|$R/codec.rs|26|26|-|debug_assert_eq!(BYTES, 8 * L|the same
G12|$R/emsa_pkcs1_v1_5.rs|78|78|-|debug_assert!(K_LEN >= t_len + 11|still a debug assertion: K_LEN >= tLen + 11 (plan E3)
G13|$R/rsa_core.rs|91|96|-|fn wipe_stack_below|the stack wipe
G13|$R/lib.rs|341|347|-|the caller's to wipe|what the crate leaves to the caller
G16|$R/rsaes_oaep.rs|333|333|rsaes_oaep.rs:241-263|ActingOnZeroizedKey|key_into: an all-zero recovered key through a branch
G16|$R/rsaes_oaep.rs|65|65|rsaes_oaep.rs:61|impl OaepHash for SHA1|SHA-1 is an OAEP hash
O2|$R/modexp.rs|358|358|modexp.rs:279|mod_pow needs base < modulus|mod_pow's debug assertion on the base
O2|$R/modexp.rs|389|392|-|`base` need only fit in `L`|mod_pow_public_exponent states the wider contract
O4|$R/modexp.rs|223|224|-|odd `modulus`|ct_shift_in_bit_mod's docs still ask for an odd modulus
O4|$R/modexp.rs|245|246|-|odd `modulus`|reduce_wide's too
N4|$R/modexp.rs|299|299|-|odd and greater than 1|the secret constructor's precondition
N4|$R/modexp.rs|316|316|-|must be greater than 1|the public constructor's
N10|$R/lib.rs|359|362|lib.rs:330-333|Key generation is not constant-time|the declared position on key generation
N11|$R/keys.rs|278|278|keys.rs:156-158|if p == q|p and q compared with ==, at import
flag3|$R/modexp.rs|412|433|-|exponent.leading_zeros()|the public exponentiation over the bits of e
flag13|$R/emsa_pss.rs|147|149|-|8 + 2 * MAX_HASH_LEN|the 136-byte M' buffer a foreign PssParams can overrun
flag15|$R/rsasve.rs|111|111|-|compile_fail,E0277|upstream's compile_fail doc test, RSASVE
flag15|$R/rsasve_kdf.rs|43|43|-|compile_fail,E0277|RSASVE-HKDF
flag15|$R/rsaes_oaep.rs|87|87|-|compile_fail,E0277|OAEP as a KEM
flag15|$R/rsaes_oaep.rs|99|99|-|compile_fail,E0277|OAEP key transport
flag16|crypto/rsa/tests/rsaes_oaep_tests.rs|267|267|-|wycheproof_json(filename)?|OAEP's Wycheproof suites return early without data
N12|$R/keys.rs|133|141|-|need not be the same bit length|the docs on unequal primes, against the constructor at 293-296
N12|$R/rsa_core.rs|245|246|-|the primes need|the same sentence in crt_exp's comment
N13|crypto/ec/src/montgomery.rs|20|21|-|debug assertion|module docs still call the width check a debug assertion
N14|$R/size.rs|90|94|-|If `n` is even|public_exp's documented panic
N14|$R/size.rs|123|131|-|fn crt_exp(|the private primitive as a public trait method
N14|$R/rsa_core.rs|1|10|-|cannot be less public than it|the crate says the exponentiations are public
N14|dev_scripts/rsa_ct_harness/src/bin/memcheck.rs|130|130|-|RSA2048::crt_exp(|upstream's own harness calls it from outside the crate
N15|$R/rsa_core.rs|71|71|-|.to_bool()|the branch on the result check in rsasp1 (register D1)
N15|$R/rsasve.rs|372|372|-|.to_bool()|and in RSASVE recovery (register D2)
N15|dev_scripts/rsa_ct_harness/src/bin/memcheck.rs|128|130|-|not turned into a `bool`|upstream's memcheck mode stops below the branch on purpose
N16|$R/rsa_core.rs|129|135|-|Measured in x86-64 release builds|the checked CRT's wipe sizes
N16|$R/keys.rs|165|176|-|Measured in x86-64 release builds|key construction, decoding, encoding, cloning
N16|$R/keygen.rs|396|402|-|Measured in x86-64 release builds|is_probable_prime
N16|$R/keygen.rs|650|656|-|Measured in x86-64 release builds|key generation
N16|$R/rsasve.rs|345|351|-|Measured in x86-64 release builds|RSASVE recovery
N16|$R/rsasve_kdf.rs|168|174|-|Measured in x86-64 release builds|RSASVE-HKDF encapsulation
N16|$R/rsasve_kdf.rs|234|240|-|Measured in x86-64 release builds|RSASVE-HKDF decapsulation: the thinnest margin
N16|$R/rsaes_oaep.rs|273|279|-|Measured in x86-64 release builds|OAEP decryption
N16|$R/lib.rs|332|340|-|Private-key operations wipe the stack they used|the claim, and its scope
N16|dev_scripts/check_rsa_stack.sh|15|19|-|What a pass shows|what upstream's search says it shows
N17|dev_scripts/check_rsa_ct.sh|7|20|-|Not covered|what upstream's constant-time check covers, and does not
X1|$R/rsassa.rs|96|101|-|fn refuse_context|a non-empty context is LengthError
X1|$R/rsassa.rs|161|161|-|refuse_context(ctx)?|before the salt draw at 163
X1|$R/rsassa.rs|203|203|-|refuse_context(ctx)?|deterministic signer
X1|$R/rsassa.rs|242|242|-|refuse_context(ctx)?|verifier
K16|$R/keygen.rs|293|293|-|rng.next_bytes_out(out)|the one call of next_bytes_out in src
C2|$R/rsa_core.rs|255|255|rsa_core.rs:110|CRT recombination must stay within|the debug assertion C2 makes a theorem
E4|$R/emsa_pkcs1_v1_5.rs|135|136|emsa_pkcs1_v1_5.rs:124-125|Some(&[0x05, 0x00])|the two accepted encodings: NULL present, or absent
K2|$R/keygen.rs|501|509|-|fn candidate|candidate shaping
Z1|$R/lib.rs|332|340|-|construction, decoding, encoding, cloning and generation|the operations the crate lists as wiping
claims|$R/lib.rs|323|347|-|checked before it is released|the three bullets the response added
claims|$R/modexp.rs|14|26|-|mod_pow_public_exponent|module docs: which function for which exponent and modulus
claims|$R/rsa_core.rs|129|149|-|stack it used is overwritten afterwards|the checked CRT's docs
claims|$R/rsa_core.rs|215|219|-|RFC 8017 §5.2.1 step 2.b|crt_exp's docs
TABLE
echo
echo "rows: $rows, stale: $stale"
item=G1
if want "$@"; then
    P='self[_ -]?test|pairwise[_ -]consist|approved[_ -]?mode|non[_ -]?approved|service[_ -]?indicator|error[_ -]?state|power[_ -]?(on|up)|conditional[_ -]?(self|algorithm)|integrity[_ -]?test|module[_ -]boundary'
    printf '\n--- G1  no self-test, pairwise test, approved-mode switch, indicator or error state\n'
    echo "matches of /$P/i in *.rs outside target/ and audit/: $(grep -rniE "$P" --include='*.rs' --exclude-dir=target --exclude-dir=audit . | wc -l)"
    grep -rniE "$P" --include='*.rs' --exclude-dir=target --exclude-dir=audit crypto/rsa crypto/core/src | cut -c1-150 | head -8
fi
item=G4
if want "$@"; then
    printf '\n--- G4  where AlgorithmOID and CollisionResistantHash are implemented (which hashes can sign)\n'
    echo "AlgorithmOID:           $(grep -rl 'AlgorithmOID for' --include='*.rs' crypto/*/src | sed -E 's|crypto/([^/]+)/src/||' | sort -u | paste -sd' ' -)"
    echo "CollisionResistantHash: $(grep -rl 'CollisionResistantHash for' --include='*.rs' crypto/*/src | sed -E 's|crypto/([^/]+)/src/||' | sort -u | paste -sd' ' -)"
fi
item=M13
if want "$@"; then
    printf '\n--- M13  every call of the two constructors outside tests, and every draw (K16)\n'
    grep -n 'for_public_modulus(\|for_secret_modulus(\|next_bytes_out' $R/*.rs | grep -v '^\S*:[0-9]*:\s*//' | cut -c1-150
fi
item=I1
if want "$@"; then
    printf '\n--- I1  every place a key value is put together (struct literals and tuple constructors)\n'
    grep -n 'RsaPublicComponents {\|RsaPrivateComponents {\|Self {$\|Self { n\|Ok(Self(\|RsaKEMPublicKey(\|RsaKEMPrivateKey(\|_alg: PhantomData' $R/keys.rs $R/rsasve.rs $R/rsasve_kdf.rs $R/rsaes_oaep.rs $R/size.rs $R/keygen.rs | cut -c1-150
fi
[ $stale -eq 0 ]
