#!/usr/bin/env bash
# build_test.sh - compile and execute-test the C# loader templates on Linux (mono)
#
# For every cipher the template is compiled with the 4B and 300B demo
# payloads, executed under mono, and the printed "payload returned N" is
# asserted:
#   4B payload   -> returns 1
#   300B payload -> returns 42
# AES is tested twice: CBC (default) and CTR (-define:AES_CTR).
#
# Usage: ./build_test.sh            # run everything
#        ./build_test.sh aes        # single cipher (aes|xor|uuid|rc4|bcrypt|chacha20)

set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CS_DIR="$ROOT/loaders/csharp"
GEN="$ROOT/tools/gen_inc.py"
MCS="mcs"
MONO="mono"

if ! command -v "$MCS" >/dev/null 2>&1 || ! command -v "$MONO" >/dev/null 2>&1; then
    echo "[-] mcs/mono not found (need the mono-devel toolchain)"
    exit 1
fi

mkdir -p "$CS_DIR/bin"
fail=0

# test_one <dir> <src> <payload-cipher> <size> <expected-ret> <extra-mcs-flags...>
test_one() {
    local dir="$1" src="$2" pc="$3" size="$4" exp="$5"; shift 5
    local exe="$CS_DIR/bin/${pc}_${size}b.exe"
    if ! (cd "$dir" && python3 "$GEN" "$pc" "$size" --lang cs --out payload_inc.cs \
          && "$MCS" -r:System.Core.dll "$@" -out:"$exe" "$src" payload_inc.cs); then
        echo "  [FAIL] compile $dir/$src"
        fail=1
        return
    fi
    local out got
    out="$("$MONO" "$exe" 2>&1)"
    got="$(printf '%s\n' "$out" | sed -n 's/.*payload returned \([0-9-]*\).*/\1/p' | tail -1)"
    if [ "$got" = "$exp" ]; then
        echo "  [PASS] $pc ${size}B -> returned $got"
    else
        echo "  [FAIL] $pc ${size}B -> expected $exp, got '${got:-<none>}'"
        printf '%s\n' "$out" | sed 's/^/         /'
        fail=1
    fi
}

run_cipher() {
    case "$1" in
    aes)
        test_one "$CS_DIR/aes"      aes_loader.cs      aes_cbc   4   1
        test_one "$CS_DIR/aes"      aes_loader.cs      aes_cbc   300 42
        test_one "$CS_DIR/aes"      aes_loader.cs      aes_ctr   4   1  -define:AES_CTR
        test_one "$CS_DIR/aes"      aes_loader.cs      aes_ctr   300 42 -define:AES_CTR
        ;;
    xor|uuid|rc4|bcrypt|chacha20)
        test_one "$CS_DIR/$1" "${1}_loader.cs" "$1" 4   1
        test_one "$CS_DIR/$1" "${1}_loader.cs" "$1" 300 42
        ;;
    *) echo "  unknown cipher: $1"; exit 2 ;;
    esac
}

if [ $# -gt 0 ]; then
    run_cipher "$1"
else
    for c in aes xor uuid rc4 bcrypt chacha20; do
        echo "== $c =="
        run_cipher "$c"
    done
fi

echo
if [ "$fail" -eq 0 ]; then
    echo "[+] all C# loader tests passed"
else
    echo "[-] some C# loader tests FAILED"
    exit 1
fi
