#!/usr/bin/env bash
# build_test.sh - compile and execute-test the C++ loader templates on Linux
#
# For every cipher the template is compiled with the 4B and 300B demo
# payloads, executed, and the printed "payload returned N" is asserted:
#   4B payload   -> returns 1
#   300B payload -> returns 42
# AES is tested twice: CBC (default) and CTR (-DAES_MODE=1).
#
# Usage: ./build_test.sh            # run everything
#        ./build_test.sh aes        # single cipher (aes|xor|uuid|rc4|bcrypt|chacha20)

set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CPP_DIR="$ROOT/loaders/cpp"
GEN="$ROOT/tools/gen_inc.py"

mkdir -p "$CPP_DIR/bin"
fail=0

# test_one <dir> <src> <payload-cipher> <size> <expected-ret> <extra-gcc-flags...>
test_one() {
    local dir="$1" src="$2" pc="$3" size="$4" exp="$5"; shift 5
    local bin="$CPP_DIR/bin/${pc}_${size}b"
    if ! (cd "$dir" && python3 "$GEN" "$pc" "$size" --lang cpp --out payload_inc.h \
          && g++ -O2 -Wall "$@" -o "$bin" "$src"); then
        echo "  [FAIL] compile $dir/$src"
        fail=1
        return
    fi
    local out got
    out="$("$bin" 2>&1)"
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
        test_one "$CPP_DIR/aes"      aes_loader.cpp      aes_cbc   4  1
        test_one "$CPP_DIR/aes"      aes_loader.cpp      aes_cbc   300 42
        test_one "$CPP_DIR/aes"      aes_loader.cpp      aes_ctr   4  1  -DAES_MODE=1
        test_one "$CPP_DIR/aes"      aes_loader.cpp      aes_ctr   300 42 -DAES_MODE=1
        ;;
    xor|uuid|rc4|bcrypt|chacha20)
        test_one "$CPP_DIR/$1" "${1}_loader.cpp" "$1" 4   1
        test_one "$CPP_DIR/$1" "${1}_loader.cpp" "$1" 300 42
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
    echo "[+] all C++ loader tests passed"
else
    echo "[-] some C++ loader tests FAILED"
    exit 1
fi
