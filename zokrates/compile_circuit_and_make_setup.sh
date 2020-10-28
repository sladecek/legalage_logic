set -e; set -x
ZOKRATES_HOME="${ZOKRATES_HOME:-~/fork/ZoKrates/zokrates_stdlib/stdlib}"
ZOKRATES_BIN="${ZOKRATES_BIN:-$ZOKRATES_HOME/../../target/release/zokrates}"
rm -f out out.ztf proving.key verification.key abi.json log >/dev/null
${ZOKRATES_BIN} check --input legalage.zok > log 2>&1
${ZOKRATES_BIN} compile --input legalage.zok >> log 2>&1
${ZOKRATES_BIN} setup >> log 2>&1
