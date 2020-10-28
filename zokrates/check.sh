set -e; set -x
ZOKRATES_HOME="${ZOKRATES_HOME:-~/fork/ZoKrates/zokrates_stdlib/stdlib}"
ZOKRATES_BIN="${ZOKRATES_BIN:-$ZOKRATES_HOME/../../target/release/zokrates}"
${ZOKRATES_BIN} check --input legalage.zok 

