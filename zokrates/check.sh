set -e; set -x
export ZOKRATES_HOME="${ZOKRATES_HOME:-$HOME/fork/ZoKrates/zokrates_stdlib/stdlib}"
export ZOKRATES_BIN="${ZOKRATES_BIN:-$ZOKRATES_HOME/../../target/release/zokrates}"
${ZOKRATES_BIN} check --input legalage.zok 

