#!/usr/bin/env bash
#
# check-no-network.sh
#
# JPKI Local Signer は「ネットワーク通信を一切実装しない」ことを設計の中核に
# 置いている（docs/design.md NFR-01 / SECURITY.md 参照）。このスクリプトは
# Sources/ と JPKILocalSignerApp/ 配下を対象に、既知のネットワーキング関連
# シンボルが含まれていないかを grep で機械的に検査する。
#
# 依存: bash と grep のみ（追加ツール不要）。
#
# 使い方:
#   ./scripts/check-no-network.sh
#
# 終了コード:
#   0 - ネットワーキングAPIは見つからなかった
#   1 - 禁止シンボルが1件以上見つかった（詳細を標準出力に表示）

set -u

# スクリプトの場所を基準にリポジトリルートを特定する。
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd)"

# 検査対象ディレクトリ（存在するものだけを対象にする）。
TARGET_DIRS=()
for d in "Sources" "JPKILocalSignerApp"; do
    if [ -d "${REPO_ROOT}/${d}" ]; then
        TARGET_DIRS+=("${REPO_ROOT}/${d}")
    fi
done

if [ "${#TARGET_DIRS[@]}" -eq 0 ]; then
    echo "check-no-network: 検査対象ディレクトリ（Sources/, JPKILocalSignerApp/）が見つかりません。" >&2
    exit 1
fi

# 禁止するネットワーキング関連シンボル（正規表現、拡張grep）。
FORBIDDEN_PATTERNS=(
    'URLSession'
    'URLRequest'
    'NWConnection'
    'NWListener'
    'import[[:space:]]+Network([[:space:]]|$)'
    'CFSocket'
    'getaddrinfo'
    'NSURLConnection'
)

# 検索対象の拡張子。
INCLUDE_GLOBS=(--include='*.swift' --include='*.m' --include='*.mm' --include='*.h' --include='*.c' --include='*.cpp')

found_any=0

for pattern in "${FORBIDDEN_PATTERNS[@]}"; do
    matches="$(grep -rnE "${INCLUDE_GLOBS[@]}" "${pattern}" "${TARGET_DIRS[@]}" 2>/dev/null)"
    if [ -n "${matches}" ]; then
        if [ "${found_any}" -eq 0 ]; then
            echo "check-no-network: 禁止されたネットワーキングAPIが見つかりました:"
            echo
        fi
        found_any=1
        echo "  パターン: ${pattern}"
        echo "${matches}" | sed 's/^/    /'
        echo
    fi
done

if [ "${found_any}" -ne 0 ]; then
    echo "本プロジェクトはネットワーク通信を一切実装しない方針です（docs/design.md NFR-01）。" >&2
    echo "上記のシンボルを削除するか、誤検知であれば本スクリプトの検討対象を見直してください。" >&2
    exit 1
fi

echo "No networking APIs found"
exit 0
