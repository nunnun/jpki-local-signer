#!/bin/bash
# macOS: USB IC カードリーダーでマイナンバーカード署名を実行する。
# TKSmartCardSlotManager には com.apple.security.smartcard entitlement が
# 必要なため、ビルド後に ad-hoc 署名してから実行する。
#
# 使い方:
#   scripts/card-sign.sh --card-info                     # リーダー/カード診断
#   scripts/card-sign.sh --card-sign in.pdf out.pdf      # 実カード署名
#   scripts/card-sign.sh --verify signed.pdf             # 検証
#   scripts/card-sign.sh --moj signed.pdf                # 登記適合チェック
set -euo pipefail
cd "$(dirname "$0")/.."
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
swift build --product TestSigner >/dev/null
BIN=.build/debug/TestSigner
codesign --force --sign - --entitlements scripts/smartcard.entitlements "$BIN" 2>/dev/null
exec "$BIN" "$@"
