#!/usr/bin/env bash
set -euo pipefail

credential_dir="/Users/lirenzhao/Documents/远程软件文件"
p12_file="$credential_dir/DeveloperID.p12"
api_key_file="$credential_dir/AuthKey_LP5PN9HD8S.p8"

if ! command -v gh >/dev/null 2>&1; then
  echo "错误：未安装 GitHub CLI (gh)。" >&2
  exit 1
fi

if ! git remote get-url origin >/dev/null 2>&1; then
  echo "错误：当前项目尚未关联 GitHub origin 仓库。" >&2
  exit 1
fi

if [[ ! -f "$p12_file" || ! -f "$api_key_file" ]]; then
  echo "错误：没有找到签名证书或 App Store Connect API Key。" >&2
  exit 1
fi

read -r -s -p "请输入 DeveloperID.p12 导出密码（输入时不会显示）：" p12_password
echo
read -r -p "请输入 App Store Connect Issuer ID：" issuer_id

if [[ -z "$p12_password" || -z "$issuer_id" ]]; then
  echo "错误：密码和 Issuer ID 都不能为空。" >&2
  exit 1
fi

echo "正在安全写入 GitHub Actions Secrets…"
base64 < "$p12_file" | tr -d '\n' | gh secret set MACOS_P12_BASE64
printf '%s' "$p12_password" | gh secret set MACOS_P12_PASSWORD
printf '%s' 'Developer ID Application: renzhao li (GB68KE7M26)' | gh secret set MACOS_CODESIGN_IDENTITY
base64 < "$api_key_file" | tr -d '\n' | gh secret set APPLE_API_PRIVATE_KEY_BASE64
printf '%s' 'LP5PN9HD8S' | gh secret set APPLE_API_KEY_ID
printf '%s' "$issuer_id" | gh secret set APPLE_API_ISSUER_ID

unset p12_password issuer_id
echo "完成：6 个 macOS 签名与公证 Secrets 已配置。"
