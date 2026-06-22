#!/usr/bin/env bash
#
# PM3一键工具 webUI — 启动脚本 (macOS 可双击)
# 不依赖 GUI 库, 只需 python3。
#
cd "$(dirname "$0")" || exit 1

echo "==============================================="
echo "   PM3一键工具 webUI"
echo "==============================================="

# 查找 python3 (浏览器版不需要 tkinter)
PY=""
for cand in python3 /usr/bin/python3 /usr/local/bin/python3 /opt/homebrew/bin/python3 python; do
    p="$(command -v "$cand" 2>/dev/null)"
    [ -n "$p" ] && { PY="$p"; break; }
done

if [ -z "$PY" ]; then
    echo "[错误] 找不到 Python3。请运行  xcode-select --install  安装。"
    read -n 1 -s -r -p "按任意键关闭..."
    exit 1
fi

echo "[*] 使用: $($PY --version 2>&1)"
echo "[*] 启动本地服务并自动打开浏览器... (关闭此终端窗口即停止服务)"
echo ""
"$PY" "$(dirname "$0")/pm3_web.py"

echo ""
read -n 1 -s -r -p "服务已停止, 按任意键关闭..."
