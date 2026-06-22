#!/usr/bin/env bash
#
# PM3一键工具 webUI — 启动脚本 (Linux)
# 用法: ./linux_start.sh   (不依赖 GUI 库, 只需 python3)
#
cd "$(dirname "$0")" || exit 1

echo "==============================================="
echo "   PM3一键工具 webUI"
echo "==============================================="

PY=""
for cand in python3 /usr/bin/python3 /usr/local/bin/python3 python; do
    p="$(command -v "$cand" 2>/dev/null)"
    [ -n "$p" ] && { PY="$p"; break; }
done

if [ -z "$PY" ]; then
    echo "[错误] 找不到 Python3。请用包管理器安装, 如:  sudo apt install python3"
    read -n 1 -s -r -p "按任意键关闭..."
    exit 1
fi

echo "[*] 使用: $($PY --version 2>&1)"
echo "[*] 启动本地服务并自动打开浏览器... (Ctrl-C 或关闭终端即停止服务)"
echo "[*] 提示: 连接 Proxmark3 一般需要串口权限, 可把当前用户加入 dialout 组,"
echo "         或用 sudo 运行; 端口通常是 /dev/ttyACM0。"
echo ""
"$PY" "$(dirname "$0")/pm3_web.py"

echo ""
read -n 1 -s -r -p "服务已停止, 按任意键关闭..."
