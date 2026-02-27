#!/bin/bash
# Security Group Manager 服务安装脚本

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_FILE="/etc/systemd/system/security-group-manager.service"
SERVICE_NAME="security-group-manager.service"

echo "======================================"
echo "Security Group Manager 服务安装"
echo "======================================"
echo ""

# 检查root权限
if [ "$EUID" -ne 0 ]; then 
    echo "❌ 请使用sudo运行此脚本"
    exit 1
fi

# 检查服务文件是否已存在
if [ -f "$SERVICE_FILE" ]; then
    echo "⚠️  服务文件已存在，是否覆盖？(y/N)"
    read -r response
    if [ "$response" != "y" ] && [ "$response" != "Y" ]; then
        echo "安装已取消"
        exit 0
    fi
    echo "删除旧的服务文件..."
    rm -f "$SERVICE_FILE"
fi

# 创建服务文件
echo "📝 创建systemd服务文件..."
cat > "$SERVICE_FILE" << 'SERVICE_EOF'
[Unit]
Description=Security Group Manager - 多云安全组自动化管理工具
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/security-group-manager
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/usr/bin/python3 -c "from app.main import main; main()"
Restart=on-failure
RestartSec=10s

StandardOutput=journal
StandardError=journal
SyslogIdentifier=security-group-manager

[Install]
WantedBy=multi-user.target
SERVICE_EOF

echo "✅ 服务文件已创建: $SERVICE_FILE"

# 重新加载systemd配置
echo "🔄 重新加载systemd配置..."
systemctl daemon-reload

if [ $? -ne 0 ]; then
    echo "❌ systemd配置重载失败"
    exit 1
fi

echo "✅ systemd配置已重载"

# 停止旧的服务进程（如果有）
echo "🛑 停止旧的服务进程..."
pkill -f "python3 -c from app.main import main" || true

# 等待进程完全停止
sleep 2

# 启用服务
echo "⚙️  启用开机自启动..."
systemctl enable $SERVICE_NAME

if [ $? -ne 0 ]; then
    echo "❌ 启用开机自启动失败"
    exit 1
fi

echo "✅ 已设置开机自启动"

# 启动服务
echo "🚀 启动服务..."
systemctl start $SERVICE_NAME

if [ $? -ne 0 ]; then
    echo "❌ 服务启动失败"
    exit 1
fi

echo "✅ 服务已启动"

# 等待服务稳定运行
sleep 3

# 检查服务状态
echo ""
echo "======================================"
echo "服务状态检查"
echo "======================================"
systemctl status $SERVICE_NAME --no-pager

# 显示服务信息
echo ""
echo "======================================"
echo "服务管理命令"
echo "======================================"
echo ""
echo "管理服务："
echo "  ./manage-service.sh start        # 启动服务"
echo "  ./manage-service.sh stop         # 停止服务"
echo "  ./manage-service.sh restart     # 重启服务"
echo "  ./manage-service.sh status      # 查看状态"
echo "  ./manage-service.sh enable       # 启用开机自启动"
echo "  ./manage-service.sh disable      # 禁用开机自启动"
echo "  ./manage-service.sh logs       # 查看日志"
echo "  ./manage-service.sh logs-follow   # 实时查看日志"
echo "  ./manage-service.sh test       # 健康检查"
echo ""
echo "健康检查："
echo "  curl http://localhost:5000/health"
echo ""

echo "======================================"
echo "✅ 安装完成！"
echo "======================================"
