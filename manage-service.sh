#!/bin/bash
# Security Group Manager 服务管理脚本

SERVICE_NAME="security-group-manager.service"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

case "$1" in
    start)
        echo -e "${BLUE}启动服务...${NC}"
        sudo systemctl start $SERVICE_NAME
        ;;
    stop)
        echo -e "${BLUE}停止服务...${NC}"
        sudo systemctl stop $SERVICE_NAME
        ;;
    restart)
        echo -e "${BLUE}重启服务...${NC}"
        sudo systemctl restart $SERVICE_NAME
        ;;
    status)
        echo -e "${BLUE}服务状态：${NC}"
        sudo systemctl status $SERVICE_NAME
        ;;
    enable)
        echo -e "${BLUE}启用开机自启动...${NC}"
        sudo systemctl enable $SERVICE_NAME
        ;;
    disable)
        echo -e "${BLUE}禁用开机自启动...${NC}"
        sudo systemctl disable $SERVICE_NAME
        ;;
    logs)
        echo -e "${BLUE}最近日志：${NC}"
        sudo journalctl -u $SERVICE_NAME -n 50 --no-pager
        ;;
    logs-follow)
        echo -e "${BLUE}实时日志（Ctrl+C退出）：${NC}"
        sudo journalctl -u $SERVICE_NAME -f --no-pager
        ;;
    test)
        echo -e "${BLUE}健康检查：${NC}"
        curl -s http://localhost:5000/health | python3 -m json.tool 2>/dev/null || curl -s http://localhost:5000/health
        ;;
    *)
        echo "Security Group Manager 服务管理脚本"
        echo ""
        echo "用法: $0 {start|stop|restart|status|enable|disable|logs|logs-follow|test}"
        echo ""
        echo "命令说明："
        echo "  start        启动服务"
        echo "  stop         停止服务"
        echo "  restart      重启服务"
        echo "  status       查看服务状态"
        echo "  enable       启用开机自启动"
        echo "  disable      禁用开机自启动"
        echo "  logs         查看最近日志"
        echo "  logs-follow   实时查看日志"
        echo "  test         健康检查"
        ;;
esac
