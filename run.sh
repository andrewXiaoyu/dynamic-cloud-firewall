#!/bin/bash

# 简化的动态云防火墙启动脚本

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查Python依赖
check_dependencies() {
    log_info "检查Python依赖..."
    
    local missing_deps=()
    
    # 检查基本依赖
    python3 -c "import flask" 2>/dev/null || missing_deps+=("flask")
    python3 -c "import yaml" 2>/dev/null || missing_deps+=("pyyaml")
    python3 -c "import dotenv" 2>/dev/null || missing_deps+=("python-dotenv")
    python3 -c "import loguru" 2>/dev/null || missing_deps+=("loguru")
    
    if [ ${#missing_deps[@]} -eq 0 ]; then
        log_success "所有基本依赖都已安装"
    else
        log_error "缺少依赖: ${missing_deps[*]}"
        log_info "请运行: pip install --user ${missing_deps[*]}"
        exit 1
    fi
}

# 检查云厂商SDK
check_cloud_sdks() {
    log_info "检查云厂商SDK..."
    
    local sdks=()
    python3 -c "import tencentcloud_sdk_python" 2>/dev/null && sdks+=("腾讯云") || sdks+=("")
    python3 -c "import alibabacloud_ecs20140526" 2>/dev/null && sdks+=("阿里云") || sdks+=("")
    python3 -c "import boto3" 2>/dev/null && sdks+=("AWS") || sdks+=("")
    python3 -c "import huaweicloudsdkecs" 2>/dev/null && sdks+=("华为云") || sdks+=("")
    
    if [ ${#sdks[@]} -gt 0 ]; then
        log_success "已安装的云厂商SDK: ${sdks[*]}"
    else
        log_warning "未检测到云厂商SDK"
    fi
}

# 检查配置文件
check_config() {
    log_info "检查配置文件..."
    
    if [ ! -f "config/config.yaml" ]; then
        if [ -f "config/config.yaml.example" ]; then
            log_warning "配置文件不存在，正在从模板复制..."
            cp config/config.yaml.example config/config.yaml
            log_info "请编辑config/config.yaml配置文件"
        else
            log_error "配置文件模板不存在"
            exit 1
        fi
    fi
    
    if [ ! -f ".env" ]; then
        if [ -f ".env.example" ]; then
            log_warning "环境变量文件不存在，正在从模板复制..."
            cp .env.example .env
            log_info "请编辑.env环境变量文件"
        fi
    fi
}

# 创建必要目录
create_directories() {
    log_info "创建必要目录..."
    mkdir -p logs
    log_success "目录创建完成"
}

# 启动服务
start_service() {
    log_info "启动动态云防火墙服务..."
    
    # 检查端口是否被占用
    if lsof -Pi :5000 -sTCP:LISTEN -t >/dev/null 2>&1; then
        log_warning "端口5000已被占用，正在尝试停止现有服务..."
        pkill -f "app/main.py" || true
        sleep 2
    fi
    
    # 设置环境变量
    export FLASK_APP=app.main
    export FLASK_ENV=production
    
    # 启动服务
    cd /home/ubuntu/security-group-manager
    if python3 -c "from app.main import main; main()"; then
        log_success "服务启动成功"
    else
        log_error "服务启动失败"
        exit 1
    fi
}

# 主函数
main() {
    echo "=========================================="
    echo "   动态云防火墙 - Dynamic Cloud Firewall"
    echo "   Multi-Cloud Security Group Automation"
    echo "=========================================="
    echo ""
    
    # 检查参数
    case "${1:-start}" in
        "check")
            check_dependencies
            check_cloud_sdks
            ;;
        "install")
            log_info "请手动安装缺失的依赖"
            log_info "命令: pip install --user [package_name]"
            ;;
        "start")
            check_dependencies
            check_cloud_sdks
            check_config
            create_directories
            start_service
            ;;
        "help"|"-h"|"--help")
            echo "用法: $0 [command]"
            echo ""
            echo "命令:"
            echo "  start     启动服务 (默认)"
            echo "  check     检查依赖和SDK"
            echo "  install   显示安装说明"
            echo "  help      显示帮助信息"
            echo ""
            ;;
        *)
            log_error "未知命令: $1"
            echo "使用 '$0 help' 查看可用命令"
            exit 1
            ;;
    esac
}

# 捕获信号
trap 'log_warning "接收到中断信号，正在停止服务..."; exit 130' INT TERM

# 执行主函数
main "$@"