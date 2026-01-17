#!/bin/bash

# 动态云防火墙启动脚本

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

# 检查Python版本
check_python() {
    log_info "检查Python版本..."
    if ! command -v python3 &> /dev/null; then
        log_error "Python3未安装"
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    REQUIRED_VERSION="3.11"
    
    if python3 -c "import sys; exit(0 if sys.version_info >= (3, 11) else 1)"; then
        log_success "Python版本检查通过: $PYTHON_VERSION"
    else
        log_error "Python版本过低，需要 >= $REQUIRED_VERSION，当前版本: $PYTHON_VERSION"
        exit 1
    fi
}

# 检查依赖
check_dependencies() {
    log_info "检查依赖文件..."
    
    if [ ! -f "requirements.txt" ]; then
        log_error "requirements.txt文件不存在"
        exit 1
    fi
    
    if [ ! -f ".env" ] && [ ! -f "config/config.yaml" ]; then
        log_warning "未找到.env或config/config.yaml，请确保已正确配置"
    fi
}

# 创建必要目录
create_directories() {
    log_info "创建必要目录..."
    mkdir -p logs
    log_success "目录创建完成"
}

# 安装依赖
install_dependencies() {
    log_info "安装Python依赖..."
    if python3 -m pip install -r requirements.txt; then
        log_success "依赖安装完成"
    else
        log_error "依赖安装失败"
        exit 1
    fi
}

# 检查配置
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

# 健康检查
health_check() {
    log_info "执行健康检查..."
    sleep 2
    
    if curl -f http://localhost:5000/health &>/dev/null; then
        log_success "服务健康检查通过"
        return 0
    else
        log_warning "服务健康检查失败，可能是服务正在启动中"
        return 1
    fi
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
    
    # 启动服务
    python3 app/main.py
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
        "start")
            check_python
            check_dependencies
            create_directories
            install_dependencies
            check_config
            start_service
            ;;
        "check")
            health_check
            ;;
        "install")
            check_python
            check_dependencies
            create_directories
            install_dependencies
            check_config
            log_success "安装完成，使用 './run.sh start' 启动服务"
            ;;
        "help"|"-h"|"--help")
            echo "用法: $0 [command]"
            echo ""
            echo "命令:"
            echo "  start     启动服务 (默认)"
            echo "  install   仅安装和检查环境"
            echo "  check     健康检查"
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