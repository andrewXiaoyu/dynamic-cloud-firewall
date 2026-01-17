.PHONY: help install test run docker-build docker-run clean lint format

help: ## 显示帮助信息
	@echo "动态云防火墙 - Multi-Cloud Security Group Automation"
	@echo ""
	@echo "可用命令:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## 安装Python依赖
	pip install -r requirements.txt

test: ## 运行测试
	python test.py
	python test_optimization.py

run: ## 运行应用
	python app/main.py

dev: ## 开发模式运行
	python -m flask --app app.main run --debug

lint: ## 代码检查
	python -m flake8 app/
	python -m black --check app/

format: ## 代码格式化
	python -m black app/
	python -m isort app/

docker-build: ## 构建Docker镜像
	docker build -t dynamic-cloud-firewall:latest .

docker-run: ## 运行Docker容器
	docker-compose up -d

docker-stop: ## 停止Docker容器
	docker-compose down

docker-logs: ## 查看Docker日志
	docker-compose logs -f

clean: ## 清理临时文件
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +

setup-dev: ## 设置开发环境
	pip install -r requirements.txt
	pip install flake8 black isort pytest pytest-cov safety bandit

security-check: ## 安全检查
	safety check -r requirements.txt
	bandit -r app/

coverage: ## 测试覆盖率
	pytest --cov=app --cov-report=html

health-check: ## 健康检查
	curl -f http://localhost:5000/health || echo "服务未运行"

deploy-staging: ## 部署到测试环境
	docker-compose -f docker-compose.staging.yml up -d

deploy-production: ## 部署到生产环境
	docker-compose -f docker-compose.prod.yml up -d

backup-config: ## 备份配置文件
	cp config/config.yaml config/config.yaml.backup.$$(date +%Y%m%d_%H%M%S)

restore-config: ## 恢复配置文件
	@echo "可用的备份文件:"
	@ls -la config/config.yaml.backup.*
	@read -p "请输入要恢复的备份文件名: " backup; \
	cp "config/$$backup" config/config.yaml