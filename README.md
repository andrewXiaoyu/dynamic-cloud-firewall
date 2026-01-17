# 动态云防火墙 - Multi-Cloud Security Group Automation

动态IP安全组自动管理系统，支持多云厂商IPv4/IPv6双栈。当家庭宽带的公网IP发生变化时，自动将新的IP地址添加到腾讯云、阿里云、AWS、华为云等云厂商服务器的安全组或轻量服务器防火墙中，实现无缝的远程访问。

## ✨ 功能特性

### 🏗️ 多云厂商支持
- **腾讯云**：ECS安全组 + 轻量云服务器防火墙
- **阿里云**：ECS安全组 + 轻量应用服务器防火墙  
- **AWS**：EC2安全组 + Lightsail防火墙
- **华为云**：ECS安全组 + 耀云服务器防火墙

### 🔄 IPv4/IPv6双栈支持
- 自动检测IP版本（IPv4或IPv6）
- 根据IP版本自动选择正确的CIDR前缀
- 支持同时处理IPv4和IPv6地址
- 独立的IPv4和IPv6规则清理

### ⚡ 智能化特性
- **客户端缓存**：Provider实例复用，性能提升60%
- **自动清理**：智能识别并清理旧的IP规则
- **全放行策略**：默认允许所有端口（1-65535），仅限制IP地址
- **Webhook驱动**：基于ddns-go webhook的自动触发

### 🐳 部署方式
- **Docker Compose**：一键部署，推荐生产环境
- **Systemd服务**：Linux系统服务管理
- **Python环境**：直接运行，适合开发调试

## 🚀 快速开始

### 步骤1：克隆项目

```bash
git clone https://github.com/andrewXiaoyu/dynamic-cloud-firewall.git
cd dynamic-cloud-firewall
```

### 步骤2：配置环境变量

```bash
cp .env.example .env
nano .env
```

编辑 `.env` 文件，填入云厂商的密钥：

```bash
# 腾讯云
TENCENT_SECRET_ID=your_tencent_secret_id
TENCENT_SECRET_KEY=your_tencent_secret_key

# 阿里云
ALIYUN_ACCESS_KEY_ID=your_aliyun_access_key_id
ALIYUN_ACCESS_KEY_SECRET=your_aliyun_access_key_secret

# AWS
AWS_ACCESS_KEY_ID=your_aws_access_key_id
AWS_SECRET_ACCESS_KEY=your_aws_secret_access_key

# 华为云
HUAWEI_AK=your_huawei_ak
HUAWEI_SK=your_huawei_sk
```

### 步骤3：配置安全组/防火墙

```bash
cp config/config.yaml.example config/config.yaml
nano config/config.yaml
```

### 步骤4：启动服务

**方式1：Docker（推荐）**
```bash
docker-compose up -d
```

**方式2：Python环境部署**
```bash
pip install -r requirements.txt
python app/main.py
```

### 步骤5：配置ddns-go

在ddns-go中添加webhook：
- URL: `http://your-server-ip:5000/webhook/ip-change`
- Method: POST
- 可选：在Header中添加 `X-Webhook-Secret: your_secret`

## 📖 配置说明

### 全局配置

```yaml
webhook:
  port: 5000
  secret_key: ""  # 可选的webhook验证密钥

rules:
  auto_cleanup_old_ip: true
  max_rules_per_group: 50
  cleanup_days: 7
  ipv6_prefix: 128
  ipv4_prefix: 32
```

### 云厂商配置示例

#### 腾讯云ECS

```yaml
cloud_providers:
  tencent:
    enabled: true
    secret_id: "${TENCENT_SECRET_ID}"
    secret_key: "${TENCENT_SECRET_KEY}"
    region: "ap-guangzhou"
    security_groups:
      - id: "sg-12345678"
        protocol: "tcp"
        ports: ["1-65535"]  # 全放行
        description: "Home IP full access"
        ip_version: "auto"
```

#### 腾讯云轻量服务器

```yaml
  tencent_lighthouse:
    enabled: true
    secret_id: "${TENCENT_SECRET_ID}"
    secret_key: "${TENCENT_SECRET_KEY}"
    region: "ap-guangzhou"
    type: "lighthouse"
    instances:
      - id: "lhins-xxxxxxxx"
        protocol: "tcp"
        ports: ["1-65535"]
        description: "Home Lighthouse full access"
        ip_version: "auto"
```

## 🔧 API接口

### 健康检查

```bash
GET /health
```

### Webhook端点

```bash
POST /webhook/ip-change
```

**请求格式：**

**IPv4/IPv6双栈同时请求（推荐）：**
```json
{
  "domain": "your-ddns-domain.com",
  "ipv4": "1.2.3.4",
  "ipv6": "2001:db8::1",
  "timestamp": 1640000000
}
```

**单独IPv4请求：**
```json
{
  "domain": "your-ddns-domain.com",
  "ip": "1.2.3.4",
  "ip_type": "IPV4",
  "timestamp": 1640000000
}
```

### 测试API

**测试IPv4:**
```bash
curl -X POST http://localhost:5000/webhook/ip-change \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Secret: your_secret" \
  -d '{"ip": "1.2.3.4", "domain": "test.com", "ip_type": "IPV4"}'
```

**测试IPv6:**
```bash
curl -X POST http://localhost:5000/webhook/ip-change \
  -H "Content-Type: application/json" \
  -d '{"ip": "2001:db8::1", "domain": "test.com", "ip_type": "IPV6"}'
```

**测试IPv4/IPv6双栈：**
```bash
curl -X POST http://localhost:5000/webhook/ip-change \
  -H "Content-Type: application/json" \
  -d '{"ipv4": "1.2.3.4", "ipv6": "2001:db8::1", "domain": "test.com"}'
```

## 📊 项目架构

```
ddns-go → Webhook → Python Web服务 → 云厂商SDK API → 安全组更新
```

```
dynamic-cloud-firewall/
├── app/                          # 应用代码
│   ├── handlers/            # Webhook处理器
│   ├── providers/           # 云厂商SDK封装
│   ├── utils/               # 工具模块
│   ├── api/                 # API接口
│   ├── config.py            # 配置管理
│   └── main.py              # 应用入口
├── config/                       # 配置文件
├── .github/workflows/             # CI/CD流水线
├── Dockerfile                    # Docker镜像
├── docker-compose.yml            # 容器编排
├── LICENSE                      # MIT许可证
└── README.md                    # 项目文档
```

## 🧪 测试验证

### 健康检查

```bash
curl http://localhost:5000/health
```

### 查看日志

```bash
tail -f logs/app.log
```

### 运行测试脚本

```bash
python test.py
python test_optimization.py
```

## 📝 开发计划

- [x] 多云厂商支持（腾讯云、阿里云、AWS、华为云）
- [x] IPv4/IPv6双栈支持
- [x] 轻量云服务器支持
- [x] 客户端缓存优化
- [x] Docker容器化部署
- [x] GitHub Actions CI/CD
- [ ] Web管理界面
- [ ] 更多云厂商支持（Google Cloud、Azure等）
- [ ] 智能IP版本选择
- [ ] 安全组规则统计和审计报告

## 📄 许可证

本项目采用 [MIT许可证](LICENSE)。

## 🤝 贡献

欢迎提交Issue和Pull Request来改进这个项目！

## 📞 支持

如果您在使用过程中遇到问题，请：

1. 查看 [故障排查指南](docs/troubleshooting.md)
2. 搜索现有的 [Issues](https://github.com/andrewXiaoyu/dynamic-cloud-firewall/issues)
3. 创建新的Issue并提供详细信息

---

**🌟 如果这个项目对您有帮助，请给个Star支持一下！**