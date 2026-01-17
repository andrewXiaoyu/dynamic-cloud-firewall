#!/usr/bin/env python3
"""
测试脚本 - 用于验证配置和API连接
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.config import config_manager
from app.providers.factory import get_provider
from app.utils.logger import logger


def test_configuration():
    """测试webhook配置加载"""
    logger.info("===== 测试配置加载 =====")

    try:
        webhook_config = config_manager.get_webhook_config()
        logger.info(f"Webhook配置: {webhook_config}")

        rules_config = config_manager.get_rules_config()
        logger.info(f"规则配置: {rules_config}")

        enabled_providers = config_manager.get_enabled_providers()
        logger.info(f"启用的云厂商: {list(enabled_providers.keys())}")

        return True
    except Exception as e:
        logger.error(f"配置加载失败: {e}")
        return False


def test_provider_initialization():
    """测试云厂商provider初始化"""
    logger.info("===== 测试Provider初始化 =====")

    try:
        enabled_providers = config_manager.get_enabled_providers()

        for provider_name, provider_config in enabled_providers.items():
            logger.info(f"测试 {provider_name} provider...")

            provider = get_provider(provider_name, provider_config)
            if provider:
                logger.info(f"{provider_name} provider 初始化成功")
                initialized = provider.initialize_client()
                logger.info(
                    f"{provider_name} 客户端初始化: {'成功' if initialized else '失败'}"
                )
            else:
                logger.error(f"{provider_name} provider 初始化失败")

        return True
    except Exception as e:
        logger.error(f"Provider初始化测试失败: {e}")
        return False


def test_api_endpoints():
    """测试API端点"""
    logger.info("===== 测试API端点 =====")

    try:
        from app.handlers.webhook import init_webhook_app

        app = init_webhook_app()

        with app.test_client() as client:
            # 测试健康检查
            response = client.get("/health")
            if response.status_code == 200:
                logger.info("健康检查端点正常")
            else:
                logger.error(f"健康检查失败: {response.status_code}")

            # 测试provider信息
            response = client.get("/api/providers")
            if response.status_code == 200:
                logger.info("Provider信息端点正常")
            else:
                logger.error(f"Provider信息端点失败: {response.status_code}")

        return True
    except Exception as e:
        logger.error(f"API端点测试失败: {e}")
        return False


def test_ip_validation():
    """测试IP验证功能"""
    logger.info("===== 测试IP验证功能 =====")

    try:
        from app.utils.validators import validate_ip, is_private_ip

        test_ips = [
            "1.2.3.4",  # 公网IPv4
            "192.168.1.1",  # 私网IPv4
            "2001:db8::1",  # IPv6
            "invalid.ip",  # 无效IP
        ]

        for ip in test_ips:
            is_valid, ip_type = validate_ip(ip)
            private = is_private_ip(ip)
            logger.info(f"IP: {ip}, 有效: {is_valid}, 类型: {ip_type}, 私网: {private}")

        return True
    except Exception as e:
        logger.error(f"IP验证测试失败: {e}")
        return False


def main():
    """主测试函数"""
    logger.info("开始运行功能测试...")

    tests = [
        ("配置加载", test_configuration),
        ("Provider初始化", test_provider_initialization),
        ("API端点", test_api_endpoints),
        ("IP验证", test_ip_validation),
    ]

    passed = 0
    total = len(tests)

    for test_name, test_func in tests:
        logger.info(f"\n--- 开始测试: {test_name} ---")
        try:
            if test_func():
                logger.info(f"✅ {test_name} 测试通过")
                passed += 1
            else:
                logger.error(f"❌ {test_name} 测试失败")
        except Exception as e:
            logger.error(f"❌ {test_name} 测试异常: {e}")

    logger.info(f"\n===== 测试完成 =====")
    logger.info(f"通过: {passed}/{total}")

    if passed == total:
        logger.info("🎉 所有测试通过！")
        return 0
    else:
        logger.error(f"💥 {total - passed} 个测试失败")
        return 1


if __name__ == "__main__":
    sys.exit(main())
