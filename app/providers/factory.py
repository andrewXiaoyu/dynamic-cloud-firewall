from typing import Dict, Any, Optional
from app.providers.base import BaseProvider
from app.providers.client_manager import client_manager
from app.providers.tencent import TencentProvider
from app.providers.others import (
    TencentLighthouseProvider,
    AliyunProvider,
    AliyunLighthouseProvider,
    AWSProvider,
    AWSLightsailProvider,
    HuaweiProvider,
    HuaweiLighthouseProvider,
)

PROVIDER_MAP = {
    "tencent": TencentProvider,
    "tencent_lighthouse": TencentLighthouseProvider,
    "aliyun": AliyunProvider,
    "aliyun_lighthouse": AliyunLighthouseProvider,
    "aws": AWSProvider,
    "aws_lightsail": AWSLightsailProvider,
    "huawei": HuaweiProvider,
    "huawei_lighthouse": HuaweiLighthouseProvider,
}


def create_provider(provider_name: str, config: Dict[str, Any]) -> BaseProvider:
    """
    创建provider实例（已废弃，请使用get_provider）

    Args:
        provider_name: 云厂商名称
        config: 云厂商配置

    Returns:
        BaseProvider: provider实例
    """
    from app.utils.logger import logger

    logger.warning("create_provider已废弃，请使用get_provider")
    return get_provider(provider_name, config)


def get_provider(provider_name: str, config: Dict[str, Any]) -> Optional[BaseProvider]:
    """
    获取provider实例，支持客户端缓存和复用

    Args:
        provider_name: 云厂商名称
        config: 云厂商配置

    Returns:
        BaseProvider: provider实例，创建失败返回None
    """
    return client_manager.get_or_create_provider(provider_name, config)


def get_supported_providers() -> list:
    """获取所有支持的云厂商列表"""
    return list(PROVIDER_MAP.keys())


def get_provider_info() -> Dict[str, Any]:
    """
    获取当前provider缓存信息

    Returns:
        Dict[str, Any]: 缓存信息
    """
    return {
        "total_count": client_manager.get_provider_count(),
        "providers": client_manager.list_providers(),
        "supported": get_supported_providers(),
    }


def clear_provider_cache(provider_name: str = None):
    """
    清理provider缓存

    Args:
        provider_name: 云厂商名称，如果为None则清理所有
    """
    client_manager.clear_provider(provider_name)


# 向后兼容的函数
def create_provider_with_cache(
    provider_name: str, config: Dict[str, Any]
) -> Optional[BaseProvider]:
    """
    带缓存的provider创建函数（向后兼容）

    Args:
        provider_name: 云厂商名称
        config: 云厂商配置

    Returns:
        BaseProvider: provider实例，创建失败返回None
    """
    return get_provider(provider_name, config)
