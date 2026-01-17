from typing import Dict, Any, Optional
from threading import Lock
from app.providers.base import BaseProvider
from app.utils.logger import logger


class ClientManager:
    """云厂商客户端管理器，实现客户端的单例化和复用"""

    _instance = None
    _lock = Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._providers = {}
                    cls._instance._configs = {}
        return cls._instance

    def get_or_create_provider(
        self, provider_name: str, config: Dict[str, Any]
    ) -> BaseProvider:
        """
        获取或创建provider实例，确保每个provider只初始化一次

        Args:
            provider_name: 云厂商名称
            config: 云厂商配置

        Returns:
            BaseProvider: provider实例
        """
        # 生成配置的哈希值用于识别相同配置
        config_key = self._generate_config_key(provider_name, config)

        with self._lock:
            if config_key not in self._providers:
                logger.info(f"创建新的provider实例: {provider_name}")
                provider = self._create_provider(provider_name, config)
                if provider:
                    self._providers[config_key] = provider
                    self._configs[config_key] = config
                else:
                    logger.error(f"创建provider失败: {provider_name}")
                    return None
            else:
                logger.debug(f"复用现有provider实例: {provider_name}")

        return self._providers[config_key]

    def _generate_config_key(self, provider_name: str, config: Dict[str, Any]) -> str:
        """
        生成配置的唯一标识符

        Args:
            provider_name: 云厂商名称
            config: 配置字典

        Returns:
            str: 配置的唯一标识符
        """
        # 提取关键配置字段用于生成唯一标识
        key_fields = {
            "tencent": ["region", "secret_id"],
            "tencent_lighthouse": ["region", "secret_id"],
            "aliyun": ["region", "access_key_id"],
            "aliyun_lighthouse": ["region", "access_key_id"],
            "aws": ["region", "access_key_id"],
            "aws_lightsail": ["region", "access_key_id"],
            "huawei": ["region", "ak"],
            "huawei_lighthouse": ["region", "ak"],
        }

        fields = key_fields.get(provider_name, ["region"])
        config_parts = [provider_name]

        for field in fields:
            value = config.get(field, "")
            if value:
                config_parts.append(f"{field}:{value}")

        return "|".join(config_parts)

    def _create_provider(
        self, provider_name: str, config: Dict[str, Any]
    ) -> Optional[BaseProvider]:
        """
        创建新的provider实例

        Args:
            provider_name: 云厂商名称
            config: 配置字典

        Returns:
            BaseProvider: provider实例，创建失败返回None
        """
        try:
            from app.providers.factory import PROVIDER_MAP

            provider_class = PROVIDER_MAP.get(provider_name.lower())
            if provider_class is None:
                logger.error(f"不支持的云厂商: {provider_name}")
                return None

            provider = provider_class(config)
            if (
                hasattr(provider, "initialize_client")
                and not provider.initialize_client()
            ):
                logger.error(f"初始化provider客户端失败: {provider_name}")
                return None
            return provider
        except Exception as e:
            logger.error(f"创建provider失败: {provider_name}, 错误: {e}")
            return None

    def clear_provider(self, provider_name: str = None, config: Dict[str, Any] = None):
        """
        清理指定的provider实例

        Args:
            provider_name: 云厂商名称，如果为None则清理所有
            config: 配置字典，如果为None则清理该provider的所有实例
        """
        with self._lock:
            if provider_name is None:
                self._providers.clear()
                self._configs.clear()
                logger.info("已清理所有provider实例")
            else:
                keys_to_remove = []
                for key in self._providers.keys():
                    if key.startswith(f"{provider_name}|"):
                        keys_to_remove.append(key)

                for key in keys_to_remove:
                    del self._providers[key]
                    if key in self._configs:
                        del self._configs[key]

                logger.info(
                    f"已清理{len(keys_to_remove)}个{provider_name} provider实例"
                )

    def get_provider_count(self, provider_name: str = None) -> int:
        """
        获取当前缓存的provider数量

        Args:
            provider_name: 云厂商名称，如果为None则返回总数

        Returns:
            int: provider数量
        """
        if provider_name is None:
            return len(self._providers)
        else:
            return sum(
                1
                for key in self._providers.keys()
                if key.startswith(f"{provider_name}|")
            )

    def list_providers(self) -> Dict[str, str]:
        """
        列出所有缓存的provider

        Returns:
            Dict[str, str]: 配置键到provider名称的映射
        """
        result = {}
        for key in self._providers.keys():
            parts = key.split("|", 1)
            provider_name = parts[0] if parts else "unknown"
            result[key] = provider_name
        return result


# 全局客户端管理器实例
client_manager = ClientManager()
