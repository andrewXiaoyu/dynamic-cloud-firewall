import os
import yaml
from typing import Dict, Any, Optional
from dotenv import load_dotenv


class ConfigManager:
    """配置管理器"""

    def __init__(self, config_file: str = "config/config.yaml"):
        """
        初始化配置管理器

        Args:
            config_file: 配置文件路径
        """
        self.config_file = config_file
        self.config = None
        self._load_config()

    def _load_config(self):
        """加载配置文件"""
        try:
            # 加载环境变量
            load_dotenv()

            # 读取YAML配置文件
            with open(self.config_file, "r", encoding="utf-8") as f:
                self.config = yaml.safe_load(f)

            # 替换环境变量
            self._replace_env_vars()

        except FileNotFoundError:
            print(f"配置文件不存在: {self.config_file}")
            self.config = {}
        except yaml.YAMLError as e:
            print(f"配置文件格式错误: {e}")
            self.config = {}

    def _replace_env_vars(self):
        """替换配置中的环境变量"""
        if not self.config:
            return

        def replace_recursive(obj):
            if isinstance(obj, dict):
                return {k: replace_recursive(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [replace_recursive(item) for item in obj]
            elif isinstance(obj, str) and obj.startswith("${") and obj.endswith("}"):
                env_var = obj[2:-1]
                return os.getenv(env_var, obj)
            else:
                return obj

        self.config = replace_recursive(self.config)

    def get_webhook_config(self) -> Dict[str, Any]:
        """获取webhook配置"""
        return self.config.get("webhook", {})

    def get_cloud_providers_config(self) -> Dict[str, Any]:
        """获取云厂商配置"""
        return self.config.get("cloud_providers", {})

    def get_enabled_providers(self) -> Dict[str, Any]:
        """获取启用的云厂商配置"""
        providers = self.get_cloud_providers_config()
        return {
            name: config
            for name, config in providers.items()
            if config.get("enabled", False)
        }

    def get_rules_config(self) -> Dict[str, Any]:
        """获取规则配置"""
        return self.config.get("rules", {})

    def get_provider_config(self, provider_name: str) -> Optional[Dict[str, Any]]:
        """
        获取指定云厂商的配置

        Args:
            provider_name: 云厂商名称

        Returns:
            Dict[str, Any]: 配置信息，不存在返回None
        """
        providers = self.get_cloud_providers_config()
        return providers.get(provider_name)

    def get_all_config(self) -> Dict[str, Any]:
        """获取所有配置"""
        return self.config or {}

    def reload_config(self):
        """重新加载配置"""
        self._load_config()


# 全局配置管理器实例
config_manager = ConfigManager()
