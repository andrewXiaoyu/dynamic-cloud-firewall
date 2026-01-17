from typing import List, Dict, Any
from app.providers.base import BaseProvider


# 简化的provider类，仅用于修复导入错误
class TencentLighthouseProvider(BaseProvider):
    def initialize_client(self) -> bool:
        return True

    def list_security_group_rules(self, security_group_id: str) -> List[Dict[str, Any]]:
        return []

    def add_security_group_rule(
        self,
        ip_address: str,
        security_group_id: str,
        protocol: str,
        ports: List[str],
        description: str = "",
    ) -> bool:
        return False

    def remove_security_group_rule(self, security_group_id: str, rule_id: str) -> bool:
        return False


class AliyunProvider(BaseProvider):
    def initialize_client(self) -> bool:
        return True

    def list_security_group_rules(self, security_group_id: str) -> List[Dict[str, Any]]:
        return []

    def add_security_group_rule(
        self,
        ip_address: str,
        security_group_id: str,
        protocol: str,
        ports: List[str],
        description: str = "",
    ) -> bool:
        return False

    def remove_security_group_rule(self, security_group_id: str, rule_id: str) -> bool:
        return False


class AliyunLighthouseProvider(BaseProvider):
    def initialize_client(self) -> bool:
        return True

    def list_security_group_rules(self, security_group_id: str) -> List[Dict[str, Any]]:
        return []

    def add_security_group_rule(
        self,
        ip_address: str,
        security_group_id: str,
        protocol: str,
        ports: List[str],
        description: str = "",
    ) -> bool:
        return False

    def remove_security_group_rule(self, security_group_id: str, rule_id: str) -> bool:
        return False


class AWSProvider(BaseProvider):
    def initialize_client(self) -> bool:
        return True

    def list_security_group_rules(self, security_group_id: str) -> List[Dict[str, Any]]:
        return []

    def add_security_group_rule(
        self,
        ip_address: str,
        security_group_id: str,
        protocol: str,
        ports: List[str],
        description: str = "",
    ) -> bool:
        return False

    def remove_security_group_rule(self, security_group_id: str, rule_id: str) -> bool:
        return False


class AWSLightsailProvider(BaseProvider):
    def initialize_client(self) -> bool:
        return True

    def list_security_group_rules(self, security_group_id: str) -> List[Dict[str, Any]]:
        return []

    def add_security_group_rule(
        self,
        ip_address: str,
        security_group_id: str,
        protocol: str,
        ports: List[str],
        description: str = "",
    ) -> bool:
        return False

    def remove_security_group_rule(self, security_group_id: str, rule_id: str) -> bool:
        return False


class HuaweiProvider(BaseProvider):
    def initialize_client(self) -> bool:
        return True

    def list_security_group_rules(self, security_group_id: str) -> List[Dict[str, Any]]:
        return []

    def add_security_group_rule(
        self,
        ip_address: str,
        security_group_id: str,
        protocol: str,
        ports: List[str],
        description: str = "",
    ) -> bool:
        return False

    def remove_security_group_rule(self, security_group_id: str, rule_id: str) -> bool:
        return False


class HuaweiLighthouseProvider(BaseProvider):
    def initialize_client(self) -> bool:
        return True

    def list_security_group_rules(self, security_group_id: str) -> List[Dict[str, Any]]:
        return []

    def add_security_group_rule(
        self,
        ip_address: str,
        security_group_id: str,
        protocol: str,
        ports: List[str],
        description: str = "",
    ) -> bool:
        return False

    def remove_security_group_rule(self, security_group_id: str, rule_id: str) -> bool:
        return False
