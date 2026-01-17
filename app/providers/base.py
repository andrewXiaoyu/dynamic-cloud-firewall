from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional


class BaseProvider(ABC):
    """云厂商安全组管理基类"""

    def __init__(self, config: Dict[str, Any]):
        """
        初始化云厂商提供商

        Args:
            config: 云厂商配置信息
        """
        self.config = config
        self.region = config.get("region", "")
        self.client = None

    @abstractmethod
    def initialize_client(self) -> bool:
        """
        初始化云厂商客户端

        Returns:
            bool: 初始化是否成功
        """
        pass

    @abstractmethod
    def list_security_group_rules(self, security_group_id: str) -> List[Dict[str, Any]]:
        """
        列出安全组规则

        Args:
            security_group_id: 安全组ID

        Returns:
            List[Dict[str, Any]]: 规则列表
        """
        pass

    @abstractmethod
    def add_security_group_rule(
        self,
        ip_address: str,
        security_group_id: str,
        protocol: str,
        ports: List[str],
        description: str = "",
    ) -> bool:
        """
        添加安全组规则

        Args:
            ip_address: IP地址
            security_group_id: 安全组ID
            protocol: 协议类型 (tcp/udp/icmp)
            ports: 端口列表
            description: 规则描述

        Returns:
            bool: 添加是否成功
        """
        pass

    @abstractmethod
    def remove_security_group_rule(self, security_group_id: str, rule_id: str) -> bool:
        """
        删除安全组规则

        Args:
            security_group_id: 安全组ID
            rule_id: 规则ID

        Returns:
            bool: 删除是否成功
        """
        pass

    def find_and_remove_old_ip_rules(
        self, security_group_id: str, protocol: str, ports: List[str], current_ip: str
    ) -> int:
        """
        查找并删除旧IP规则

        Args:
            security_group_id: 安全组ID
            protocol: 协议类型
            ports: 端口列表
            current_ip: 当前IP地址

        Returns:
            int: 删除的规则数量
        """
        try:
            rules = self.list_security_group_rules(security_group_id)
            removed_count = 0

            for rule in rules:
                if self._is_old_rule(rule, protocol, ports, current_ip):
                    rule_id = rule.get("rule_id", "")
                    if self.remove_security_group_rule(security_group_id, rule_id):
                        removed_count += 1

            return removed_count
        except Exception as e:
            from app.utils.logger import logger

            logger.error(f"清理旧规则失败: {e}")
            return 0

    def _is_old_rule(
        self, rule: Dict[str, Any], protocol: str, ports: List[str], current_ip: str
    ) -> bool:
        """
        判断是否为旧规则

        Args:
            rule: 规则信息
            protocol: 协议类型
            ports: 端口列表
            current_ip: 当前IP地址

        Returns:
            bool: 是否为旧规则
        """
        # 基础检查：协议和端口匹配
        if rule.get("protocol") != protocol:
            return False

        if not self._ports_match(rule.get("ports", []), ports):
            return False

        # 检查IP地址：排除当前IP
        rule_cidr = rule.get("cidr", "")
        if not rule_cidr or current_ip in rule_cidr:
            return False

        # 检查是否为家庭IP类型的规则（通过描述判断）
        description = rule.get("description", "")
        home_keywords = ["home", "家庭", "住宅", "residential", "ddns"]

        return any(keyword.lower() in description.lower() for keyword in home_keywords)

    def _ports_match(self, rule_ports: List[str], target_ports: List[str]) -> bool:
        """
        检查端口是否匹配

        Args:
            rule_ports: 规则端口
            target_ports: 目标端口

        Returns:
            bool: 是否匹配
        """
        # 处理端口范围和单个端口的匹配逻辑
        if not rule_ports or not target_ports:
            return False

        # 简化处理：检查是否有交集
        for target_port in target_ports:
            if target_port in rule_ports:
                return True

        return False
