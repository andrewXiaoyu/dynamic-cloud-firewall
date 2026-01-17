from typing import List, Dict, Any
from app.providers.base import BaseProvider
from app.utils.validators import is_ipv6
from app.utils.logger import logger


class TencentLighthouseProvider(BaseProvider):
    """腾讯云轻量服务器防火墙管理"""

    def initialize_client(self) -> bool:
        """初始化腾讯云轻量服务器客户端"""
        try:
            from tencentcloud.common import credential
            from tencentcloud.common.profile.http_profile import HttpProfile
            from tencentcloud.common.profile.client_profile import ClientProfile
            from tencentcloud.lighthouse.v20200324 import lighthouse_client

            secret_id = self.config.get("secret_id")
            secret_key = self.config.get("secret_key")
            region = self.config.get("region")

            if not all([secret_id, secret_key, region]):
                logger.error("腾讯云轻量服务器配置不完整")
                return False

            cred = credential.Credential(secret_id, secret_key)
            httpProfile = HttpProfile()
            httpProfile.endpoint = "lighthouse.tencentcloudapi.com"

            clientProfile = ClientProfile()
            clientProfile.httpProfile = httpProfile

            self.client = lighthouse_client.LighthouseClient(
                cred, region, clientProfile
            )
            return True
        except Exception as e:
            logger.error(f"初始化腾讯云轻量服务器客户端失败: {e}")
            return False

    def list_firewall_rules(self, instance_id: str) -> List[Dict[str, Any]]:
        """列出实例的防火墙规则"""
        try:
            from tencentcloud.lighthouse.v20200324 import models as lh_models

            request = lh_models.DescribeFirewallRulesRequest()
            request.InstanceId = instance_id

            response = self.client.DescribeFirewallRules(request)

            rules = []
            if response.FirewallRuleSet:
                for rule in response.FirewallRuleSet:
                    # 解析IP地址
                    ip_address = rule.CidrBlock or ""
                    ip_version = "IPv4"
                    if ip_address:
                        ip_address = ip_address.replace("/32", "").replace("/128", "")
                        if is_ipv6(ip_address):
                            ip_version = "IPv6"

                    # 解析端口
                    ports = []
                    if rule.Port and rule.Port != "ALL":
                        if "-" in rule.Port:
                            parts = rule.Port.split("-")
                            if (
                                len(parts) == 2
                                and parts[0].isdigit()
                                and parts[1].isdigit()
                            ):
                                start, end = int(parts[0]), int(parts[1])
                                if start == end:
                                    ports = [start]
                                else:
                                    ports = [start, end]
                        elif rule.Port.isdigit():
                            ports = [int(rule.Port)]

                    rules.append(
                        {
                            "rule_id": rule.FirewallRuleId
                            if hasattr(rule, "FirewallRuleId")
                            else getattr(rule, "RuleId", None),
                            "protocol": (rule.Protocol or "").lower(),
                            "ports": ports,
                            "ip_address": ip_address,
                            "description": getattr(
                                rule, "Description", getattr(rule, "Remark", "")
                            ),
                            "ip_version": ip_version,
                            "action": rule.Action
                            if hasattr(rule, "Action")
                            else "ACCEPT",
                        }
                    )

            return rules
        except Exception as e:
            logger.error(f"获取腾讯云轻量服务器防火墙规则失败: {e}")
            return []

    def add_firewall_rule(
        self,
        instance_id: str,
        ip_address: str,
        protocol: str,
        ports: List[int],
        description: str,
    ) -> bool:
        if not self.client:
            return False

        try:
            from tencentcloud.lighthouse.v20200324 import models as lh_models

            # 判断IP版本
            ip_version = "IPv6" if is_ipv6(ip_address) else "IPv4"
            cidr_suffix = "/128" if ip_version == "IPv6" else "/32"
            # 腾讯云轻量服务器对IPv6地址格式可能不同
            if ip_version == "IPv6":
                cidr_block = f"{ip_address}{cidr_suffix}"
            else:
                cidr_block = f"{ip_address}{cidr_suffix}"

            # 检查规则是否已存在
            existing_rules = self.list_firewall_rules(instance_id)

            # 统一端口格式为字符串，便于比较
            if len(ports) == 1:
                port_str = str(ports[0])
            elif len(ports) > 1:
                port_str = f"{min(ports)}-{max(ports)}"
            else:
                port_str = "ALL"

            # 检查规则是否已存在
            rule_exists = False
            for rule in existing_rules:
                if (
                    rule["protocol"] == protocol.lower()
                    and rule["ip_address"] == ip_address
                ):
                    if len(ports) == 1 and rule["ports"] == ports:
                        rule_exists = True
                        break
                    elif len(ports) > 1 and rule["ports"] == ports:
                        rule_exists = True
                        break
                    elif len(ports) == 0 and len(rule["ports"]) == 0:
                        rule_exists = True
                        break

            if rule_exists:
                logger.info(
                    f"腾讯云轻量服务器防火墙规则已存在: {instance_id}, IP: {ip_address}, Port: {port_str}"
                )
                return False

                # 继续添加规则

                # 创建规则
                firewall_rule = lh_models.FirewallRule()
                firewall_rule.Protocol = protocol.upper()
                firewall_rule.Port = port_str
                # 根据IP版本选择正确的属性
                if ip_version == "IPv6":
                    firewall_rule.Ipv6CidrBlock = cidr_block
                else:
                    firewall_rule.CidrBlock = cidr_block
                firewall_rule.Action = "ACCEPT"
                firewall_rule.FirewallRuleDescription = description

                request = lh_models.CreateFirewallRulesRequest()
                request.InstanceId = instance_id
                request.FirewallRules = [firewall_rule]

                self.client.CreateFirewallRules(request)
                logger.info(
                    f"腾讯云轻量服务器防火墙规则添加成功: {instance_id}, IP: {ip_address}, Port: {port_str}"
                )

            return True
        except Exception as e:
            logger.error(f"腾讯云轻量服务器添加防火墙规则失败: {e}")
            return False

    def remove_firewall_rule(self, instance_id: str, rule_id: str) -> bool:
        if not self.client:
            return False

        try:
            from tencentcloud.lighthouse.v20200324 import models as lh_models

            request = lh_models.DeleteFirewallRulesRequest()
            request.InstanceId = instance_id
            # 对于腾讯云轻量服务器，需要通过RuleId删除
            # 但根据API文档，需要通过InstanceId和规则的其他属性来匹配
            rule = lh_models.FirewallRule()
            if rule_id:
                # 如果有rule_id，说明是通过list获取的，需要通过属性匹配来删除
                for existing_rule in self.list_firewall_rules(instance_id):
                    if existing_rule["rule_id"] == rule_id:
                        rule.Protocol = existing_rule["protocol"].upper()
                        rule.Port = (
                            str(existing_rule["ports"][0])
                            if existing_rule["ports"]
                            else "ALL"
                        )
                        rule.CidrBlock = existing_rule.get("cidr", "")
                        break
            request.FirewallRules = [rule]

            self.client.DeleteFirewallRules(request)
            logger.info(
                f"腾讯云轻量服务器防火墙规则删除成功: {instance_id}, Rule: {rule_id}"
            )
            return True
        except Exception as e:
            logger.error(f"腾讯云轻量服务器删除防火墙规则失败: {e}")
            return False

    def cleanup_old_firewall_rules(
        self,
        instance_id: str,
        current_ip: str,
        protocol: str,
        ports: List[int],
        days: int = 7,
    ) -> int:
        """清理旧的防火墙规则"""
        removed_count = 0
        current_ip_version = "IPv6" if is_ipv6(current_ip) else "IPv4"

        rules = self.list_firewall_rules(instance_id)
        for rule in rules:
            if (
                rule["protocol"] == protocol.lower()
                and (
                    (len(ports) == 1 and set(rule["ports"]) == set(ports))
                    or (len(ports) > 1 and rule["ports"] == ports)
                    or (len(ports) == 0 and len(rule["ports"]) == 0)
                )
                and rule["ip_address"] != current_ip
                and "Home" in rule["description"]
                and rule["ip_version"] == current_ip_version
                and rule["rule_id"]
            ):
                if self.remove_firewall_rule(instance_id, rule["rule_id"]):
                    removed_count += 1
                    logger.info(
                        f"已清理腾讯云轻量服务器旧防火墙规则: {rule['ip_address']}"
                    )

        return removed_count

    def find_and_remove_old_ip_rules(
        self,
        instance_id: str,
        protocol: str,
        ports: List[int],
        new_ip: str,
    ) -> int:
        """查找并删除旧的IP规则"""
        return self.cleanup_old_firewall_rules(instance_id, new_ip, protocol, ports, 7)

    # 为了兼容现有接口，实现安全组相关方法
    def list_security_group_rules(self, security_group_id: str) -> List[Dict[str, Any]]:
        """列出防火墙规则（兼容接口）"""
        return self.list_firewall_rules(security_group_id)

    def add_security_group_rule(
        self,
        ip_address: str,
        security_group_id: str,
        protocol: str,
        ports: List[int],
        description: str = "",
    ) -> bool:
        """添加防火墙规则（兼容接口）"""
        return self.add_firewall_rule(
            security_group_id, ip_address, protocol, ports, description
        )

    def remove_security_group_rule(self, security_group_id: str, rule_id: str) -> bool:
        """删除防火墙规则（兼容接口）"""
        return self.remove_firewall_rule(security_group_id, rule_id)
