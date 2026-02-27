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
                    # 解析IP地址 - 同时检查IPv4和IPv6 CIDR块
                    ipv4_cidr = rule.CidrBlock or ""
                    ipv6_cidr = rule.Ipv6CidrBlock or ""
                    ip_address = ""
                    ip_version = "IPv4"

                    if ipv6_cidr:
                        ip_address = ipv6_cidr
                        ip_version = "IPv6"
                    elif ipv4_cidr:
                        ip_address = ipv4_cidr
                        ip_version = "IPv4"

                    # 移除CIDR后缀
                    if ip_address:
                        ip_address = ip_address.replace("/32", "").replace("/128", "")

                    # 参考阿里云的方式，统一端口格式为列表
                    port_value = rule.Port or ""
                    ports = []
                    if port_value and port_value != "ALL":
                        # 腾讯云轻量服务器可能返回字符串格式的端口
                        if isinstance(port_value, str):
                            ports = [port_value]
                        else:
                            ports = port_value
                    else:
                        ports = ["all"]

                    # 尝试获取描述字段，腾讯云轻量服务器可能使用不同的字段名
                    description = ""
                    if hasattr(rule, "FirewallRuleDescription"):
                        description = rule.FirewallRuleDescription or ""
                    elif hasattr(rule, "Description"):
                        description = rule.Description or ""
                    elif hasattr(rule, "Remark"):
                        description = rule.Remark or ""
                    elif hasattr(rule, "RuleDescription"):
                        description = rule.RuleDescription or ""

                    # 调试：打印规则的所有属性
                    logger.debug(
                        f"腾讯云轻量服务器: 规则属性 - IP={ip_address}, 描述字段: {description}, Protocol={rule.Protocol}"
                    )

                    rules.append(
                        {
                            "rule_id": rule.FirewallRuleId
                            if hasattr(rule, "FirewallRuleId")
                            else getattr(rule, "RuleId", None),
                            "protocol": (rule.Protocol or "").lower(),
                            "ports": ports,
                            "ip_address": ip_address,
                            "description": description,
                            "ip_version": ip_version,
                            "action": rule.Action
                            if hasattr(rule, "Action")
                            else "ACCEPT",
                        }
                    )

            return rules
        except Exception as e:
            logger.error(f"腾讯云轻量服务器: 获取防火墙规则失败: {e}")
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

            # 先清理旧的家庭IP规则
            port_strings = [str(port) for port in ports]
            old_removed = self.cleanup_all_old_home_rules(
                instance_id, protocol, port_strings, ip_version
            )

            # 清理旧规则后，重新获取规则列表进行存在性检查
            existing_rules = self.list_firewall_rules(instance_id)

            # 检查规则是否已存在（完全匹配：IP、协议、端口）
            for rule in existing_rules:
                rule_protocol = rule.get("protocol", "").lower()
                rule_ip = rule.get("ip_address", "")
                rule_ports = rule.get("ports", [])

                if rule_protocol == protocol.lower() and rule_ip == ip_address:
                    if self._ports_match(rule_ports, port_strings):
                        return True

            # 继续添加规则
            # 统一端口格式为字符串，便于API调用
            if len(ports) == 1:
                port_str = str(ports[0])
            elif len(ports) > 1:
                port_str = f"{min(ports)}-{max(ports)}"
            else:
                port_str = "ALL"

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

    def cleanup_all_old_home_rules(
        self, instance_id: str, protocol: str, ports: List[str], ip_version: str
    ) -> int:
        """清理所有旧家庭IP规则（IPv4和IPv6）"""
        removed_count = 0
        try:
            rules = self.list_firewall_rules(instance_id)

            # 统一清理描述：清理所有"Home Lighthouse full access"规则的IPv4和IPv6
            target_description = "Home Lighthouse full access"

            for rule in rules:
                rule_protocol = rule.get("protocol", "").lower()
                rule_ports = rule.get("ports", [])
                rule_ip = rule.get("ip_address", "")
                rule_desc = rule.get("description", "")
                rule_ip_version = rule.get("ip_version", "IPv4")

                # 清理条件：IP版本匹配 + 协议端口匹配 + 描述匹配 + 有IP地址
                ip_version_match = rule_ip_version == ip_version
                protocol_match = rule_protocol == protocol.lower()
                ports_match = self._ports_match(rule_ports, ports)
                desc_exact_match = rule_desc == "Home Lighthouse full access"
                has_ip = bool(rule_ip)

                if (
                    ip_version_match
                    and protocol_match
                    and desc_exact_match
                    and ports_match
                    and has_ip
                ):
                    try:
                        if self.remove_firewall_rule_by_attr(
                            instance_id, rule_protocol, rule_ports, rule_ip
                        ):
                            removed_count += 1
                    except Exception as e:
                        pass

            return removed_count
        except Exception as e:
            logger.error(f"腾讯云轻量服务器: 清理旧规则失败: {e}")
            return 0

    def remove_firewall_rule_by_attr(
        self, instance_id: str, protocol: str, ports: List[str], ip_address: str
    ) -> bool:
        """通过规则属性删除防火墙规则"""
        if not self.client:
            return False

        try:
            from tencentcloud.lighthouse.v20200324 import models as lh_models

            request = lh_models.DeleteFirewallRulesRequest()
            request.InstanceId = instance_id

            # 构建删除规则
            rule = lh_models.FirewallRule()
            rule.Protocol = protocol.upper()

            # 处理端口格式
            if ports and len(ports) > 0:
                port_str = ports[0]
            else:
                port_str = "ALL"
            rule.Port = port_str

            # 根据IP类型设置CIDR
            if is_ipv6(ip_address):
                rule.Ipv6CidrBlock = f"{ip_address}/128"
            else:
                rule.CidrBlock = f"{ip_address}/32"

            request.FirewallRules = [rule]
            self.client.DeleteFirewallRules(request)
            # 移除冗余日志
            return True
        except Exception as e:
            logger.error(f"腾讯云轻量服务器: 通过属性删除规则失败 - {e}")
            return False

    def _ports_match(self, rule_ports: List[str], target_ports: List[str]) -> bool:
        """
        检查端口是否匹配 - 参考阿里云的实现方式

        Args:
            rule_ports: 规则端口（列表格式，如['22']或['1-65535']）
            target_ports: 目标端口（列表格式，如['1-65535']或['22']）

        Returns:
            bool: 是否匹配
        """
        if not rule_ports or not target_ports:
            return False

        # 将规则端口转换为字符串格式进行比较
        rule_ports_str = []
        for port in rule_ports:
            if isinstance(port, int):
                rule_ports_str.append(str(port))
            else:
                rule_ports_str.append(str(port))

        # 检查是否有匹配
        for target_port in target_ports:
            if target_port in rule_ports_str:
                return True
            # 处理"1-65535"的匹配
            if "1-65535" in target_port or "65535" in target_port:
                if "65535" in rule_ports_str or "all" in [
                    p.lower() for p in rule_ports_str
                ]:
                    return True

        return False

    def rule_exists(
        self,
        instance_id: str,
        ip_address: str,
        protocol: str,
        ports: List[int],
    ) -> bool:
        """检查规则是否已存在"""
        from app.utils.validators import is_ipv6

        current_ip_version = "IPv6" if is_ipv6(ip_address) else "IPv4"

        rules = self.list_firewall_rules(instance_id)
        port_strings = [str(p) for p in ports]

        for rule in rules:
            rule_ip = rule.get("ip_address", "")
            rule_version = rule.get("ip_version", "")
            rule_protocol = rule.get("protocol", "")
            rule_ports = rule.get("ports", [])

            if (
                rule_protocol == protocol.lower()
                and rule_ip == ip_address
                and rule_version == current_ip_version
                and self._ports_match(rule_ports, port_strings)
            ):
                return True

        return False

    def cleanup_old_firewall_rules(
        self,
        instance_id: str,
        current_ip: str,
        protocol: str,
        ports: List[str],
        days: int = 7,
    ) -> int:
        """清理旧的防火墙规则"""
        removed_count = 0
        current_ip_version = "IPv6" if is_ipv6(current_ip) else "IPv4"

        rules = self.list_firewall_rules(instance_id)
        for rule in rules:
            # 参考阿里云的方式，使用详细的变量进行匹配检查
            rule_protocol = rule.get("protocol", "").lower()
            rule_ports = rule.get("ports", [])
            rule_ip = rule.get("ip_address", "")
            rule_desc = rule.get("description", "")
            rule_ip_version = rule.get("ip_version", "IPv4")

            protocol_match = rule_protocol == protocol.lower()
            ports_match = self._ports_match(rule_ports, ports)
            ip_different = rule_ip != current_ip
            desc_has_home = "home" in rule_desc.lower()  # 使用小写匹配
            ip_version_match = rule_ip_version == current_ip_version

            is_old = (
                protocol_match
                and ports_match
                and ip_different
                and desc_has_home
                and ip_version_match
            )

            if is_old and rule.get("rule_id"):
                if self.remove_firewall_rule(instance_id, rule["rule_id"]):
                    removed_count += 1
                    logger.info(
                        f"腾讯云轻量服务器: 删除旧{current_ip_version}规则: {rule['ip_address']}"
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
        # 将端口转换为字符串列表以匹配cleanup_old_firewall_rules的期望类型
        port_strings = [str(port) for port in ports]
        return self.cleanup_old_firewall_rules(
            instance_id, new_ip, protocol, port_strings, 7
        )

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
