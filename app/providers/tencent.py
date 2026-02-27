from typing import List, Dict, Any, Union
from app.providers.base import BaseProvider


class TencentProvider(BaseProvider):
    """腾讯云ECS安全组管理"""

    def initialize_client(self) -> bool:
        """初始化腾讯云客户端"""
        try:
            from tencentcloud.common import credential
            from tencentcloud.common.profile.client_profile import ClientProfile
            from tencentcloud.common.profile.http_profile import HttpProfile
            from tencentcloud.cvm.v20170312 import cvm_client

            secret_id = self.config.get("secret_id")
            secret_key = self.config.get("secret_key")
            region = self.config.get("region")

            if not all([secret_id, secret_key, region]):
                from app.utils.logger import logger

                logger.error("腾讯云配置不完整")
                return False

            cred = credential.Credential(secret_id, secret_key)
            httpProfile = HttpProfile()
            httpProfile.endpoint = "vpc.tencentcloudapi.com"

            clientProfile = ClientProfile()
            clientProfile.httpProfile = httpProfile

            from tencentcloud.vpc.v20170312 import vpc_client

            self.client = vpc_client.VpcClient(cred, region, clientProfile)
            return True
        except Exception as e:
            from app.utils.logger import logger

            logger.error(f"初始化腾讯云客户端失败: {e}", exc_info=True)
            return False

    def list_security_group_rules(self, security_group_id: str) -> List[Dict[str, Any]]:
        """列出安全组规则"""
        try:
            from tencentcloud.vpc.v20170312 import models
            from app.utils.logger import logger

            req = models.DescribeSecurityGroupPoliciesRequest()
            req.SecurityGroupId = security_group_id

            resp = self.client.DescribeSecurityGroupPolicies(req)
            rules = []

            if (
                resp
                and hasattr(resp, "SecurityGroupPolicySet")
                and resp.SecurityGroupPolicySet
            ):
                for rule in resp.SecurityGroupPolicySet.Ingress:
                    ipv6_cidr = rule.Ipv6CidrBlock or ""
                    ipv4_cidr = rule.CidrBlock or ""

                    ip_version = "IPv6" if ipv6_cidr else "IPv4"
                    ip_address = ipv6_cidr or ipv4_cidr

                    # 参考阿里云的方式，将端口统一转换为列表格式
                    port_value = rule.Port or "all"
                    ports = []
                    if port_value and port_value != "all":
                        # 腾讯云可能返回字符串格式的端口
                        if isinstance(port_value, str):
                            ports = [port_value]
                        else:
                            ports = port_value
                    else:
                        ports = ["all"]

                    rules.append(
                        {
                            "rule_id": rule.PolicyIndex,
                            "cidr": ip_address,
                            "protocol": rule.Protocol.lower() if rule.Protocol else "",
                            "ports": ports,
                            "description": rule.PolicyDescription or "",
                            "direction": "ingress",
                            "ip_version": ip_version,
                        }
                    )

            return rules
        except Exception as e:
            from app.utils.logger import logger

            logger.error(f"获取腾讯云安全组规则失败: {e}")
            return []

    def add_security_group_rule(
        self,
        ip_address: str,
        security_group_id: str,
        protocol: str,
        ports: List[str],
        description: str = "",
    ) -> bool:
        """添加安全组规则"""
        try:
            from tencentcloud.cvm.v20170312 import models
            from app.utils.validators import get_cidr_for_ip
            from app.utils.logger import logger

            # 判断IP类型
            if ":" in ip_address:
                cidr_ip = get_cidr_for_ip(ip_address, "IPv6")
                cidr_field = "Ipv6CidrBlock"
            else:
                cidr_ip = get_cidr_for_ip(ip_address, "IPv4")
                cidr_field = "CidrBlock"

            from tencentcloud.vpc.v20170312 import models as vpc_models

            req = vpc_models.CreateSecurityGroupPoliciesRequest()

            # 构建规则
            policy_set = vpc_models.SecurityGroupPolicySet()
            policies = []
            for port in ports:
                policy = vpc_models.SecurityGroupPolicy()
                policy.Protocol = protocol.upper()
                policy.PolicyDescription = description
                policy.Action = "ACCEPT"

                if cidr_field == "Ipv6CidrBlock":
                    policy.Ipv6CidrBlock = cidr_ip
                else:
                    policy.CidrBlock = cidr_ip

                if port == ["1-65535"] or port == "1-65535":
                    policy.Port = "ALL"
                else:
                    policy.Port = str(port)

                policies.append(policy)

            policy_set.Ingress = policies
            req.SecurityGroupPolicySet = policy_set
            req.SecurityGroupId = security_group_id

            resp = self.client.CreateSecurityGroupPolicies(req)
            logger.info(f"腾讯云安全组规则添加成功: {ip_address}, 响应: {resp}")
            return True
        except Exception as e:
            from app.utils.logger import logger

            logger.error(f"添加腾讯云安全组规则失败: {e}")
            import traceback

            logger.error(f"详细错误信息: {traceback.format_exc()}")
            return False

    def remove_security_group_rule(self, security_group_id: str, rule_id: str) -> bool:
        """删除安全组规则"""
        try:
            from tencentcloud.vpc.v20170312 import models as vpc_models
            from app.utils.logger import logger

            req = vpc_models.DeleteSecurityGroupPoliciesRequest()
            policy_set = vpc_models.SecurityGroupPolicySet()
            policy = vpc_models.SecurityGroupPolicy()
            policy.PolicyIndex = rule_id
            policy_set.Ingress = [policy]
            req.SecurityGroupPolicySet = policy_set
            req.SecurityGroupId = security_group_id

            resp = self.client.DeleteSecurityGroupPolicies(req)
            return True
        except Exception as e:
            from app.utils.logger import logger

            # 捕获PolicyIndex范围错误，静默跳过
            if "Range" in str(e) and "PolicyIndex" in str(e):
                return False
            logger.error(f"腾讯云: 删除规则{rule_id}失败: {e}")
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
        security_group_id: str,
        ip_address: str,
        protocol: str,
        ports: List[str],
    ) -> bool:
        """检查规则是否已存在"""
        from app.utils.validators import is_ipv6, get_cidr_for_ip

        current_ip_version = "IPv6" if is_ipv6(ip_address) else "IPv4"
        # 添加CIDR后缀进行比较
        ip_with_cidr = get_cidr_for_ip(ip_address, current_ip_version)

        rules = self.list_security_group_rules(security_group_id)

        for rule in rules:
            if (
                rule.get("protocol") == protocol.lower()
                and rule.get("cidr", "") == ip_with_cidr
                and rule.get("ip_version") == current_ip_version
                and self._ports_match(rule.get("ports", []), ports)
            ):
                return True

        return False

    def find_and_remove_old_ip_rules(
        self, security_group_id: str, protocol: str, ports: List[str], current_ip: str
    ) -> int:
        """查找并删除旧的IP规则"""
        try:
            from app.utils.validators import is_ipv6
            from app.utils.logger import logger

            current_ip_version = "IPv6" if is_ipv6(current_ip) else "IPv4"

            # 获取当前所有规则
            rules = self.list_security_group_rules(security_group_id)
            removed_count = 0

            if not rules:
                return 0

            # 根据IP版本确定需要清理的描述
            if current_ip_version == "IPv6":
                target_description = "Home IP full access"
            else:
                target_description = "Home IP full access"

            for rule in rules:
                # 参考阿里云的方式，使用详细的变量进行匹配检查
                rule_protocol = rule.get("protocol", "").lower()
                rule_ports = rule.get("ports", [])
                rule_cidr = rule.get("cidr", "")
                rule_desc = rule.get("description", "")
                rule_ip_version = rule.get("ip_version", "IPv4")

                # 只清理：1) IP版本匹配 2) 协议端口匹配 3) 描述完全匹配 4) IP地址不同
                protocol_match = rule_protocol == protocol.lower()
                ports_match = self._ports_match(rule_ports, ports)
                desc_exact_match = rule_desc == target_description
                ip_different = rule_cidr != current_ip
                ip_version_match = rule_ip_version == current_ip_version

                is_old = (
                    protocol_match
                    and ports_match
                    and ip_different
                    and desc_exact_match  # 精确匹配描述
                    and ip_version_match  # 必须匹配IP版本
                )

                if is_old:
                    rule_id = rule.get("rule_id", "")
                    try:
                        if self.remove_security_group_rule(security_group_id, rule_id):
                            removed_count += 1
                            logger.info(
                                f"腾讯云: 删除旧{current_ip_version}规则: {rule_id}, IP: {rule.get('cidr', '')}"
                            )
                    except Exception as e:
                        if "Range" not in str(e) or "PolicyIndex" not in str(e):
                            logger.error(f"腾讯云: 删除规则{rule_id}失败: {e}")

            if removed_count > 0:
                logger.info(
                    f"腾讯云: 已清理{removed_count}个旧{current_ip_version}规则"
                )

            return removed_count
        except Exception as e:
            logger.error(f"清理腾讯云旧规则失败: {e}")
            return 0
