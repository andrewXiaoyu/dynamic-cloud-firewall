from typing import List, Dict, Any
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

            if resp and resp.SecurityGroupPolicySet:
                for rule in resp.SecurityGroupPolicySet.Ingress:
                    rules.append(
                        {
                            "rule_id": rule.PolicyIndex,
                            "cidr": rule.CidrBlock or rule.Ipv6CidrBlock,
                            "protocol": rule.Protocol.lower() if rule.Protocol else "",
                            "ports": rule.Port or "all",
                            "description": rule.PolicyDescription or "",
                            "direction": "ingress",
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

            resp = self.client.DeleteSecurityGroupPolicies(req)
            logger.info(f"腾讯云安全组规则删除成功: {rule_id}")
            return True
        except Exception as e:
            from app.utils.logger import logger

            logger.error(f"添加腾讯云安全组规则失败: {e}")
            return False

    def remove_security_group_rule(self, security_group_id: str, rule_id: str) -> bool:
        """删除安全组规则"""
        try:
            from tencentcloud.vpc.v20170312 import models
            from app.utils.logger import logger

            from tencentcloud.vpc.v20170312 import models

            from tencentcloud.vpc.v20170312 import models as vpc_models

            req = vpc_models.DeleteSecurityGroupPoliciesRequest()
            policy_set = vpc_models.SecurityGroupPolicySet()
            policy = vpc_models.SecurityGroupPolicy()
            policy.PolicyIndex = rule_id
            policy_set.Ingress = [policy]
            req.SecurityGroupPolicySet = policy_set
            req.SecurityGroupId = security_group_id

            resp = self.client.DeleteSecurityGroupPolicies(req)
            logger.info(f"腾讯云安全组规则删除成功: {rule_id}")
            return True
        except Exception as e:
            from app.utils.logger import logger

            logger.error(f"删除腾讯云安全组规则失败: {e}")
            return False

    def _ports_match(self, rule_port: str, target_ports: List[str]) -> bool:
        """
        检查端口是否匹配

        Args:
            rule_port: 规则端口
            target_ports: 目标端口（字符串格式，如['1-65535']或['22']）

        Returns:
            bool: 是否匹配
        """
        if not rule_port or not target_ports:
            return False

        # 处理端口范围和单个端口的匹配逻辑
        for target_port in target_ports:
            if target_port in rule_port:
                return True
            # 处理端口范围，如"1-65535"包含"22"
            if "-" in target_port:
                parts = target_port.split("-")
                if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                    start, end = int(parts[0]), int(parts[1])
                    if "-" in rule_port:
                        rule_parts = rule_port.split("-")
                        if (
                            len(rule_parts) == 2
                            and rule_parts[0].isdigit()
                            and rule_parts[1].isdigit()
                        ):
                            rule_start, rule_end = (
                                int(rule_parts[0]),
                                int(rule_parts[1]),
                            )
                            if start >= rule_start and end <= rule_end:
                                return True

        return False

    def find_and_remove_old_ip_rules(
        self, security_group_id: str, protocol: str, ports: List[str], current_ip: str
    ) -> int:
        """查找并删除旧的IP规则（腾讯云专用）"""
        try:
            from tencentcloud.vpc.v20170312 import models as vpc_models
            from app.utils.validators import is_ipv6
            from app.utils.logger import logger

            current_ip_version = "IPv6" if is_ipv6(current_ip) else "IPv4"

            # 获取当前所有规则（通过list方法，确保返回字典格式）
            rules = self.list_security_group_rules(security_group_id)
            removed_count = 0

            for rule in rules:
                # 检查是否为旧规则（使用字典格式）
                is_old = (
                    rule.get("description")
                    and "Home" in rule.get("description", "")
                    and rule.get("protocol") == protocol.lower()
                    and (
                        (
                            current_ip_version == "IPv4"
                            and rule.get("cidr")
                            and rule.get("cidr") != current_ip
                        )
                        or (
                            current_ip_version == "IPv6"
                            and rule.get("cidr")
                            and rule.get("cidr") != current_ip
                        )
                    )
                )
            return removed_count
        except Exception as e:
            from app.utils.logger import logger

            logger.error(f"腾讯云清理旧规则失败: {e}")
            return 0
