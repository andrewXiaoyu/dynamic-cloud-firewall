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
            httpProfile.endpoint = "cvm.tencentcloudapi.com"

            clientProfile = ClientProfile()
            clientProfile.httpProfile = httpProfile

            self.client = cvm_client.CvmClient(cred, region, clientProfile)
            return True
        except Exception as e:
            from app.utils.logger import logger

            logger.error(f"初始化腾讯云客户端失败: {e}")
            return False

    def list_security_group_rules(self, security_group_id: str) -> List[Dict[str, Any]]:
        """列出安全组规则"""
        try:
            from tencentcloud.cvm.v20170312 import models
            from app.utils.logger import logger

            req = models.DescribeSecurityGroupPoliciesRequest()
            params = {"SecurityGroupId": security_group_id}
            req.from_json_string(params)

            resp = self.client.DescribeSecurityGroupPolicies(req)
            rules = []

            if resp.SecurityGroupPolicySet:
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

            req = models.CreateSecurityGroupPoliciesRequest()

            # 构建规则
            policies = []
            for port in ports:
                policy = {
                    "SecurityGroupId": security_group_id,
                    "Protocol": protocol.upper(),
                    cidr_field: cidr_ip,
                    "PolicyDescription": description,
                    "Action": "ACCEPT",
                }

                if port == ["1-65535"] or port == "1-65535":
                    policy["Port"] = "ALL"
                else:
                    policy["Port"] = port

                policies.append(policy)

            params = {"SecurityGroupPolicySet": {"Ingress": policies}}
            req.from_json_string(params)

            resp = self.client.CreateSecurityGroupPolicies(req)
            logger.info(f"腾讯云安全组规则添加成功: {security_group_id}")
            return True

        except Exception as e:
            from app.utils.logger import logger

            logger.error(f"添加腾讯云安全组规则失败: {e}")
            return False

    def remove_security_group_rule(self, security_group_id: str, rule_id: str) -> bool:
        """删除安全组规则"""
        try:
            from tencentcloud.cvm.v20170312 import models
            from app.utils.logger import logger

            req = models.DeleteSecurityGroupPoliciesRequest()
            params = {"SecurityGroupPolicySet": {"Ingress": [{"PolicyIndex": rule_id}]}}
            req.from_json_string(params)

            resp = self.client.DeleteSecurityGroupPolicies(req)
            logger.info(f"腾讯云安全组规则删除成功: {rule_id}")
            return True

        except Exception as e:
            from app.utils.logger import logger

            logger.error(f"删除腾讯云安全组规则失败: {e}")
            return False
