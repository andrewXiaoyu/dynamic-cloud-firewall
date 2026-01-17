from typing import List, Dict, Any
from app.providers.base import BaseProvider
from app.utils.validators import is_ipv6
from app.utils.logger import logger


class AliyunProvider(BaseProvider):
    """阿里云ECS安全组管理"""

    def initialize_client(self) -> bool:
        """初始化阿里云客户端"""
        try:
            from alibabacloud_ecs20140526.client import Client as EcsClient
            from alibabacloud_tea_openapi import models as open_api_models
            from alibabacloud_tea_util import models as util_models

            access_key_id = self.config.get("access_key_id")
            access_key_secret = self.config.get("access_key_secret")
            region = self.config.get("region")

            if not all([access_key_id, access_key_secret, region]):
                logger.error("阿里云配置不完整")
                return False

            config = open_api_models.Config(
                access_key_id=access_key_id, access_key_secret=access_key_secret
            )
            config.endpoint = self._get_endpoint(region)
            self.client = EcsClient(config)
            self.region = region
            return True
        except Exception as e:
            logger.error(f"初始化阿里云客户端失败: {e}")
            return False

    def _get_endpoint(self, region: str) -> str:
        region_map = {
            "cn-hangzhou": "ecs.cn-hangzhou.aliyuncs.com",
            "cn-shenzhen": "ecs.cn-shenzhen.aliyuncs.com",
            "cn-beijing": "ecs.cn-beijing.aliyuncs.com",
            "cn-shanghai": "ecs.cn-shanghai.aliyuncs.com",
        }
        return region_map.get(region, f"ecs.{region}.aliyuncs.com")

    def list_security_group_rules(self, security_group_id: str) -> List[Dict[str, Any]]:
        """列出安全组规则"""
        try:
            from alibabacloud_ecs20140526 import models as ecs_models

            request = ecs_models.DescribeSecurityGroupAttributeRequest(
                security_group_id=security_group_id, region_id=self.region
            )
            response = self.client.describe_security_group_attribute(request)

            rules = []
            # 先尝试从不同路径获取数据
            if hasattr(response, "body") and response.body:
                permissions = getattr(response.body, "permissions", [])
            elif (
                hasattr(response, "security_group_attribute")
                and response.security_group_attribute
            ):
                permissions = getattr(
                    response.security_group_attribute, "permissions", []
                )
            else:
                permissions = []

            # 处理permissions，可能是对象或列表
            perm_list = []
            try:
                perm_list = list(permissions) if permissions else []
            except (TypeError, AttributeError):
                # 如果permissions不是可迭代的，尝试其他方式
                if hasattr(permissions, "permissions"):
                    perm_list = permissions.permissions or []
                else:
                    perm_list = []

            for perm in perm_list:
                if perm.direction == "ingress":
                    # 解析IP地址
                    ip_address = ""
                    ip_version = "IPv4"
                    if perm.source_cidr_ip:
                        ip_address = perm.source_cidr_ip.replace("/32", "").replace(
                            "/128", ""
                        )
                        if is_ipv6(ip_address):
                            ip_version = "IPv6"
                    elif perm.ipv_6_source_cidr_ip:
                        ip_address = perm.ipv_6_source_cidr_ip.replace("/128", "")
                        ip_version = "IPv6"

                    # 解析端口
                    ports = []
                    if perm.port_range:
                        if perm.port_range == "-1/-1":
                            ports = []
                        elif "/" in perm.port_range:
                            parts = perm.port_range.split("/")
                            if len(parts) == 2:
                                start, end = parts
                                if start.isdigit() and end.isdigit():
                                    start_int, end_int = int(start), int(end)
                                    if start_int == end_int:
                                        ports = [start_int]
                                    else:
                                        ports = [start_int, end_int]

                    rules.append(
                        {
                            "rule_id": getattr(perm, "security_group_rule_id", None),
                            "protocol": (perm.ip_protocol or "").lower(),
                            "ports": ports,
                            "ip_address": ip_address,
                            "description": perm.description or "",
                            "ip_version": ip_version,
                        }
                    )

            return rules
        except Exception as e:
            logger.error(f"获取阿里云安全组规则失败: {e}")
            return []

    def add_security_group_rule(
        self,
        ip_address: str,
        security_group_id: str,
        protocol: str,
        ports: List[int],
        description: str,
    ) -> bool:
        if not self.client:
            return False

        try:
            from alibabacloud_ecs20140526 import models as ecs_models

            # 判断IP版本
            ip_version = "IPv6" if is_ipv6(ip_address) else "IPv4"
            cidr_suffix = "/128" if ip_version == "IPv6" else "/32"
            source_cidr = f"{ip_address}{cidr_suffix}"

            # 检查规则是否已存在
            existing_rules = self.list_security_group_rules(security_group_id)
            for port in ports:
                # 修复端口范围格式 - 阿里云需要两个整数，如 "1/65535"
                if port and isinstance(port, int):
                    port_range = f"{port}/{port}"
                elif isinstance(port, str) and "-" in port:
                    port_range = port.replace("-", "/")
                elif port and len(ports) == 1:
                    port_range = f"{port}/{port}"
                else:
                    port_range = "-1/-1"  # 全端口

                # 检查规则是否已存在
                rule_ports = [port] if port else []
                for rule in existing_rules:
                    if (
                        rule["protocol"] == protocol.lower()
                        and rule["ip_address"] == ip_address
                        and set(rule["ports"]) == set(rule_ports)
                    ):
                        logger.info(
                            f"阿里云安全组规则已存在: {security_group_id}, IP: {ip_address}, Port: {port_range}"
                        )
                        continue

                # 添加规则
                permission = ecs_models.AuthorizeSecurityGroupRequestPermissions(
                    ip_protocol=protocol.upper(),
                    port_range=port_range,
                    description=description,
                    policy="accept",
                    **{
                        f"{'ipv_6source_cidr_ip' if ip_version == 'IPv6' else 'source_cidr_ip'}": source_cidr
                    },
                )

                request = ecs_models.AuthorizeSecurityGroupRequest(
                    region_id=self.region,
                    security_group_id=security_group_id,
                    permissions=[permission],
                )

                self.client.authorize_security_group(request)
                logger.info(
                    f"阿里云安全组规则添加成功: {security_group_id}, IP: {ip_address}, Port: {port_range}"
                )

            return True
        except Exception as e:
            logger.error(f"阿里云添加安全组规则失败: {e}")
            return False

    def remove_security_group_rule(self, security_group_id: str, rule_id: str) -> bool:
        if not self.client:
            return False

        try:
            from alibabacloud_ecs20140526 import models as ecs_models

            # 如果是真实规则ID，使用规则ID删除
            if rule_id and str(rule_id).startswith("sgr-"):
                request = ecs_models.RevokeSecurityGroupRequest(
                    security_group_id=security_group_id,
                    security_group_rule_id=[rule_id],
                )
            else:
                # 兼容旧格式
                logger.error(f"阿里云删除规则需要真实的规则ID: {rule_id}")
                return False

            self.client.revoke_security_group(request)
            logger.info(
                f"阿里云安全组规则删除成功: {security_group_id}, Rule: {rule_id}"
            )
            return True
        except Exception as e:
            logger.error(f"阿里云删除安全组规则失败: {e}")
            return False

    def cleanup_old_rules(
        self,
        security_group_id: str,
        current_ip: str,
        protocol: str,
        ports: List[int],
        days: int = 7,
    ) -> int:
        """清理旧的安全组规则"""
        removed_count = 0
        current_ip_version = "IPv6" if is_ipv6(current_ip) else "IPv4"

        rules = self.list_security_group_rules(security_group_id)
        for rule in rules:
            if (
                rule["protocol"] == protocol.lower()
                and set(rule["ports"]) == set(ports)
                and rule["ip_address"] != current_ip
                and "Home" in rule["description"]
                and rule["ip_version"] == current_ip_version
                and rule["rule_id"]
            ):
                if self.remove_security_group_rule(security_group_id, rule["rule_id"]):
                    removed_count += 1
                    logger.info(f"已清理阿里云旧规则: {rule['ip_address']}")

        return removed_count

    def find_and_remove_old_ip_rules(
        self,
        security_group_id: str,
        protocol: str,
        ports: List[int],
        new_ip: str,
    ) -> int:
        """查找并删除旧的IP规则"""
        return self.cleanup_old_rules(security_group_id, new_ip, protocol, ports, 7)
