from typing import List, Dict, Any
from app.providers.base import BaseProvider


class AliyunProvider(BaseProvider):
    """阿里云ECS安全组管理"""

    def initialize_client(self) -> bool:
        """初始化阿里云客户端"""
        try:
            from alibabacloud_ecs20140526.client import Client as EcsClient
            from alibabacloud_tea_openapi import models as open_api_models
            from app.utils.logger import logger

            access_key_id = self.config.get("access_key_id", "")
            access_key_secret = self.config.get("access_key_secret", "")
            region = self.config.get("region", "")

            logger.debug(f"开始初始化阿里云客户端，region={region}")
            logger.debug(f"access_key_id前8位: {access_key_id[:8]}***")
            logger.debug(f"access_key_secret前8位: {access_key_secret[:8]}***")

            if not access_key_id:
                logger.error("阿里云access_key_id未配置")
                return False
            if not access_key_secret:
                logger.error("阿里云access_key_secret未配置")
                return False
            if not region:
                logger.warning("阿里云region未配置，使用默认值: cn-shenzhen")
                region = "cn-shenzhen"

            config = open_api_models.Config(
                access_key_id=access_key_id,
                access_key_secret=access_key_secret,
                region_id=region,
            )

            self.client = EcsClient(config)
            # logger.info("阿里云客户端初始化成功")
            return True
        except Exception as e:
            from app.utils.logger import logger

            logger.error(f"阿里云客户端初始化失败: {e}", exc_info=True)
            return False

    def list_security_group_rules(self, security_group_id: str) -> List[Dict[str, Any]]:
        """列出安全组规则"""
        try:
            from alibabacloud_ecs20140526 import models as ecs_models
            from app.utils.logger import logger

            request = ecs_models.DescribeSecurityGroupAttributeRequest()
            request.security_group_id = security_group_id
            request.region_id = self.config.get("region", "cn-shenzhen")

            response = self.client.describe_security_group_attribute(request)
            rules = []

            if response:
                if hasattr(response, "body"):
                    body = response.body

                    if hasattr(body, "permissions"):
                        permissions = body.permissions

                        if hasattr(permissions, "to_map"):
                            perm_map = permissions.to_map()

                            # 尝试不同的key名字
                            permissions_list = (
                                perm_map.get("permission")
                                or perm_map.get("permissions")
                                or perm_map.get("Permission")
                                or perm_map.get("Permissions")
                                or []
                            )

            response = self.client.describe_security_group_attribute(request)
            rules = []

            logger.debug(f"响应类型: {type(response)}")

            if response:
                if hasattr(response, "body"):
                    body = response.body
                    logger.debug(f"响应body类型: {type(body)}")

                    if hasattr(body, "permissions"):
                        permissions = body.permissions
                        logger.debug(f"permissions对象类型: {type(permissions)}")

                        if hasattr(permissions, "to_map"):
                            perm_map = permissions.to_map()
                            # 尝试不同的key名字
                            permissions_list = (
                                perm_map.get("permission")
                                or perm_map.get("permissions")
                                or perm_map.get("Permission")
                                or perm_map.get("Permissions")
                                or []
                            )
                        else:
                            logger.warning(
                                f"permissions对象不支持to_map，可用方法: {dir(permissions)[:20]}"
                            )
                            permissions_list = []

                        if permissions_list and isinstance(permissions_list, list):
                            for perm_dict in permissions_list:
                                perm_type = perm_dict.get(
                                    "Direction", perm_dict.get("direction", "")
                                )

                                if perm_type and perm_type.lower() == "ingress":
                                    ipv6_source = perm_dict.get("Ipv6SourceCidrIp", "")
                                    ipv4_source = perm_dict.get("SourceCidrIp", "")

                                    if ipv6_source:
                                        ip_address = ipv6_source
                                        ip_version = "IPv6"
                                    else:
                                        ip_address = ipv4_source
                                        ip_version = "IPv4"

                                    port_range = perm_dict.get("PortRange", "")
                                    ports = []
                                    if port_range:
                                        if "/" in port_range:
                                            parts = port_range.split("/")
                                            if len(parts) == 2 and parts[0] == parts[1]:
                                                ports = [parts[0]]
                                            else:
                                                ports = [port_range.replace("/", "-")]
                                        else:
                                            ports = [port_range]

                                    rule = {
                                        "rule_id": perm_dict.get(
                                            "SecurityGroupRuleId", ""
                                        ),
                                        "cidr": ip_address,
                                        "protocol": perm_dict.get(
                                            "IpProtocol", "tcp"
                                        ).lower(),
                                        "ports": ports,
                                        "description": perm_dict.get("Description", ""),
                                        "direction": "ingress",
                                        "ip_version": ip_version,
                                    }
                                    rules.append(rule)

                    else:
                        logger.warning(f"响应body中没有permissions属性")

            return rules
        except Exception as e:
            from app.utils.logger import logger

            logger.error(f"获取阿里云安全组规则失败: {e}", exc_info=True)
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
            from alibabacloud_ecs20140526 import models as ecs_models
            from app.utils.validators import get_cidr_for_ip
            from app.utils.logger import logger

            # 判断IP类型
            if ":" in ip_address:
                cidr_ip = get_cidr_for_ip(ip_address, "IPv6")
                cidr_field = "source_cidr_ipv6_ip"
                ip_version = "IPv6"
            else:
                cidr_ip = get_cidr_for_ip(ip_address, "IPv4")
                cidr_field = "source_cidr_ip"
                ip_version = "IPv4"

            # 先获取当前规则以检查重复
            existing_rules = self.list_security_group_rules(security_group_id)

            # 检查是否有完全相同的规则
            is_duplicate = False
            for existing_rule in existing_rules:
                if (
                    existing_rule.get("cidr") == cidr_ip
                    and existing_rule.get("protocol", "").lower() == protocol.lower()
                    and self._ports_match(existing_rule.get("ports", []), ports)
                    and existing_rule.get("ip_version") == ip_version
                ):
                    is_duplicate = True
                    break

            if is_duplicate:
                return False

            # 创建权限对象
            permissions = []
            for port in ports:
                # 处理端口范围格式
                if port == "1-65535":
                    port_range = "1/65535"
                elif "-" in port:
                    port_range = port.replace("-", "/")
                elif port.isdigit():
                    port_range = f"{port}/{port}"
                else:
                    port_range = "1/65535"

                logger.debug(f"处理端口: {port} -> {port_range}")

                # 创建权限对象
                if ip_version == "IPv6":
                    permission_dict = {
                        "description": description,
                        "ip_protocol": protocol.upper(),
                        "ipv_6source_cidr_ip": cidr_ip,
                        "port_range": port_range,
                        "policy": "accept",
                        "priority": "1",
                    }
                    logger.debug(f"创建IPv6权限: {permission_dict}")
                    permission = ecs_models.AuthorizeSecurityGroupRequestPermissions(
                        description=description,
                        ip_protocol=protocol.upper(),
                        ipv_6source_cidr_ip=cidr_ip,
                        port_range=port_range,
                        policy="accept",
                        priority="1",
                    )
                else:
                    permission_dict = {
                        "description": description,
                        "ip_protocol": protocol.upper(),
                        "source_cidr_ip": cidr_ip,
                        "port_range": port_range,
                        "policy": "accept",
                        "priority": "1",
                    }
                    logger.debug(f"创建IPv4权限: {permission_dict}")
                    permission = ecs_models.AuthorizeSecurityGroupRequestPermissions(
                        description=description,
                        ip_protocol=protocol.upper(),
                        source_cidr_ip=cidr_ip,
                        port_range=port_range,
                        policy="accept",
                        priority="1",
                    )

                permissions.append(permission)

            logger.debug(f"创建{len(permissions)}个权限对象")

            # 创建授权请求
            request = ecs_models.AuthorizeSecurityGroupRequest()
            request.security_group_id = security_group_id
            request.permissions = permissions
            request.region_id = self.config.get("region", "cn-shenzhen")

            logger.debug(
                f"发送授权请求到阿里云: sg={security_group_id}, region={request.region_id}"
            )
            response = self.client.authorize_security_group(request)
            logger.info(
                f"阿里云安全组规则添加成功: {security_group_id}, IP: {ip_address}"
            )
            return True
        except Exception as e:
            from app.utils.logger import logger

            logger.error(f"阿里云安全组规则添加失败: {e}")
            return False

    def remove_security_group_rule(self, security_group_id: str, rule_id: str) -> bool:
        """删除安全组规则"""
        try:
            from alibabacloud_ecs20140526 import models as ecs_models
            from app.utils.logger import logger

            request = ecs_models.RevokeSecurityGroupRequest()
            request.security_group_id = security_group_id
            request.region_id = self.config.get("region", "cn-shenzhen")
            request.security_group_rule_id = [rule_id]

            response = self.client.revoke_security_group(request)
            return True
        except Exception as e:
            from app.utils.logger import logger

            logger.error(
                f"阿里云安全组规则删除失败: rule_id={rule_id}, 错误: {e}", exc_info=True
            )
            return False

    def _ports_match(self, rule_ports: List[str], target_ports: List[str]) -> bool:
        """
        检查端口是否匹配

        Args:
            rule_ports: 规则端口（可能是整数列表或字符串列表）
            target_ports: 目标端口（字符串格式，如['1-65535']或['22']）

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
                if "65535" in rule_ports_str:
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

            for idx, rule in enumerate(rules):
                # 检查是否为旧规则
                rule_protocol = rule.get("protocol", "").lower()
                rule_ports = rule.get("ports", [])
                rule_cidr = rule.get("cidr", "")
                rule_desc = rule.get("description", "")
                rule_ip_version = rule.get("ip_version", "IPv4")

                protocol_match = rule_protocol == protocol.lower()
                ports_match = self._ports_match(rule_ports, ports)
                ip_different = rule_cidr != current_ip
                desc_has_home = "home" in rule_desc.lower()
                ip_version_match = rule_ip_version == current_ip_version

                is_old = (
                    protocol_match
                    and ports_match
                    and ip_different
                    and desc_has_home
                    and ip_version_match
                )

                if is_old:
                    rule_id = rule.get("rule_id", "")
                    try:
                        if self.remove_security_group_rule(security_group_id, rule_id):
                            removed_count += 1
                            logger.info(
                                f"阿里云: 删除旧{current_ip_version}规则: {rule_id}, IP: {rule.get('cidr', '')}"
                            )
                    except Exception as e:
                        logger.error(f"阿里云删除规则{rule_id}失败: {e}")

            return removed_count
        except Exception as e:
            from app.utils.logger import logger

            logger.error(f"清理阿里云旧规则失败: {e}")
            return 0

    def cleanup_old_rules(
        self,
        security_group_id: str,
        current_ip: str,
        protocol: str,
        ports: List[str],
        days: int = 7,
    ) -> int:
        """清理旧的安全组规则"""
        try:
            from app.utils.validators import is_ipv6
            from app.utils.logger import logger

            current_ip_version = "IPv6" if is_ipv6(current_ip) else "IPv4"

            # 获取当前所有规则
            rules = self.list_security_group_rules(security_group_id)
            removed_count = 0

            for rule in rules:
                # 检查是否为旧规则
                is_old = (
                    rule.get("protocol", "").lower() == protocol.lower()
                    and self._ports_match(rule.get("ports", []), ports)
                    and rule.get("cidr", "") != current_ip
                    and "home" in rule.get("description", "").lower()
                    and rule.get("ip_version", "IPv4") == current_ip_version
                )

                if is_old:
                    rule_id = rule.get("rule_id", "")
                    try:
                        if self.remove_security_group_rule(security_group_id, rule_id):
                            removed_count += 1
                            logger.info(
                                f"阿里云: 删除旧{current_ip_version}规则: {rule_id}, IP: {rule.get('cidr', '')}"
                            )
                    except Exception as e:
                        logger.error(f"阿里云删除规则{rule_id}失败: {e}")

            logger.info(f"阿里云清理了{removed_count}个旧{current_ip_version}规则")
            return removed_count
        except Exception as e:
            from app.utils.logger import logger

            logger.error(f"阿里云清理旧规则失败: {e}")
            return 0

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
