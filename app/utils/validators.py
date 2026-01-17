import re
from typing import Tuple
from ipaddress import ip_address, IPv4Address, IPv6Address


def validate_ip(ip: str) -> Tuple[bool, str]:
    """
    验证IP地址格式

    Args:
        ip: IP地址字符串

    Returns:
        Tuple[bool, str]: (是否有效, IP类型 'IPv4'/'IPv6'/'Invalid')
    """
    try:
        addr = ip_address(ip)
        if isinstance(addr, IPv4Address):
            return True, "IPv4"
        elif isinstance(addr, IPv6Address):
            return True, "IPv6"
        else:
            return False, "Invalid"
    except ValueError:
        return False, "Invalid"


def is_ipv6(ip: str) -> bool:
    """
    判断是否为IPv6地址

    Args:
        ip: IP地址字符串

    Returns:
        bool: 是否为IPv6
    """
    try:
        addr = ip_address(ip)
        return isinstance(addr, IPv6Address)
    except ValueError:
        return False


def is_ipv4(ip: str) -> bool:
    """
    判断是否为IPv4地址

    Args:
        ip: IP地址字符串

    Returns:
        bool: 是否为IPv4
    """
    try:
        addr = ip_address(ip)
        return isinstance(addr, IPv4Address)
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """
    检查是否为私有IP地址

    Args:
        ip: IP地址字符串

    Returns:
        bool: 是否为私有IP
    """
    try:
        addr = ip_address(ip)
        return addr.is_private
    except ValueError:
        return False


def normalize_ip(ip: str, ip_type: str = "IPv4") -> str:
    """
    标准化IP地址格式

    Args:
        ip: IP地址字符串
        ip_type: IP类型

    Returns:
        str: 标准化后的IP地址
    """
    if ip_type == "IPv6":
        # IPv6地址压缩格式
        try:
            addr = ip_address(ip)
            return str(addr.compressed)
        except ValueError:
            return ip
    else:
        # IPv4地址
        try:
            addr = ip_address(ip)
            return str(addr)
        except ValueError:
            return ip


def get_cidr_for_ip(ip: str, ip_type: str = "IPv4") -> str:
    """
    根据IP类型获取CIDR前缀

    Args:
        ip: IP地址
        ip_type: IP类型

    Returns:
        str: CIDR格式的IP地址
    """
    normalized_ip = normalize_ip(ip, ip_type)

    if ip_type == "IPv6":
        return f"{normalized_ip}/128"
    else:
        return f"{normalized_ip}/32"


def is_valid_port(port: int) -> bool:
    """
    验证端口号是否有效

    Args:
        port: 端口号

    Returns:
        bool: 是否有效
    """
    return 1 <= port <= 65535


def parse_port_range(port_range: str) -> Tuple[int, int]:
    """
    解析端口范围

    Args:
        port_range: 端口范围字符串 (如 "22-80" 或 "22")

    Returns:
        Tuple[int, int]: (起始端口, 结束端口)
    """
    if "-" in port_range:
        start, end = port_range.split("-", 1)
        return int(start), int(end)
    else:
        port = int(port_range)
        return port, port


def validate_port_list(ports: list) -> bool:
    """
    验证端口列表

    Args:
        ports: 端口列表

    Returns:
        bool: 是否有效
    """
    if not ports:
        return False

    for port in ports:
        if isinstance(port, str):
            if "-" in port:
                start, end = parse_port_range(port)
                if not (is_valid_port(start) and is_valid_port(end) and start <= end):
                    return False
            else:
                try:
                    port_num = int(port)
                    if not is_valid_port(port_num):
                        return False
                except ValueError:
                    return False
        elif isinstance(port, int):
            if not is_valid_port(port):
                return False
        else:
            return False

    return True


def sanitize_description(description: str) -> str:
    """
    清理描述文本

    Args:
        description: 原始描述

    Returns:
        str: 清理后的描述
    """
    if not description:
        return ""

    # 移除特殊字符，但保留中文和基本符号
    cleaned = re.sub(r"[^\w\s\-.,;:()[\]{}【】（）\u4e00-\u9fff]", "", description)
    # 限制长度
    return cleaned[:255]


def extract_ip_from_cidr(cidr: str) -> str:
    """
    从CIDR中提取IP地址

    Args:
        cidr: CIDR格式的地址

    Returns:
        str: IP地址
    """
    if "/" in cidr:
        return cidr.split("/")[0]
    return cidr
