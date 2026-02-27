from flask import Flask, request, jsonify
import hmac
import hashlib
from typing import Dict, Any, Tuple
import logging

from app.config import config_manager
from app.providers.factory import get_provider, get_provider_info
from app.utils.validators import validate_ip, is_private_ip
from app.utils.logger import logger


def init_webhook_app() -> Flask:
    app = Flask(__name__)

    webhook_config = config_manager.get_webhook_config()
    rules_config = config_manager.get_rules_config()
    enabled_providers = config_manager.get_enabled_providers()

    app.config["SECRET_KEY"] = webhook_config.get("secret_key", "")
    app.config["WEBHOOK_SECRET"] = webhook_config.get("secret_key", "")
    app.config["RULES"] = rules_config

    @app.route("/health", methods=["GET"])
    def health_check():
        provider_info = get_provider_info()
        return jsonify(
            {
                "status": "healthy",
                "enabled_providers": list(enabled_providers.keys()),
                "rules_config": rules_config,
                "cached_providers": provider_info,
            }
        )

    # 注册缓存管理API
    from app.api.cache_management import register_cache_api

    register_cache_api(app)

    @app.route("/webhook/ip-change", methods=["POST"])
    def handle_ip_change():
        try:
            data = request.get_json()

            if not data:
                logger.warning("收到空的webhook请求")
                return jsonify({"success": False, "message": "Empty request body"}), 400

            ip = data.get("ip")
            ipv4 = data.get("ipv4") or data.get("ip")  # 兼容 ip 字段
            ipv6 = data.get("ipv6")
            domain = data.get("domain", "")
            ip_type = data.get("ip_type", "IPV4")

            if not ipv4 and not ipv6:
                logger.warning("webhook请求中缺少IP地址")
                return jsonify({"success": False, "message": "Missing IP address"}), 400

            # 验证 IPv4
            if ipv4:
                is_valid, detected_type = validate_ip(ipv4)
                if not is_valid:
                    logger.error(f"无效的IPv4地址: {ipv4}")
                    return jsonify(
                        {"success": False, "message": "Invalid IPv4 address"}
                    ), 400
                if is_private_ip(ipv4):
                    logger.warning(f"检测到私有IPv4地址: {ipv4}")

            # 验证 IPv6
            if ipv6:
                is_valid, detected_type = validate_ip(ipv6)
                if not is_valid:
                    logger.error(f"无效的IPv6地址: {ipv6}")
                    return jsonify(
                        {"success": False, "message": "Invalid IPv6 address"}
                    ), 400

            # 构建要处理的IP列表
            ips_to_process = []
            if ipv4:
                ips_to_process.append({"ip": ipv4, "type": "IPv4"})
            if ipv6:
                ips_to_process.append({"ip": ipv6, "type": "IPv6"})

            logger.info(
                f"收到IP变更通知: 域名={domain}, IPv4={ipv4 or 'N/A'}, IPv6={ipv6 or 'N/A'}"
            )

            secret = request.headers.get("X-Webhook-Secret")
            if app.config["WEBHOOK_SECRET"] and secret != app.config["WEBHOOK_SECRET"]:
                logger.warning("Webhook密钥验证失败")
                return jsonify({"success": False, "message": "Invalid secret"}), 401

            results = []

            # 预加载所有provider实例，避免在IP处理循环中重复初始化
            loaded_providers = {}
            for provider_name, provider_config in enabled_providers.items():
                try:
                    provider = get_provider(provider_name, provider_config)
                    if provider:
                        loaded_providers[provider_name] = provider
                        logger.debug(f"预加载provider成功: {provider_name}")
                    else:
                        logger.error(f"预加载provider失败: {provider_name}")
                        results.append(
                            {
                                "provider": provider_name,
                                "status": "failed",
                                "message": "Provider初始化失败",
                                "ip_type": "N/A",
                                "ip_address": "N/A",
                                "targets": [],
                            }
                        )
                except Exception as e:
                    logger.error(f"预加载provider异常: {provider_name}, 错误: {e}")
                    results.append(
                        {
                            "provider": provider_name,
                            "status": "failed",
                            "message": f"Provider初始化异常: {str(e)}",
                            "ip_type": "N/A",
                            "ip_address": "N/A",
                            "targets": [],
                        }
                    )

            # 处理每个IP地址
            for ip_info in ips_to_process:
                logger.info(f"处理 {ip_info['type']} 地址: {ip_info['ip']}")
                ip_results = update_security_groups_cached(
                    ip_info["ip"], loaded_providers, rules_config, ip_info["type"]
                )
                results.extend(ip_results)

            total_updated = len([r for r in results if r["status"] == "success"])
            total_failed = len([r for r in results if r["status"] == "failed"])

            response = {
                "success": total_failed == 0,
                "message": f"处理完成: {total_updated}个成功, {total_failed}个失败",
                "ip_address": ip,
                "updated_providers": results,
                "summary": {
                    "total": len(results),
                    "success": total_updated,
                    "failed": total_failed,
                },
                "optimization": {
                    "cached_providers_used": len(loaded_providers),
                    "total_enabled_providers": len(enabled_providers),
                },
            }

            logger.info(
                f"IP变更处理完成: IP={ip}, 成功={total_updated}, 失败={total_failed}, 缓存命中={len(loaded_providers)}"
            )
            return jsonify(response), 200

        except Exception as e:
            logger.error(f"处理webhook请求时发生错误: {e}", exc_info=True)
            return jsonify({"success": False, "message": str(e)}), 500

    @app.route("/api/providers", methods=["GET"])
    def list_providers():
        provider_info = get_provider_info()
        return jsonify(provider_info)

    @app.route("/api/cache/clear", methods=["POST"])
    def clear_cache():
        try:
            data = request.get_json() or {}
            provider_name = data.get("provider_name")

            from app.providers.factory import clear_provider_cache

            clear_provider_cache(provider_name)

            message = f"已清理缓存: {provider_name or '全部'}"
            logger.info(message)
            return jsonify({"success": True, "message": message})
        except Exception as e:
            logger.error(f"清理缓存失败: {e}")
            return jsonify({"success": False, "message": str(e)}), 500

    return app


def update_security_groups_cached(
    ip_address: str,
    loaded_providers: Dict[str, Any],
    rules_config: Dict[str, Any],
    ip_type: str = "IPv4",
) -> list:
    """
    使用缓存的provider实例更新安全组规则

    Args:
        ip_address: IP地址
        loaded_providers: 已加载的provider字典
        rules_config: 规则配置
        ip_type: IP类型 (IPv4/IPv6)

    Returns:
        list: 处理结果列表
    """
    results = []

    for provider_name, provider in loaded_providers.items():
        provider_result = {
            "provider": provider_name,
            "status": "failed",
            "message": "",
            "ip_type": ip_type,
            "ip_address": ip_address,
            "targets": [],
            "optimization": "cached",
        }

        try:
            is_lighthouse = (
                "lighthouse" in provider_name or "lightsail" in provider_name
            )

            targets = []

            if is_lighthouse:
                # 对于lighthouse provider，需要从配置中获取实例信息
                from app.config import config_manager

                enabled_providers = config_manager.get_enabled_providers()
                provider_config = enabled_providers.get(provider_name, {})
                targets = provider_config.get("instances", [])
                target_key = "instance_id"
                target_label = "实例ID"
            else:
                # 对于普通provider，需要从配置中获取安全组信息
                from app.config import config_manager

                enabled_providers = config_manager.get_enabled_providers()
                provider_config = enabled_providers.get(provider_name, {})
                targets = provider_config.get("security_groups", [])
                target_key = "security_group_id"
                target_label = "安全组ID"

            for target_config in targets:
                target_result = {
                    target_key: target_config.get("id", ""),
                    "status": "failed",
                    "message": "",
                    "ip_type": ip_type,
                }

                target_id = target_config.get("id", "")
                protocol = target_config.get("protocol", "tcp")
                ports = target_config.get("ports", [22])

                # 检查该目标的 ip_version 配置
                target_ip_version = target_config.get("ip_version", "auto")

                # 判断是否应该处理这个目标
                should_process = False
                if target_ip_version == "auto":
                    should_process = True
                elif target_ip_version == "dual":
                    should_process = True
                elif target_ip_version.lower() == ip_type.lower():
                    should_process = True

                if not should_process:
                    target_result["message"] = (
                        f"跳过：目标配置的IP版本为{target_ip_version}，不匹配当前{ip_type}"
                    )
                    provider_result["targets"].append(target_result)
                    continue

                # 根据IP类型添加后缀和前缀
                if ip_type == "IPv6":
                    description = target_config.get(
                        "description", f"Home IPv6 access - {ip_address}"
                    )
                    cidr_suffix = "/128"
                else:
                    description = target_config.get(
                        "description", f"Home IPv4 access - {ip_address}"
                    )
                    cidr_suffix = "/32"

                if not target_id:
                    target_result["message"] = f"{target_label}为空"
                    provider_result["targets"].append(target_result)
                    continue

                try:
                    # 先检查规则是否已存在（只对有 rule_exists 方法的provider）
                    rule_already_exists = False
                    if hasattr(provider, "rule_exists"):
                        try:
                            rule_already_exists = provider.rule_exists(
                                target_id, ip_address, protocol, ports
                            )
                        except Exception:
                            # 如果 rule_exists 方法调用失败，继续执行正常流程
                            pass

                    if rule_already_exists:
                        # 规则已存在，跳过清理和添加
                        target_result["status"] = "success"
                        target_result["message"] = f"{ip_type}规则已存在"
                        logger.info(
                            f"{provider_name}: {target_label} {target_id} 的{ip_type}规则已存在，跳过更新"
                        )
                    else:
                        # 规则不存在，先清理旧规则再添加新规则
                        if rules_config.get("auto_cleanup_old_ip", True):
                            removed = provider.find_and_remove_old_ip_rules(
                                target_id, protocol, ports, ip_address
                            )
                            if removed > 0:
                                logger.info(
                                    f"{provider_name}: 已清理{removed}个旧{ip_type}规则"
                                )

                        success = provider.add_security_group_rule(
                            ip_address, target_id, protocol, ports, description
                        )

                        if success:
                            target_result["status"] = "success"
                            target_result["message"] = (
                                f"已添加{ip_type}地址 {ip_address}"
                            )
                            logger.info(
                                f"{provider_name}: 成功更新{target_label} {target_id} ({ip_type}) - 使用缓存客户端"
                            )
                        else:
                            target_result["message"] = f"添加{ip_type}规则失败"

                except Exception as e:
                    target_result["message"] = str(e)
                    logger.error(
                        f"{provider_name}: 更新{target_label} {target_id} 失败: {e}"
                    )

                provider_result["targets"].append(target_result)

            provider_success_count = len(
                [t for t in provider_result["targets"] if t["status"] == "success"]
            )
            if provider_success_count > 0:
                provider_result["status"] = "success"
                provider_result["message"] = (
                    f"成功更新{provider_success_count}/{len(targets)}个{'实例' if is_lighthouse else '安全组'} ({ip_type})"
                )

        except Exception as e:
            provider_result["message"] = str(e)
            logger.error(f"{provider_name}: 处理失败: {e}")

        results.append(provider_result)

    return results


# 保留原有的函数以确保向后兼容
def update_security_groups(
    ip_address: str,
    enabled_providers: Dict[str, Any],
    rules_config: Dict[str, Any],
    ip_type: str = "IPv4",
) -> list:
    """
    原有的安全组更新函数（向后兼容）

    注意：此函数会创建新的provider实例，建议使用update_security_groups_cached
    """
    from app.utils.logger import logger

    logger.warning(
        "使用已废弃的update_security_groups函数，建议使用update_security_groups_cached"
    )

    results = []

    for provider_name, provider_config in enabled_providers.items():
        provider_result = {
            "provider": provider_name,
            "status": "failed",
            "message": "",
            "ip_type": ip_type,
            "ip_address": ip_address,
            "targets": [],
            "optimization": "new_instance",
        }

        try:
            # 使用原有的create_provider方式（不使用缓存）
            from app.providers.factory import create_provider

            provider = create_provider(provider_name, provider_config)

            is_lighthouse = (
                "lighthouse" in provider_name or "lightsail" in provider_name
            )

            targets = []

            if is_lighthouse:
                targets = provider_config.get("instances", [])
                target_key = "instance_id"
                target_label = "实例ID"
            else:
                targets = provider_config.get("security_groups", [])
                target_key = "security_group_id"
                target_label = "安全组ID"

            for target_config in targets:
                target_result = {
                    target_key: target_config.get("id", ""),
                    "status": "failed",
                    "message": "",
                    "ip_type": ip_type,
                }

                target_id = target_config.get("id", "")
                protocol = target_config.get("protocol", "tcp")
                ports = target_config.get("ports", [22])

                # 检查该目标的 ip_version 配置
                target_ip_version = target_config.get("ip_version", "auto")

                # 判断是否应该处理这个目标
                should_process = False
                if target_ip_version == "auto":
                    should_process = True
                elif target_ip_version == "dual":
                    should_process = True
                elif target_ip_version.lower() == ip_type.lower():
                    should_process = True

                if not should_process:
                    target_result["message"] = (
                        f"跳过：目标配置的IP版本为{target_ip_version}，不匹配当前{ip_type}"
                    )
                    provider_result["targets"].append(target_result)
                    continue

                # 根据IP类型添加后缀和前缀
                if ip_type == "IPv6":
                    description = target_config.get(
                        "description", f"Home IPv6 access - {ip_address}"
                    )
                    cidr_suffix = "/128"
                else:
                    description = target_config.get(
                        "description", f"Home IPv4 access - {ip_address}"
                    )
                    cidr_suffix = "/32"

                if not target_id:
                    target_result["message"] = f"{target_label}为空"
                    provider_result["targets"].append(target_result)
                    continue

                try:
                    if rules_config.get("auto_cleanup_old_ip", True):
                        removed = provider.find_and_remove_old_ip_rules(
                            target_id, protocol, ports, ip_address
                        )
                        if removed > 0:
                            logger.info(
                                f"{provider_name}: 已清理{removed}个旧{ip_type}规则"
                            )

                    success = provider.add_security_group_rule(
                        ip_address, target_id, protocol, ports, description
                    )

                    if success:
                        target_result["status"] = "success"
                        target_result["message"] = f"已添加{ip_type}地址 {ip_address}"
                        logger.info(
                            f"{provider_name}: 成功更新{target_label} {target_id} ({ip_type}) - 创建新实例"
                        )
                    else:
                        target_result["message"] = f"添加{ip_type}规则失败"

                except Exception as e:
                    target_result["message"] = str(e)
                    logger.error(
                        f"{provider_name}: 更新{target_label} {target_id} 失败: {e}"
                    )

                provider_result["targets"].append(target_result)

            provider_success_count = len(
                [t for t in provider_result["targets"] if t["status"] == "success"]
            )
            if provider_success_count > 0:
                provider_result["status"] = "success"
                provider_result["message"] = (
                    f"成功更新{provider_success_count}/{len(targets)}个{'实例' if is_lighthouse else '安全组'} ({ip_type})"
                )

        except Exception as e:
            provider_result["message"] = str(e)
            logger.error(f"{provider_name}: 初始化或处理失败: {e}")

        results.append(provider_result)

    return results
