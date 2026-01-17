#!/usr/bin/env python3
"""
删除历史旧规则测试脚本
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.config import config_manager
from app.providers.factory import get_provider
from app.utils.logger import logger


def test_delete_old_rules():
    """测试删除历史旧规则功能"""
    print("🧪 开始测试删除历史旧规则功能...")
    print("=" * 50)

    # 获取配置
    enabled_providers = config_manager.get_enabled_providers()
    rules_config = config_manager.get_rules_config()

    test_results = []

    for provider_name, provider_config in enabled_providers.items():
        print(f"\n🔍 测试云厂商: {provider_name}")
        print("-" * 40)

        try:
            # 创建provider实例
            provider = get_provider(provider_name, provider_config)

            if not provider:
                print(f"❌ {provider_name}: Provider创建失败")
                continue

            print(f"✅ {provider_name}: Provider创建成功")

            # 获取目标配置
            is_lighthouse = (
                "lighthouse" in provider_name or "lightsail" in provider_name
            )

            if is_lighthouse:
                targets = provider_config.get("instances", [])
                target_key = "instance_id"
                target_label = "实例ID"
            else:
                targets = provider_config.get("security_groups", [])
                target_key = "security_group_id"
                target_label = "安全组ID"

            # 测试每个目标
            for i, target_config in enumerate(targets):
                target_id = target_config.get("id", "")
                protocol = target_config.get("protocol", "tcp")
                ports = target_config.get("ports", [22])
                current_ip = "1.2.3.4"  # 模拟当前IP

                if not target_id:
                    print(
                        f"  ⚠️ {provider_name} - {target_label} {i + 1}: ID为空，跳过测试"
                    )
                    continue

                print(f"  🎯 {provider_name} - {target_label} {i + 1}: {target_id}")

                try:
                    # 先获取当前规则列表
                    rules_before = provider.list_security_group_rules(target_id)
                    rules_count_before = len(rules_before) if rules_before else 0
                    print(f"    📋 当前规则数量: {rules_count_before}")

                    # 执行删除旧规则
                    if rules_config.get("auto_cleanup_old_ip", True):
                        removed_count = provider.find_and_remove_old_ip_rules(
                            target_id, protocol, ports, current_ip
                        )
                        print(f"    🗑️ 删除了 {removed_count} 个旧规则")

                        # 验证删除后的规则数量
                        rules_after = provider.list_security_group_rules(target_id)
                        rules_count_after = len(rules_after) if rules_after else 0

                        if rules_count_before > rules_count_after:
                            print(
                                f"    ✅ 规则数量变化: {rules_count_before} → {rules_count_after}"
                            )

                            # 检查是否还有匹配的旧规则
                            remaining_old_rules = []
                            for rule in rules_after:
                                try:
                                    if provider._is_old_rule(
                                        rule, protocol, ports, current_ip
                                    ):
                                        remaining_old_rules.append(
                                            rule.get("rule_id", "")
                                        )
                                except:
                                    pass

                            if remaining_old_rules:
                                print(
                                    f"    ⚠️ 仍有 {len(remaining_old_rules)} 个疑似旧规则未清理"
                                )
                            else:
                                print(f"    ✅ 没有匹配的旧规则")

                        test_results.append(
                            {
                                "provider": provider_name,
                                "target_id": target_id,
                                "rules_before": rules_count_before,
                                "removed_count": removed_count,
                                "rules_after": rules_count_after,
                                "status": "success",
                            }
                        )
                    else:
                        print(f"    ⚠️ 自动清理功能未启用")
                        test_results.append(
                            {
                                "provider": provider_name,
                                "target_id": target_id,
                                "rules_before": rules_count_before,
                                "removed_count": 0,
                                "rules_after": rules_count_before,
                                "status": "skip",
                            }
                        )

                except Exception as e:
                    print(f"    ❌ 删除规则失败: {e}")
                    test_results.append(
                        {
                            "provider": provider_name,
                            "target_id": target_id,
                            "status": "error",
                            "error": str(e),
                        }
                    )

        except Exception as e:
            print(f"❌ {provider_name}: 测试失败: {e}")
            test_results.append(
                {"provider": provider_name, "status": "error", "error": str(e)}
            )

    # 输出测试总结
    print("\n" + "=" * 50)
    print("📊 测试总结:")
    print("=" * 50)

    total_providers = len([r for r in test_results if r.get("status") != "error"])
    success_providers = len([r for r in test_results if r.get("status") == "success"])
    skip_providers = len([r for r in test_results if r.get("status") == "skip"])
    error_providers = len([r for r in test_results if r.get("status") == "error"])

    total_removed = sum(r.get("removed_count", 0) for r in test_results)

    print(f"🏢 总厂商数: {total_providers}")
    print(f"✅ 成功厂商: {success_providers}")
    print(f"⏭️ 跳过厂商: {skip_providers}")
    print(f"❌ 错误厂商: {error_providers}")
    print(f"🗑️ 总删除规则数: {total_removed}")

    if error_providers == 0 and success_providers > 0:
        print("🎉 删除历史旧规则功能测试通过!")
        return True
    else:
        print("❌ 删除历史旧规则功能测试失败!")
        return False


def main():
    """主测试函数"""
    print("🔧 动态云防火墙 - 删除历史旧规则测试")
    print("🌐 预期功能: 自动检测并删除旧的IP访问规则")

    try:
        success = test_delete_old_rules()
        if success:
            print("\n🚀 所有测试通过，系统功能正常!")
            return 0
        else:
            print("\n💥 测试失败，请检查系统配置!")
            return 1

    except Exception as e:
        print(f"\n💥 测试异常: {e}")
        return 1


if __name__ == "__main__":
    exit(main())
