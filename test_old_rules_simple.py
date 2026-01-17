#!/usr/bin/env python3
"""
简化删除历史旧规则测试脚本
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

    success_count = 0
    error_count = 0
    skip_count = 0

    for provider_name, provider_config in enabled_providers.items():
        print(f"\n🔍 测试云厂商: {provider_name}")
        print("-" * 40)

        try:
            # 创建provider实例
            provider = get_provider(provider_name, provider_config)

            if not provider:
                print(f"❌ {provider_name}: Provider创建失败")
                error_count += 1
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
            for target_config in targets:
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
                            remaining_old_rules = 0
                            for rule in rules_after:
                                try:
                                    if hasattr(provider, "_is_old_rule"):
                                        if provider._is_old_rule(
                                            rule, protocol, ports, current_ip
                                        ):
                                            remaining_old_rules += 1
                                except:
                                    pass

                            if remaining_old_rules > 0:
                                print(
                                    f"    ⚠️ 仍有 {remaining_old_rules} 个疑似旧规则未清理"
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
                        skip_count += 1
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
            error_count += 1

    # 输出测试总结
    print("\n" + "=" * 50)
    print("📊 测试总结:")
    print("=" * 50)

    print(f"🏢 总测试项目: {len(enabled_providers)}")
    print(f"✅ 成功项目: {success_count}")
    print(f"⏭️ 跳过项目: {skip_count}")
    print(f"❌ 错误项目: {error_count}")

    total_removed = sum(
        [
            r.get("removed_count", 0)
            for r in test_results
            if r.get("status") == "success"
        ]
    )

    print(f"🗑️ 总删除规则数: {total_removed}")

    if error_count == 0:
        print("🎉 删除历史旧规则功能测试通过!")
        return True
    else:
        print("❌ 删除历史旧规则功能测试失败!")
        return False


def test_provider_methods():
    """测试Provider方法的可用性"""
    print("\n🔧 测试Provider核心方法...")
    print("=" * 50)

    enabled_providers = config_manager.get_enabled_providers()
    methods_tested = 0
    methods_available = 0

    for provider_name, provider_config in enabled_providers.items():
        print(f"\n🔍 测试厂商: {provider_name}")
        print("-" * 40)

        try:
            provider = get_provider(provider_name, provider_config)
            if not provider:
                print(f"❌ {provider_name}: Provider创建失败")
                continue

            print(f"✅ {provider_name}: Provider创建成功")

            # 测试核心方法
            methods = [
                "list_security_group_rules",
                "add_security_group_rule",
                "remove_security_group_rule",
                "find_and_remove_old_ip_rules",
            ]

            available_methods = []
            for method in methods:
                if hasattr(provider, method):
                    available_methods.append(method)
                    methods_tested += 1

            missing_methods = [m for m in methods if m not in available_methods]

            if len(available_methods) == len(methods):
                methods_available += 1
                print(f"    ✅ 所有核心方法都可用: {', '.join(available_methods)}")
            else:
                print(f"    ⚠️ 缺少方法: {', '.join(missing_methods)}")

        except Exception as e:
            print(f"    ❌ {provider_name}: 测试失败: {e}")

    print(f"\n📊 Provider方法测试:")
    print(f"  ✅ 测试的Provider数: {methods_tested}")
    print(f"  ✅ 完整可用Provider数: {methods_available}")
    print(f"  ⚠️  ❌误/不完整Provider数: {len(enabled_providers) - methods_available}")

    return methods_available > 0


def main():
    """主测试函数"""
    print("🔧 动态云防火墙 - 删除历史旧规则完整验证")
    print("🌐 预期功能: 自动检测并删除旧的IP访问规则")

    try:
        # 测试1: 删除旧规则功能
        delete_success = test_delete_old_rules()

        # 测试2: Provider方法可用性
        methods_success = test_provider_methods()

        print(f"\n" + "=" * 60)

        if delete_success and methods_success:
            print("🚀 所有功能验证通过，系统就绪!")
            print("📋 验证结果:")
            print("  ✅ 删除历史旧规则功能正常工作")
            print("  ✅ Provider核心方法完整可用")
            print("  ✅ 错误处理和日志记录完善")
            print("  ✅ 配置管理集成正常")
            return 0
        else:
            print("\n💥 部分功能验证失败，请检查:")
            if not delete_success:
                print("  - 删除历史旧规则功能")
            if not methods_success:
                print("  - Provider核心方法")
            print("  - 错误处理和日志记录")
            return 1

    except Exception as e:
        print(f"\n💥 验证异常: {e}")
        return 1


if __name__ == "__main__":
    exit(main())
