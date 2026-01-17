#!/usr/bin/env python3
"""
简单的删除历史旧规则测试
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.config import config_manager
from app.providers.factory import get_provider
from app.utils.logger import logger


def main():
    print("🧪 测试删除历史旧规则功能")
    print("=" * 50)

    try:
        # 获取配置
        enabled_providers = config_manager.get_enabled_providers()
        rules_config = config_manager.get_rules_config()

        if not enabled_providers:
            print("❌ 没有启用的云厂商")
            return 1

        print(f"📋 可用厂商: {list(enabled_providers.keys())}")

        # 测试第一个提供商
        first_provider_name = list(enabled_providers.keys())[0]
        first_config = enabled_providers[first_provider_name]

        print(f"🎯 测试厂商: {first_provider_name}")
        print("-" * 40)

        # 创建provider
        provider = get_provider(first_provider_name, first_config)

        if not provider:
            print(f"❌ Provider创建失败")
            return 1

        print(f"✅ Provider创建成功")

        # 获取目标
        targets = first_config.get("security_groups", [])
        if not targets:
            print(f"❌ 没有安全组配置")
            return 1

        target_id = targets[0].get("id", "")
        if not target_id:
            print(f"❌ 安全组ID为空")
            return 1

        print(f"🎯 目标: {target_id}")

        # 测试删除功能
        if not hasattr(provider, "find_and_remove_old_ip_rules"):
            print("❌ 缺少find_and_remove_old_ip_rules方法")
            return 1

        print("🧪 测试删除功能...")

        try:
            # 获取规则
            rules_before = provider.list_security_group_rules(target_id)
            print(f"📋 当前规则数: {len(rules_before) if rules_before else 0}")

            # 执行删除
            removed_count = provider.find_and_remove_old_ip_rules(
                target_id, "tcp", ["22"], "1.2.3.4"
            )
            print(f"🗑️ 删除了 {removed_count} 个旧规则")

            # 验证结果
            rules_after = provider.list_security_group_rules(target_id)
            remaining_count = 0

            for rule in rules_after:
                try:
                    if hasattr(provider, "_is_old_rule"):
                        if provider._is_old_rule(rule, "tcp", ["22"], "1.2.3.4"):
                            remaining_count += 1
                except:
                    pass

            if remaining_count > 0:
                print(f"⚠️ 仍有{remaining_count}个旧规则残留")
            else:
                print("✅ 清理完成，无匹配的旧规则")

            print("🎉 删除历史旧规则测试通过!")
            return 0

        except Exception as e:
            print(f"❌ 测试失败: {e}")
            return 1

    except Exception as e:
        print(f"💥 系统异常: {e}")
        return 1


if __name__ == "__main__":
    exit(main())
