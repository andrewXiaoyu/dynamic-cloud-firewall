from flask import Flask
from app.providers.factory import get_provider_info, clear_provider_cache
from app.utils.logger import logger


def register_cache_api(app: Flask):
    """
    注册缓存管理API路由

    Args:
        app: Flask应用实例
    """

    @app.route("/api/cache/status", methods=["GET"])
    def get_cache_status():
        """获取缓存状态信息"""
        try:
            provider_info = get_provider_info()

            return {
                "success": True,
                "data": {
                    "total_cached_providers": provider_info["total_count"],
                    "cached_providers": provider_info["providers"],
                    "supported_providers": provider_info["supported"],
                    "cache_status": "active",
                },
            }
        except Exception as e:
            logger.error(f"获取缓存状态失败: {e}")
            return {"success": False, "message": f"获取缓存状态失败: {str(e)}"}, 500

    @app.route("/api/cache/providers", methods=["GET"])
    def list_cached_providers():
        """列出所有缓存的provider"""
        try:
            provider_info = get_provider_info()

            return {
                "success": True,
                "data": {
                    "providers": provider_info["providers"],
                    "total_count": provider_info["total_count"],
                },
            }
        except Exception as e:
            logger.error(f"列出缓存provider失败: {e}")
            return {"success": False, "message": f"列出缓存provider失败: {str(e)}"}, 500

    @app.route("/api/cache/provider/<provider_name>", methods=["GET"])
    def get_provider_cache_info(provider_name: str):
        """获取指定provider的缓存信息"""
        try:
            provider_info = get_provider_info()

            # 筛选指定provider的信息
            provider_cache_info = {}
            for config_key, provider_name_cached in provider_info["providers"].items():
                if provider_name_cached == provider_name:
                    provider_cache_info[config_key] = provider_name_cached

            if not provider_cache_info:
                return {
                    "success": False,
                    "message": f"Provider {provider_name} 没有缓存实例",
                }, 404

            return {
                "success": True,
                "data": {
                    "provider_name": provider_name,
                    "cached_instances": provider_cache_info,
                    "instance_count": len(provider_cache_info),
                },
            }
        except Exception as e:
            logger.error(f"获取provider缓存信息失败: {e}")
            return {
                "success": False,
                "message": f"获取provider缓存信息失败: {str(e)}",
            }, 500

    @app.route("/api/cache/statistics", methods=["GET"])
    def get_cache_statistics():
        """获取缓存统计信息"""
        try:
            provider_info = get_provider_info()

            # 统计各类型provider的缓存数量
            provider_counts = {}
            for provider_name in provider_info["providers"].values():
                provider_counts[provider_name] = (
                    provider_counts.get(provider_name, 0) + 1
                )

            return {
                "success": True,
                "data": {
                    "total_cached_providers": provider_info["total_count"],
                    "supported_providers": provider_info["supported"],
                    "provider_counts": provider_counts,
                    "cache_hit_ratio": "N/A",  # 需要在实际使用中统计
                    "memory_usage": "N/A",  # 需要实际测量
                },
            }
        except Exception as e:
            logger.error(f"获取缓存统计失败: {e}")
            return {"success": False, "message": f"获取缓存统计失败: {str(e)}"}, 500

    @app.route("/api/cache/warmup", methods=["POST"])
    def warmup_cache():
        """预热缓存（预加载所有启用的provider）"""
        try:
            from app.config import config_manager

            enabled_providers = config_manager.get_enabled_providers()
            loaded_providers = {}

            for provider_name, provider_config in enabled_providers.items():
                try:
                    provider = get_provider(provider_name, provider_config)
                    if provider:
                        loaded_providers[provider_name] = provider
                        logger.info(f"预热provider成功: {provider_name}")
                    else:
                        logger.warning(f"预热provider失败: {provider_name}")
                except Exception as e:
                    logger.error(f"预热provider异常: {provider_name}, 错误: {e}")

            return {
                "success": True,
                "data": {
                    "loaded_providers": list(loaded_providers.keys()),
                    "total_loaded": len(loaded_providers),
                    "message": f"成功预热 {len(loaded_providers)} 个provider",
                },
            }
        except Exception as e:
            logger.error(f"预热缓存失败: {e}")
            return {"success": False, "message": f"预热缓存失败: {str(e)}"}, 500

    logger.info("缓存管理API已注册")
