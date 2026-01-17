#!/usr/bin/env python3
"""
主应用入口
"""

from app.handlers.webhook import init_webhook_app


def main():
    """主函数"""
    app = init_webhook_app()

    # 获取配置
    from app.config import config_manager

    webhook_config = config_manager.get_webhook_config()
    port = webhook_config.get("port", 5000)

    # 启动应用
    app.run(host="0.0.0.0", port=port, debug=False)


if __name__ == "__main__":
    main()
