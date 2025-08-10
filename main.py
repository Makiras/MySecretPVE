from webapp import app


if __name__ == '__main__':
    # 统一的程序入口：仅启动 Web 应用，所有外部连接均采用惰性初始化
    app.run(host="0.0.0.0", port=5000)

    