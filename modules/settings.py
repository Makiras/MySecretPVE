from sqlalchemy import create_engine, Column, String, Boolean, Integer, text
from sqlalchemy.orm import declarative_base, sessionmaker

# 初始化数据库
DATABASE_URL = "sqlite:///settings.db"
Base = declarative_base()
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 定义 PVE 配置模型
class PVEConfig(Base):
    __tablename__ = "pve_config"

    id = Column(String, primary_key=True, index=True, default="default")
    host = Column(String, nullable=False)
    user = Column(String, nullable=False)
    password = Column(String, nullable=False)
    ssl_verify = Column(Boolean, default=True)
    # 新增字段：协议与端口
    protocol = Column(String, nullable=False, default="https")
    port = Column(Integer, nullable=True)
    # 可选：API Token 认证（优先于用户密码）
    token_name = Column(String, nullable=True)
    token_value = Column(String, nullable=True)

# 定义 Tencent 配置模型
class TencentConfig(Base):
    __tablename__ = "tencent_config"

    id = Column(String, primary_key=True, index=True, default="default")
    secret = Column(String, nullable=False)
    key = Column(String, nullable=False)

# 修改 Settings 类（基于数据库持久化）
class Settings:
    """Persistent settings using SQLite (SQLAlchemy)."""

    def __init__(self) -> None:
        Base.metadata.create_all(bind=engine)
        # 轻量迁移：确保新增字段存在
        with engine.connect() as conn:
            cols = {r[1] for r in conn.exec_driver_sql("PRAGMA table_info('pve_config')").fetchall()}
            if "protocol" not in cols:
                conn.exec_driver_sql("ALTER TABLE pve_config ADD COLUMN protocol VARCHAR NOT NULL DEFAULT 'https'")
            if "port" not in cols:
                conn.exec_driver_sql("ALTER TABLE pve_config ADD COLUMN port INTEGER")
            if "token_name" not in cols:
                conn.exec_driver_sql("ALTER TABLE pve_config ADD COLUMN token_name VARCHAR")
            if "token_value" not in cols:
                conn.exec_driver_sql("ALTER TABLE pve_config ADD COLUMN token_value VARCHAR")
        self.db = SessionLocal()

    # 归一化 PVE Host：剥离协议与端口，自动识别重复输入
    @staticmethod
    def _normalize_pve_input(host: str, user_protocol: str | None, user_port: int | None):
        host = (host or "").strip()
        protocol = (user_protocol or "").lower().strip() or "https"
        port = user_port

        # 解析协议
        if host.startswith("http://"):
            protocol = "http"
            host = host[len("http://"):]
        elif host.startswith("https://"):
            protocol = "https"
            host = host[len("https://"):]

        # 去除尾部斜杠
        host = host.rstrip("/")

        # 解析端口（考虑 IPv6 带方括号）
        if host.startswith("["):
            # IPv6 形式：[addr]:port 或 [addr]
            if "]:" in host:
                addr, p = host.rsplit(":", 1)
                host = addr
                try:
                    port = int(p)
                except Exception:
                    pass
        else:
            # IPv4 或域名: a.b.c:port
            if ":" in host and host.count(":") == 1:
                addr, p = host.split(":", 1)
                if p.isdigit():
                    host = addr
                    try:
                        port = int(p)
                    except Exception:
                        pass

        # 默认端口
        if port is None:
            port = 8006

        # 存储时 host 不含协议/端口
        return host, protocol, port

    @property
    def pve(self):
        config = self.db.query(PVEConfig).filter_by(id="default").first()
        if not config:
            config = PVEConfig(host="", user="", password="", ssl_verify=True, protocol="https", port=8006)
            self.db.add(config)
            self.db.commit()
        return {
            "host": config.host,
            "user": config.user,
            "password": config.password,
            "ssl_verify": config.ssl_verify,
            "protocol": config.protocol or "https",
            "port": config.port or 8006,
            "token_name": config.token_name or "",
            "token_value": config.token_value or "",
        }

    def update_pve(self, host: str, user: str, password: str, ssl_verify: bool, protocol: str | None = None, port: int | None = None, token_name: str | None = None, token_value: str | None = None) -> None:
        # 归一化输入
        norm_host, norm_protocol, norm_port = self._normalize_pve_input(host, protocol, port)
        config = self.db.query(PVEConfig).filter_by(id="default").first()
        if not config:
            config = PVEConfig(
                id="default",
                host=norm_host,
                user=user,
                password=password,
                ssl_verify=ssl_verify,
                protocol=norm_protocol,
                port=norm_port,
                token_name=(token_name or None),
                token_value=(token_value or None),
            )
            self.db.add(config)
        else:
            config.host = norm_host
            config.user = user
            config.password = password
            config.ssl_verify = ssl_verify
            config.protocol = norm_protocol
            config.port = norm_port
            config.token_name = (token_name or None)
            config.token_value = (token_value or None)
        self.db.commit()

    @property
    def tencent(self):
        config = self.db.query(TencentConfig).filter_by(id="default").first()
        if not config:
            config = TencentConfig(secret="", key="")
            self.db.add(config)
            self.db.commit()
        return {
            "secret": config.secret,
            "key": config.key,
        }

    def update_tencent(self, secret: str, key: str) -> None:
        config = self.db.query(TencentConfig).filter_by(id="default").first()
        if not config:
            config = TencentConfig(id="default", secret=secret, key=key)
            self.db.add(config)
        else:
            config.secret = secret
            config.key = key
        self.db.commit()
