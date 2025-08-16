from __future__ import annotations
from sqlalchemy import create_engine, Column, String, Boolean, Integer, text
from sqlalchemy.types import BigInteger
from datetime import datetime
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

# 定义 CDN 配置模型
class CDNConfig(Base):
    __tablename__ = "cdn_config"

    id = Column(String, primary_key=True, index=True, default="default")
    # 是否启用定时同步
    enabled = Column(Boolean, default=False)
    # 同步周期（分钟）
    interval_minutes = Column(Integer, default=360)
    # 各提供商对应的 IPSet 名称
    ipset_edgeone = Column(String, nullable=False, default="edgeone")
    ipset_cloudflare = Column(String, nullable=False, default="cloudflare")
    ipset_tencent = Column(String, nullable=False, default="tencent")

    
class CDNSyncStatus(Base):
    __tablename__ = "cdn_sync_status"

    provider = Column(String, primary_key=True, index=True)
    last_ts = Column(BigInteger, nullable=False, default=0)
    last_ok = Column(Boolean, default=False)
    last_count = Column(Integer, default=0)
    last_message = Column(String, nullable=True)

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
            # ensure temp_whitelist table and new columns
            conn.exec_driver_sql("CREATE TABLE IF NOT EXISTS temp_whitelist (id INTEGER PRIMARY KEY AUTOINCREMENT, cidr VARCHAR NOT NULL, created_at BIGINT NOT NULL, expires_at BIGINT NOT NULL)")
            cols_tw = {r[1] for r in conn.exec_driver_sql("PRAGMA table_info('temp_whitelist')").fetchall()}
            if "hostname" not in cols_tw:
                conn.exec_driver_sql("ALTER TABLE temp_whitelist ADD COLUMN hostname VARCHAR")
            # Ensure cdn_config table exists
            conn.exec_driver_sql(
                "CREATE TABLE IF NOT EXISTS cdn_config ("
                "id VARCHAR PRIMARY KEY, "
                "enabled BOOLEAN DEFAULT 0, "
                "interval_minutes INTEGER DEFAULT 360, "
                "ipset_edgeone VARCHAR NOT NULL DEFAULT 'edgeone', "
                "ipset_cloudflare VARCHAR NOT NULL DEFAULT 'cloudflare', "
                "ipset_tencent VARCHAR NOT NULL DEFAULT 'tencent'"
                ")"
            )
            # Ensure cdn_sync_status table exists
            conn.exec_driver_sql(
                "CREATE TABLE IF NOT EXISTS cdn_sync_status ("
                "provider VARCHAR PRIMARY KEY, "
                "last_ts BIGINT NOT NULL DEFAULT 0, "
                "last_ok BOOLEAN DEFAULT 0, "
                "last_count INTEGER DEFAULT 0, "
                "last_message VARCHAR"
                ")"
            )
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
    
    # CDN sync status helpers
    def set_cdn_sync_status(self, provider: str, ok: bool, count: int, message: str | None = None, ts: int | None = None) -> None:
        if ts is None:
            ts = int(datetime.utcnow().timestamp())
        row = self.db.query(CDNSyncStatus).filter_by(provider=provider).first()
        if not row:
            row = CDNSyncStatus(provider=provider, last_ts=ts, last_ok=ok, last_count=count, last_message=message)
            self.db.add(row)
        else:
            row.last_ts = ts
            row.last_ok = ok
            row.last_count = count
            row.last_message = message
        self.db.commit()

    def get_cdn_sync_status(self) -> dict:
        rows = self.db.query(CDNSyncStatus).all()
        res = {}
        for r in rows:
            res[r.provider] = {
                "last_ts": int(r.last_ts or 0),
                "last_ok": bool(r.last_ok),
                "last_count": int(r.last_count or 0),
                "last_message": r.last_message or "",
            }
        # ensure placeholders for known providers
        for key in ("edgeone", "cloudflare", "tencent"):
            if key not in res:
                res[key] = {"last_ts": 0, "last_ok": False, "last_count": 0, "last_message": ""}
        return res

    # 临时白名单表：记录 CIDR 与过期时间
    class TempWhitelist(Base):
        __tablename__ = "temp_whitelist"

        id = Column(Integer, primary_key=True, autoincrement=True)
        cidr = Column(String, nullable=False, index=True)
        created_at = Column(BigInteger, nullable=False)  # epoch seconds
        expires_at = Column(BigInteger, nullable=False)  # epoch seconds
        hostname = Column(String, nullable=True)

    def _ensure_tempwhitelist_table(self):
        # Create table if not exists (create_all covers new tables)
        self.db.execute(text(""))  # no-op to ensure engine is ready

    def add_or_update_temp_whitelist(self, cidr: str, expires_at: int, hostname: str | None = None) -> None:
        now = int(datetime.utcnow().timestamp())
        row = self.db.query(Settings.TempWhitelist).filter_by(cidr=cidr).first()
        if row:
            row.expires_at = expires_at
            if hostname:
                row.hostname = hostname
        else:
            row = Settings.TempWhitelist(cidr=cidr, created_at=now, expires_at=expires_at, hostname=(hostname or None))
            self.db.add(row)
        self.db.commit()

    def get_expired_temp_whitelist(self, now_ts: int) -> list["Settings.TempWhitelist"]:
        return (
            self.db.query(Settings.TempWhitelist)
            .filter(Settings.TempWhitelist.expires_at <= now_ts)
            .all()
        )

    def delete_temp_whitelist(self, cidr: str) -> None:
        self.db.query(Settings.TempWhitelist).filter_by(cidr=cidr).delete()
        self.db.commit()

    def list_temp_whitelist(self, include_expired: bool = False) -> list["Settings.TempWhitelist"]:
        q = self.db.query(Settings.TempWhitelist)
        if not include_expired:
            now_ts = int(datetime.utcnow().timestamp())
            q = q.filter(Settings.TempWhitelist.expires_at > now_ts)
        return q.order_by(Settings.TempWhitelist.expires_at.asc()).all()

    def update_temp_hostname(self, cidr: str, hostname: str | None) -> None:
        row = self.db.query(Settings.TempWhitelist).filter_by(cidr=cidr).first()
        if not row:
            # create a placeholder with immediate expiration in case not exists
            now = int(datetime.utcnow().timestamp())
            row = Settings.TempWhitelist(cidr=cidr, created_at=now, expires_at=now, hostname=(hostname or None))
            self.db.add(row)
        else:
            row.hostname = (hostname or None)
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

    @property
    def cdn(self):
        config = self.db.query(CDNConfig).filter_by(id="default").first()
        if not config:
            config = CDNConfig(
                id="default",
                enabled=False,
                interval_minutes=360,
                ipset_edgeone="edgeone",
                ipset_cloudflare="cloudflare",
                ipset_tencent="tencent",
            )
            self.db.add(config)
            self.db.commit()
        return {
            "enabled": bool(config.enabled),
            "interval_minutes": int(config.interval_minutes or 360),
            "ipset_edgeone": config.ipset_edgeone or "edgeone",
            "ipset_cloudflare": config.ipset_cloudflare or "cloudflare",
            "ipset_tencent": config.ipset_tencent or "tencent",
        }

    def update_cdn(self, *, enabled: bool, interval_minutes: int, ipset_edgeone: str, ipset_cloudflare: str, ipset_tencent: str) -> None:
        config = self.db.query(CDNConfig).filter_by(id="default").first()
        if not config:
            config = CDNConfig(
                id="default",
                enabled=enabled,
                interval_minutes=interval_minutes,
                ipset_edgeone=ipset_edgeone,
                ipset_cloudflare=ipset_cloudflare,
                ipset_tencent=ipset_tencent,
            )
            self.db.add(config)
        else:
            config.enabled = enabled
            config.interval_minutes = interval_minutes
            config.ipset_edgeone = ipset_edgeone
            config.ipset_cloudflare = ipset_cloudflare
            config.ipset_tencent = ipset_tencent
        self.db.commit()
