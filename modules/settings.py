from sqlalchemy import create_engine, Column, String, Boolean
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
        self.db = SessionLocal()

    @property
    def pve(self):
        config = self.db.query(PVEConfig).filter_by(id="default").first()
        if not config:
            config = PVEConfig(host="", user="", password="", ssl_verify=True)
            self.db.add(config)
            self.db.commit()
        return {
            "host": config.host,
            "user": config.user,
            "password": config.password,
            "ssl_verify": config.ssl_verify,
        }

    def update_pve(self, host: str, user: str, password: str, ssl_verify: bool) -> None:
        config = self.db.query(PVEConfig).filter_by(id="default").first()
        if not config:
            config = PVEConfig(id="default", host=host, user=user, password=password, ssl_verify=ssl_verify)
            self.db.add(config)
        else:
            config.host = host
            config.user = user
            config.password = password
            config.ssl_verify = ssl_verify
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
