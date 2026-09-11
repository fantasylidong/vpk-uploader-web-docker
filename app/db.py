from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text
from sqlalchemy.orm import declarative_base, sessionmaker
import os

DATA_DIR = os.getenv("DATA_DIR", os.path.join(os.path.dirname(os.path.dirname(__file__)), "data"))
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.getenv("DATABASE_PATH", os.path.join(DATA_DIR, "uploader.sqlite3"))
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

class Upload(Base):
    __tablename__ = "uploads"
    id = Column(Integer, primary_key=True, index=True)
    original_name = Column(String(512))
    stored_name = Column(String(512), unique=True)
    sha256 = Column(String(64), index=True)
    size = Column(Integer)
    role = Column(String(32))  # guest/admin
    created_at = Column(DateTime)
    expires_at = Column(DateTime, nullable=True)
    vpk_valid = Column(Boolean, default=False)
    vpk_report = Column(Text, nullable=True)
    status = Column(String(32), default="active")
    uploader_ip = Column(String(64), nullable=True)


class AppSetting(Base):
    __tablename__ = "app_settings"
    key = Column(String(128), primary_key=True, index=True)
    value = Column(String(1024), nullable=False)


class ReplicationReservation(Base):
    __tablename__ = "replication_reservations"
    id = Column(String(64), primary_key=True, index=True)
    source_node_id = Column(String(128), nullable=False, index=True)
    lan_group = Column(String(128), nullable=False, index=True)
    manifest = Column(Text, nullable=False)
    reserved_bytes = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)
    status = Column(String(32), nullable=False, default="active", index=True)


class WorkshopJob(Base):
    """创意工坊导入任务，供 NewAnneWeb 轮询进度。"""

    __tablename__ = "workshop_jobs"
    id = Column(String(64), primary_key=True, index=True)
    status = Column(String(32), nullable=False, default="queued", index=True)
    role = Column(String(32), nullable=False, default="admin")
    ttl_hours = Column(Integer, nullable=True)
    request = Column(Text, nullable=True)
    items = Column(Text, nullable=False, default="[]")
    replication = Column(Text, nullable=True)
    error = Column(Text, nullable=True)
    source_ip = Column(String(64), nullable=True)
    created_at = Column(DateTime, nullable=False, index=True)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)


def init_db():
    Base.metadata.create_all(bind=engine)
