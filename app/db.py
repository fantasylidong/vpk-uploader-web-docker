from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text
from sqlalchemy.orm import declarative_base, sessionmaker
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "uploader.sqlite3")
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
    status = Column(String(32), default="active")  # active/rejected/deleted
    uploader_ip = Column(String(64), nullable=True)

def init_db():
    Base.metadata.create_all(bind=engine)
