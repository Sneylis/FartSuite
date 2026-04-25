from typing import Optional
from sqlmodel import Field, Session, SQLModel, create_engine
import time


class Project(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    description: Optional[str] = None


class Capture(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    project_id: int = Field(foreign_key="project.id")
    interface: str
    filter_ip: Optional[str] = None
    status: str = "starting"
    packets_count: int = 0


class Packet(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id")
    timestamp: float = Field(default_factory=time.time)
    length: int = 0
    protocol: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    data: Optional[str] = None


sqlite_file_name = "fartsuite.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"
engine = create_engine(sqlite_url, echo=False)


def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session
