from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()
class KDC(Base):
    __tablename__ = "KDC"
    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False, unique=True)
    realm = Column(String(200), nullable=False)
    secret_key = Column(String(500))
    key_exp = Column(DateTime)

def CreateAndGetSession(servicedbfile):
    engine = create_engine("sqlite:///" + servicedbfile)
    Base.metadata.bind = engine
    Base.metadata.create_all()
    return sessionmaker(bind=engine)()
