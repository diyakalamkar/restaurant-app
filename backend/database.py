from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from urllib.parse import quote_plus
import pyodbc


connection_string = quote_plus(
    "DRIVER={ODBC Driver 18 for SQL Server};"
    "SERVER=localhost\\SQLSERVER;" #server path
    "DATABASE=restaurantdb;"
    "UID=sa;"
    "PWD=diya;"
    "Encrypt=no;"
    "TrustServerCertificate=yes;"
)

SQLALCHEMY_DATABASE_URL = f"mssql+pyodbc:///?odbc_connect={connection_string}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"timeout": 30}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


