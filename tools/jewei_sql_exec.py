from collections.abc import Generator
from typing import Any, Optional, Dict, List
from enum import Enum
import json
from datetime import datetime, date, time
from decimal import Decimal
import uuid
import contextlib
from urllib.parse import quote_plus
import re

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.types import TypeEngine
from sqlalchemy.exc import SQLAlchemyError, DatabaseError
from cryptography.fernet import Fernet, InvalidToken
from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

class DatabaseError(Exception):
    """Custom database error"""
    pass

class DatabaseType(Enum):
    MYSQL = "mysql"
    MSSQL = "mssql"

class DatabaseEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        elif isinstance(obj, time):
            return obj.strftime('%H:%M:%S.%f')
        elif isinstance(obj, Decimal):
            return str(obj)
        elif isinstance(obj, bytes):
            return obj.hex()
        elif isinstance(obj, uuid.UUID):
            return str(obj)
        elif isinstance(obj, TypeEngine):
            return str(obj)
        return str(obj) if hasattr(obj, '__str__') else super().default(obj)

class DatabaseConnection:
    def __init__(self, db_type: DatabaseType, host: str, port: int, database: str, 
                 username: str, password: str, encrypt_key: Optional[str] = None,
                 timeout: int = 30):
        self.db_type = db_type
        self.host = host
        self.port = port
        self.database = database
        self.username = username
        self.timeout = timeout
        try:
            self._password = self._encrypt_password(password, encrypt_key) if encrypt_key else password
        except Exception as e:
            raise DatabaseError(f"Failed to encrypt password: {str(e)}")
        self._engine: Optional[Engine] = None
        self._encrypt_key = encrypt_key

    def _encrypt_password(self, password: str, key: str) -> str:
        try:
            f = Fernet(key.encode())
            return f.encrypt(password.encode()).decode()
        except Exception as e:
            raise DatabaseError(f"Password encryption failed: {str(e)}")

    def _decrypt_password(self) -> str:
        if not self._encrypt_key:
            return self._password
        try:
            f = Fernet(self._encrypt_key.encode())
            return f.decrypt(self._password.encode()).decode()
        except InvalidToken:
            raise DatabaseError("Invalid encryption key or corrupted password")
        except Exception as e:
            raise DatabaseError(f"Password decryption failed: {str(e)}")

    def get_connection_string(self) -> str:
        try:
            password = self._decrypt_password()
            # URL encode username and password
            safe_username = quote_plus(self.username)
            safe_password = quote_plus(password)
            
            if self.db_type == DatabaseType.MYSQL:
                return f"mysql+pymysql://{safe_username}:{safe_password}@{self.host}:{self.port}/{self.database}?charset=utf8mb4"
            elif self.db_type == DatabaseType.MSSQL:
                return f"mssql+pymssql://{safe_username}:{safe_password}@{self.host}:{self.port}/{self.database}?charset=utf8"
            raise ValueError(f"Unsupported database type: {self.db_type}")
        except Exception as e:
            raise DatabaseError(f"Failed to create connection string: {str(e)}")

    @contextlib.contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        if not self._engine:
            try:
                self._engine = create_engine(
                    self.get_connection_string(),
                    pool_pre_ping=True,  # Enable connection health checks
                    pool_recycle=3600,   # Recycle connections after 1 hour
                    connect_args={
                        "connect_timeout": self.timeout,
                        "read_timeout": self.timeout
                    }
                )
            except Exception as e:
                raise DatabaseError(f"Failed to create database engine: {str(e)}")
        
        try:
            with self._engine.connect() as connection:
                yield connection
        except SQLAlchemyError as e:
            raise DatabaseError(f"Database operation failed: {str(e)}")
        finally:
            if self._engine:
                self._engine.dispose()
                self._engine = None

    def _add_limit_to_query(self, query: str, max_rows: int) -> str:
        """Add LIMIT clause to the query if not present."""
        query = query.strip()
        
        # 如果已经有 LIMIT，不做修改
        if re.search(r'\bLIMIT\s+\d+\s*(?:,\s*\d+\s*)?$', query, re.IGNORECASE):
            return query
            
        # 对于 SELECT 语句添加 LIMIT
        if re.match(r'^\s*SELECT\b', query, re.IGNORECASE):
            if self.db_type == DatabaseType.MYSQL:
                return f"{query} LIMIT {max_rows}"
            elif self.db_type == DatabaseType.MSSQL:
                # 对于 MSSQL，如果已经有 TOP，不做修改
                if not re.search(r'\bTOP\s+\d+\b', query, re.IGNORECASE):
                    # 在 SELECT 后插入 TOP
                    query = re.sub(r'^\s*SELECT\b', f'SELECT TOP {max_rows}', query, flags=re.IGNORECASE)
                return query
                
        return query

    def execute_query(self, query: str, max_rows: int = 1000) -> List[Dict[str, Any]]:
        """Execute a SQL query and return results."""
        try:
            # 添加 LIMIT 语句
            modified_query = query
            
            with self.get_connection() as connection:
                result = connection.execute(text(modified_query))
                return [{k: self._convert_value(v) for k, v in row._mapping.items()} 
                        for row in result]
        except DatabaseError:
            raise
        except Exception as e:
            raise DatabaseError(f"Query execution failed: {str(e)}")

    def _convert_value(self, value: Any) -> Any:
        """Convert special database types to Python native types."""
        try:
            if value is None:
                return None
            elif isinstance(value, (int, float, str, bool)):
                return value
            elif isinstance(value, (datetime, date, time, Decimal, uuid.UUID)):
                return value
            elif isinstance(value, bytes):
                return value.hex()
            elif hasattr(value, '_asdict'):  # For composite types
                return value._asdict()
            return str(value)
        except Exception as e:
            raise DatabaseError(f"Value conversion failed: {str(e)}")

class JeweiSqlExecTool(Tool):
    def _invoke(self, tool_parameters: dict[str, Any]) -> Generator[ToolInvokeMessage, None, None]:
        try:
            # Extract parameters
            db_type = DatabaseType(tool_parameters.get("db_type", "mysql"))
            host = tool_parameters.get("host")
            port = int(tool_parameters.get("port", 3306))
            database = tool_parameters.get("database")
            username = tool_parameters.get("username")
            password = tool_parameters.get("password")
            query = tool_parameters.get("query")
            encrypt_key = None
            timeout = int(tool_parameters.get("timeout", 30))
            max_rows = 1000

            # Validate required parameters
            required_params = ["host", "database", "username", "password", "query"]
            missing_params = [param for param in required_params if not tool_parameters.get(param)]
            if missing_params:
                raise ValueError(f"Missing required parameters: {', '.join(missing_params)}")

            # Validate port number
            if not (1 <= port <= 65535):
                raise ValueError(f"Invalid port number: {port}")

            # Validate timeout
            if timeout <= 0:
                raise ValueError(f"Invalid timeout value: {timeout}")

            # Create database connection
            db_conn = DatabaseConnection(
                db_type=db_type,
                host=host,
                port=port,
                database=database,
                username=username,
                password=password,
                encrypt_key=encrypt_key,
                timeout=timeout
            )

            # Execute query and get results
            results={"data": []}
            results["data"] = db_conn.execute_query(query, max_rows)
            
            # Format results as JSON
            yield self.create_text_message(json.dumps(results, indent=2, cls=DatabaseEncoder))

        except DatabaseError as e:
            results={"error_msg": f"Database error: {str(e)}"}
            yield self.create_text_message(json.dumps(results, indent=2, cls=DatabaseEncoder))
        except ValueError as e:
            results={"error_msg": f"Invalid parameter: {str(e)}"}
            yield self.create_text_message(json.dumps(results, indent=2, cls=DatabaseEncoder))
        except Exception as e:
            results={"error_msg": f"Unexpected error: {str(e)}"}
            yield self.create_text_message(json.dumps(results, indent=2, cls=DatabaseEncoder))
