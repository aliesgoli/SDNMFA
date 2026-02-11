import os
import json
import logging
import getpass
import psycopg2
from psycopg2 import pool
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from cryptography.fernet import Fernet
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass
from dotenv import load_dotenv
import atexit
import threading
import time

BASE_DIR = Path(__file__).parent
ROOT_DIR = BASE_DIR.parent
CREDENTIALS_PATH = BASE_DIR / "db_credentials.enc"
KEY_PATH = BASE_DIR / "key.fernet"
LOG_DIR = ROOT_DIR / "logs"
LOG_PATH = LOG_DIR / "db_connections.log"

LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(LOG_PATH, encoding='utf-8')]
)
logger = logging.getLogger(__name__)

load_dotenv(ROOT_DIR / ".env")


@dataclass
class DBConfig:
    dbname: str
    user: str
    password: str
    host: str = "localhost"
    port: str = "5432"
    timeout: int = 10


class ConnectionPoolManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._pool = None
        self._config = None
        self._initialized = True
        self._connection_count = 0
        self._max_retries = 3
        self._closed = False
        atexit.register(self.close_all)

    def initialize(self, config: DBConfig):
        if self._closed:
            logger.warning("Pool was closed, reinitializing...")
            self._closed = False
            self._pool = None

        if self._pool is not None:
            return

        try:
            self._config = config

            self._pool = psycopg2.pool.ThreadedConnectionPool(
                minconn=2,
                maxconn=30,
                dbname=config.dbname,
                user=config.user,
                password=config.password,
                host=config.host,
                port=config.port,
                connect_timeout=config.timeout,
                keepalives=1,
                keepalives_idle=30,
                keepalives_interval=10,
                keepalives_count=3,
                options='-c statement_timeout=30000'
            )
            logger.info("✅ Connection pool initialized (maxconn=30)")
        except Exception as e:
            logger.error("❌ Pool initialization failed: %s", e)
            self._pool = None

    def get_connection(self, retry_count=0):
        if self._closed:
            logger.warning("Pool is closed, attempting to reinitialize")
            if self._config:
                self._closed = False
                self._pool = None
                self.initialize(self._config)

        if self._pool is None:
            logger.error("Pool is None, cannot get connection")
            return None

        try:
            conn = self._pool.getconn()
            if conn:
                conn.autocommit = False
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                self._connection_count += 1
                return conn
        except psycopg2.pool.PoolError as e:
            logger.warning(f"Pool exhausted (attempt {retry_count + 1}): {e}")
            if retry_count < self._max_retries:
                time.sleep(2)
                return self.get_connection(retry_count + 1)
        except psycopg2.OperationalError as e:
            logger.warning(f"Connection failed (attempt {retry_count + 1}): {e}")
            if retry_count < self._max_retries:
                time.sleep(1)
                return self.get_connection(retry_count + 1)
        except Exception as e:
            logger.error("Failed to get connection: %s", e)

        return None

    def return_connection(self, conn, close=False):
        if conn and self._pool and not self._closed:
            try:
                try:
                    if not conn.closed:
                        conn.rollback()
                except:
                    pass

                if close:
                    self._pool.putconn(conn, close=True)
                else:
                    self._pool.putconn(conn)

                self._connection_count = max(0, self._connection_count - 1)
            except Exception as e:
                logger.error("Error returning connection: %s", e)
                try:
                    if not conn.closed:
                        conn.close()
                except:
                    pass

    def close_all(self):
        if self._pool and not self._closed:
            try:
                self._closed = True
                self._pool.closeall()
                logger.info("Connection pool closed")
            except Exception as e:
                logger.error("Error closing pool: %s", e)
            finally:
                self._pool = None
                self._connection_count = 0

    def get_stats(self):
        return {
            'active_connections': self._connection_count,
            'pool_initialized': self._pool is not None and not self._closed,
            'closed': self._closed
        }


class DBManager:
    @staticmethod
    def _load_or_generate_key() -> bytes:
        try:
            if KEY_PATH.exists():
                with open(KEY_PATH, "rb") as key_file:
                    return key_file.read()
            key = Fernet.generate_key()
            with open(KEY_PATH, "wb") as key_file:
                key_file.write(key)
            return key
        except Exception as e:
            logger.error("Key management failed: %s", e)
            raise

    def __init__(self):
        self.key = self._load_or_generate_key()

    def encrypt_data(self, data: Dict[str, str]) -> None:
        try:
            fernet = Fernet(self.key)
            encrypted = fernet.encrypt(json.dumps(data).encode('utf-8'))
            with open(CREDENTIALS_PATH, "wb") as file:
                file.write(encrypted)
        except Exception as e:
            logger.error("Encryption failed: %s", e)
            raise

    def decrypt_data(self) -> Optional[Dict[str, str]]:
        if not CREDENTIALS_PATH.exists():
            return None
        try:
            with open(CREDENTIALS_PATH, "rb") as file:
                encrypted = file.read()
            fernet = Fernet(self.key)
            decrypted = fernet.decrypt(encrypted).decode('utf-8')
            return json.loads(decrypted)
        except Exception:
            return None

    @staticmethod
    def _validate_config(config: Dict[str, Any]) -> bool:
        required = ['dbname', 'user', 'password', 'host', 'port']
        if not all(config.get(field) for field in required):
            return False
        try:
            port = int(config['port'])
            return 1 <= port <= 65535
        except (ValueError, TypeError):
            return False

    @staticmethod
    def create_connection(config: DBConfig) -> Optional[psycopg2.extensions.connection]:
        try:
            connection = psycopg2.connect(
                dbname=config.dbname,
                user=config.user,
                password=config.password,
                host=config.host,
                port=config.port,
                connect_timeout=config.timeout
            )
            connection.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
            return connection
        except Exception as e:
            logger.error("Connection error: %s", e)
            return None

    def prompt_user_input(self) -> Optional[DBConfig]:
        print("\n🔐 PostgreSQL Connection Setup")
        print("=" * 40)
        try:
            config_dict = {
                "dbname": input("Database name [sdn_mfa_db]: ").strip() or "sdn_mfa_db",
                "user": input("Username [sdn_user]: ").strip() or "sdn_user",
                "password": getpass.getpass("Password: "),
                "host": "localhost",
                "port": input("Port [5432]: ").strip() or "5432",
                "timeout": 10
            }

            if not self._validate_config(config_dict):
                print("❌ Invalid configuration")
                return None

            config = DBConfig(**config_dict)

            if self.test_connection(config):
                if input("💾 Save credentials? (y/n): ").lower() == 'y':
                    self.encrypt_data(config_dict)
                    print("✅ Credentials saved")
                return config
            else:
                print("❌ Connection test failed")
        except KeyboardInterrupt:
            print("\nℹ️  Cancelled")
        except Exception as e:
            print(f"❌ Error: {e}")
        return None

    def load_config(self) -> Optional[DBConfig]:
        env_config = {
            "dbname": os.getenv("DB_NAME"),
            "user": os.getenv("DB_USER"),
            "password": os.getenv("DB_PASSWORD"),
            "host": "localhost",
            "port": os.getenv("DB_PORT", "5432"),
            "timeout": 10
        }

        if all([env_config["dbname"], env_config["user"], env_config["password"]]):
            if self._validate_config(env_config):
                return DBConfig(**env_config)

        encrypted = self.decrypt_data()
        if encrypted and self._validate_config(encrypted):
            encrypted["host"] = "localhost"
            encrypted["timeout"] = 10
            return DBConfig(**encrypted)
        return self.prompt_user_input()

    def test_connection(self, config: DBConfig) -> bool:
        conn = self.create_connection(config)
        if not conn:
            return False
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                return cur.fetchone()[0] == 1
        except Exception:
            return False
        finally:
            conn.close()

_pool_manager = ConnectionPoolManager()


def get_db_connection() -> Optional[psycopg2.extensions.connection]:
    global _pool_manager
    if _pool_manager._pool is None:
        manager = DBManager()
        config = manager.load_config()
        if config:
            logger.info(f"Initializing pool with host={config.host}, port={config.port}")
            _pool_manager.initialize(config)
        else:
            logger.error("Failed to load database configuration")
            return None

    conn = _pool_manager.get_connection()
    if conn is None:
        logger.error("Failed to get connection from pool. Pool stats: %s", _pool_manager.get_stats())
    return conn


def release_db_connection(conn, close: bool = False):
    global _pool_manager
    _pool_manager.return_connection(conn, close)


def get_pool_stats():
    global _pool_manager
    return _pool_manager.get_stats()


def create_or_migrate_schema():
    conn = get_db_connection()
    if not conn:
        print("❌ Database connection failed")
        return False

    try:
        try:
            from SDNMFA.database.models import SCHEMA_QUERIES
        except ImportError:
            from models import SCHEMA_QUERIES

        with conn.cursor() as cur:
            for query in SCHEMA_QUERIES:
                try:
                    cur.execute(query)
                except Exception as e:
                    if "already exists" not in str(e):
                        logger.warning("Query warning: %s", e)

        conn.commit()
        print("✅ Database schema is up to date")
        return True

    except Exception as e:
        logger.error("Migration error: %s", e)
        print(f"❌ Migration failed: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        release_db_connection(conn)


class DatabaseConnection:

    def __init__(self):
        self.conn = None

    def __enter__(self):
        self.conn = get_db_connection()
        if not self.conn:
            raise ConnectionError("Failed to get database connection")
        return self.conn

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            if exc_type is not None:
                try:
                    self.conn.rollback()
                except:
                    pass
                release_db_connection(self.conn, close=True)
            else:
                try:
                    self.conn.commit()
                except:
                    pass
                release_db_connection(self.conn, close=False)
def close_all_connections():
    """Close all database connections"""
    global _pool_manager
    if '_pool_manager' in globals():
        _pool_manager.close_all()
        logger.info("All database connections closed")


import traceback


def close_all(self):
    if self._pool and not self._closed:
        try:
            logger.warning("⚠️ POOL BEING CLOSED! Call stack:")
            for line in traceback.format_stack():
                logger.warning(line.strip())

            self._closed = True
            self._pool.closeall()
            logger.info("Connection pool closed")
        except Exception as e:
            logger.error("Error closing pool: %s", e)
        finally:
            self._pool = None
            self._connection_count = 0
