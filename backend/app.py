# Standard library imports
import json
import os
import secrets
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

# Third-party imports
import jwt
import qrcode
import requests
from flask import Flask, jsonify, request, send_file, send_from_directory, redirect
from flask_cors import CORS
from sqlalchemy import (
    create_engine, Column, Integer, String, Text, DateTime,
    ForeignKey, JSON, Boolean, and_, or_, text
)
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, scoped_session
from werkzeug.utils import secure_filename


def create_app():
    # ===================== Configuration Constants =====================
    # Flask configuration
    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), '..', 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

    # Feishu configuration
    FEISHU_APP_ID = os.getenv("FEISHU_APP_ID", "cli_a84d36f557729013")
    FEISHU_APP_SECRET = os.getenv("FEISHU_APP_SECRET", "ZebTrPQlsZKHOA2nJeAv0gjvotAqOiGf")
    FEISHU_REDIRECT_URI = os.getenv(
        "FEISHU_REDIRECT_URI",
        "http://1.13.176.116:5011/api/auth/feishu/callback"
    )

    # JWT configuration
    JWT_SECRET = os.getenv("JWT_SECRET", "fixed_jwt_secret_key_here_32_chars_minimum")
    JWT_ALGORITHM = "HS256"

    # Database configuration
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///instrument_reservation.db")
    DB_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "20"))
    DB_MAX_OVERFLOW = int(os.getenv("DB_MAX_OVERFLOW", "30"))
    DB_POOL_RECYCLE = 3600
    DB_POOL_TIMEOUT = 60

    # Timezone configuration
    CN_OFFSET = timedelta(hours=8)

    # ===================== Flask App Setup =====================
    app = Flask(__name__)

    # Session configuration
    app.config.update({
        'SESSION_COOKIE_SECURE': False,  # Set to False to avoid ngrok issues
        'SESSION_COOKIE_HTTPONLY': True,
        'SESSION_COOKIE_SAMESITE': 'Lax',
        'UPLOAD_FOLDER': UPLOAD_FOLDER,
        'MAX_CONTENT_LENGTH': MAX_CONTENT_LENGTH,
    })

    CORS(app, supports_credentials=True)

    # ===================== Database Setup =====================
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        pool_size=DB_POOL_SIZE,
        max_overflow=DB_MAX_OVERFLOW,
        pool_recycle=DB_POOL_RECYCLE,
        pool_timeout=DB_POOL_TIMEOUT,
        echo=os.getenv("SQLALCHEMY_ECHO", "0") == "1",
        connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
    )

    Session = scoped_session(sessionmaker(bind=engine, expire_on_commit=False))
    _SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    Base = declarative_base()

    def now_cn():
        # 返回北京时间的“当前时间”（保持 naive，整个项目按本地北京时解释）
        return datetime.utcnow() + CN_OFFSET

    # ===================== Feishu Bot helpers =====================
    _tenant_access_token_cache = {"token": None, "expire_at": 0}
    FEISHU_API_BASE = "https://open.feishu.cn/open-apis"
    FEISHU_TOKEN_URL = f"{FEISHU_API_BASE}/auth/v3/tenant_access_token/internal"
    FEISHU_MESSAGE_URL = f"{FEISHU_API_BASE}/im/v1/messages"
    FEISHU_TIMEOUT = 10

    # 更新已发送卡片：/im/v1/messages/{message_id}/card
    def update_feishu_card(open_message_id: str, card: dict, update_token: str) -> bool:
        """使用回调提供的 token 更新原消息卡片内容（有效期30分钟，最多2次）。
        传入的是 open_message_id，需要在请求中声明 message_id_type=open_message_id。
        """
        if not open_message_id or not card or not update_token:
            return False

        access_token = get_tenant_access_token()
        if not access_token:
            return False

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json; charset=utf-8",
            # 按飞书规范携带卡片更新 token
            "X-Lark-Card-Token": update_token,
        }
        # 指定使用 open_message_id 类型
        url = f"{FEISHU_MESSAGE_URL}/{open_message_id}/card?message_id_type=open_message_id"
        payload = {"card": card}
        try:
            resp = requests.put(url, headers=headers, json=payload, timeout=FEISHU_TIMEOUT)
            resp.raise_for_status()
            result = resp.json()
            if result.get("code") == 0:
                return True
            # 回退：若上面失败，尝试按普通 message_id（极少数情况下回调给的是 message_id）
            try:
                url2 = f"{FEISHU_MESSAGE_URL}/{open_message_id}/card"
                resp2 = requests.put(url2, headers=headers, json=payload, timeout=FEISHU_TIMEOUT)
                resp2.raise_for_status()
                result2 = resp2.json()
                return result2.get("code") == 0
            except Exception:
                return False
        except Exception:
            return False

    def get_tenant_access_token() -> str:
        """获取飞书租户访问令牌，带缓存机制"""
        now_ts = int(time.time())
        if (_tenant_access_token_cache["token"] and
                now_ts < _tenant_access_token_cache["expire_at"] - 60):
            return _tenant_access_token_cache["token"]

        try:
            response = requests.post(
                FEISHU_TOKEN_URL,
                json={"app_id": FEISHU_APP_ID, "app_secret": FEISHU_APP_SECRET},
                timeout=FEISHU_TIMEOUT
            )
            response.raise_for_status()

            data = response.json()
            if data.get("code") == 0:
                token = data.get("tenant_access_token")
                ttl = int(data.get("expire", 3600))
                _tenant_access_token_cache["token"] = token
                _tenant_access_token_cache["expire_at"] = now_ts + ttl
                return token
            else:
                print(f"获取飞书token失败: {data.get('msg', 'Unknown error')}")
        except requests.RequestException as e:
            print(f"获取飞书token网络错误: {e}")
        except Exception as e:
            print(f"获取飞书token未知错误: {e}")

        return None

    def send_feishu_text_to_user(feishu_user_id: str, text: str) -> bool:
        """发送飞书文本消息给用户"""
        if not feishu_user_id or not text:
            return False

        access_token = get_tenant_access_token()
        if not access_token:
            print("未获取到飞书access_token")
            return False

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        data = {
            "receive_id": feishu_user_id,
            "msg_type": "text",
            "content": json.dumps({"text": text})
        }

        try:
            response = requests.post(
                f"{FEISHU_MESSAGE_URL}?receive_id_type=user_id",
                headers=headers,
                json=data,
                timeout=FEISHU_TIMEOUT
            )
            response.raise_for_status()

            result = response.json()
            if result.get("code") == 0:
                print("飞书消息发送成功")
                return True
            else:
                print(f"飞书消息发送失败: {result.get('msg', 'Unknown error')}")
        except requests.RequestException as e:
            print(f"飞书消息发送网络错误: {e}")
        except Exception as e:
            print(f"飞书消息发送未知错误: {e}")

        return False

    def build_action_token(reservation_id: int, keeper_id: int, action: str, minutes_valid: int = 60) -> str:
        """构建飞书操作令牌"""
        payload = {
            "rid": reservation_id,
            "kid": keeper_id,
            "act": action,
            "exp": int(time.time()) + minutes_valid * 60,
            "typ": "feishu_action_v1",
        }
        return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    def send_feishu_approval_card_to_keeper(reservation: "Reservation") -> bool:
        """发送飞书审批卡片给保管员"""
        # Use an independent non-scoped session to avoid detaching objects in current request
        local_s = _SessionLocal()
        try:
            inst = local_s.query(Instrument).get(reservation.instrument_id)
            keeper = local_s.query(User).get(getattr(inst, "keeper_id", None) or 0)
            reserver = local_s.query(User).get(reservation.user_id)
        finally:
            local_s.close()

        if not keeper or not keeper.feishu_user_id:
            print("保管员不存在或未绑定飞书账号")
            return False

        access_token = get_tenant_access_token()
        if not access_token:
            print("未获取到飞书access_token")
            return False

        # Build approve/reject links with signed token
        base_url = (request.url_root or "").rstrip("/")
        approve_token = build_action_token(reservation.id, keeper.id, "approve")
        reject_token = build_action_token(reservation.id, keeper.id, "reject")
        approve_url = f"{base_url}/api/feishu/action?token={approve_token}"
        reject_url = f"{base_url}/api/feishu/action?token={reject_token}"

        # Format time strings
        start_str = reservation.start_time.strftime("%Y-%m-%d %H:%M")
        end_str = reservation.end_time.strftime("%Y-%m-%d %H:%M")
        reserver_name = reserver.name if reserver else "未知用户"
        instrument_name = inst.name if inst else "未知仪器"

        card = {
            "schema": "2.0",
            "config": {"wide_screen_mode": True},
            "header": {
                "title": {
                    "tag": "plain_text",
                    "content": "仪器预约待审核"
                }
            },
            "body": {
                "elements": [
                    {
                        "tag": "div",
                        "text": {
                            "tag": "lark_md",
                            "content": f"**申请人：**{reserver_name}\n**仪器：**{instrument_name}\n**时段：**{start_str} - {end_str}"
                        }
                    },
                    {
                        "tag": "button",
                        "element_id": "approve_btn",
                        "type": "primary",
                        "text": {
                            "tag": "plain_text",
                            "content": "同意"
                        },
                        "behaviors": [
                            {
                                "type": "callback",
                                "value": {
                                    "reservation_id": reservation.id,
                                    "keeper_id": keeper.id,
                                    "action": "approve"
                                }
                            }
                        ]
                    },
                    {
                        "tag": "button",
                        "element_id": "reject_btn",
                        "type": "default",
                        "text": {
                            "tag": "plain_text",
                            "content": "驳回"
                        },
                        "behaviors": [
                            {
                                "type": "callback",
                                "value": {
                                    "reservation_id": reservation.id,
                                    "keeper_id": keeper.id,
                                    "action": "reject"
                                }
                            }
                        ]
                    }
                ]
            }
        }

        try:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
            payload = {
                "receive_id": keeper.feishu_user_id,
                "msg_type": "interactive",
                "content": json.dumps(card)
            }

            response = requests.post(
                f"{FEISHU_MESSAGE_URL}?receive_id_type=user_id",
                headers=headers,
                json=payload,
                timeout=FEISHU_TIMEOUT
            )
            response.raise_for_status()

            result = response.json()
            if result.get("code") == 0:
                print("飞书审批卡片发送成功")
                return True
            else:
                print(f"飞书审批卡片发送失败: {result.get('msg', 'Unknown error')}")
        except requests.RequestException as e:
            print(f"飞书审批卡片发送网络错误: {e}")
        except Exception as e:
            print(f"飞书审批卡片发送未知错误: {e}")

        return False

    def build_status_card(reservation: "Reservation", instrument: "Instrument", action: str) -> dict:
        """构建状态卡片，显示审批结果"""
        from datetime import datetime

        # 获取预约人信息
        s = get_session()
        try:
            reserver = s.query(User).get(reservation.user_id)
            reserver_name = reserver.name if reserver else "未知用户"
        finally:
            s.close()

        # 格式化时间
        start_str = reservation.start_time.strftime("%Y-%m-%d %H:%M")
        end_str = reservation.end_time.strftime("%Y-%m-%d %H:%M")
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M")

        # 根据状态确定显示内容
        if reservation.status == "approved":
            status_text = "✅ 已同意"
            status_color = "green"
        elif reservation.status == "rejected":
            status_text = "❌ 已驳回"
            status_color = "red"
        else:
            status_text = "⏳ 待处理"
            status_color = "orange"

        card = {
            "schema": "2.0",
            "config": {"wide_screen_mode": True},
            "header": {
                "title": {
                    "tag": "plain_text",
                    "content": "仪器预约审核结果"
                }
            },
            "body": {
                "elements": [
                    {
                        "tag": "div",
                        "text": {
                            "tag": "lark_md",
                            "content": f"**申请人：**{reserver_name}\n**仪器：**{instrument.name if instrument else '未知仪器'}\n**时段：**{start_str} - {end_str}"
                        }
                    },
                    {
                        "tag": "div",
                        "text": {
                            "tag": "lark_md",
                            "content": f"**状态：** {status_text}\n**处理时间：** {current_time}"
                        }
                    }
                ]
            }
        }

        return card

    class Instrument(Base):
        __tablename__ = "instruments"
        id = Column(Integer, primary_key=True)
        name = Column(String(255), nullable=False)
        slot_minutes = Column(Integer, default=15)
        asset_code = Column(String(255))
        factory_code = Column(String(255))
        model = Column(String(255))
        brand = Column(String(255))
        category = Column(String(255))
        quantity = Column(Integer, default=1)
        location = Column(String(255))
        keeper_unit = Column(String(255))
        keeper_name = Column(String(255))
        keeper_phone = Column(String(64))
        purpose = Column(Text)
        notes = Column(Text)
        booking_notes = Column(Text)

        # 仪器状态和权限控制
        status = Column(String(32), default="active")  # active/suspended/maintenance
        keeper_id = Column(Integer, ForeignKey("users.id"))  # 仪器保管人ID
        requires_approval = Column(String(8), default="false")  # 是否需要审批
        booking_enabled = Column(String(8), default="true")  # 是否允许预约
        booking_start_time = Column(String(8))  # 预约开始时间 HH:MM
        booking_end_time = Column(String(8))  # 预约结束时间 HH:MM

        # admin only
        vendor_company = Column(String(255))
        price = Column(Integer)
        production_date = Column(DateTime)
        start_use_date = Column(DateTime)
        warranty_years = Column(Integer)
        warranty_company = Column(String(255))
        admin_notes = Column(Text)
        photo_url = Column(String(1024))
        qrcode_url = Column(String(1024))

        reservations = relationship("Reservation", back_populates="instrument")
        keeper = relationship("User", foreign_keys=[keeper_id])

    class User(Base):
        __tablename__ = "users"
        id = Column(Integer, primary_key=True)
        name = Column(String(255), nullable=False)
        employee_no = Column(String(255))
        phone = Column(String(64))
        type = Column(String(32), nullable=False, default="internal")  # internal/external
        role = Column(String(32), nullable=False, default="user")  # super_admin/admin/user
        is_keeper = Column(Boolean, default=False)  # 是否为保管员
        allowed_windows = Column(JSON, default=list)  # list of {weekday: 0-6, start:"HH:MM", end:"HH:MM"}

        # 权限控制字段
        is_active = Column(String(8), default="active")  # active/suspended
        created_by = Column(Integer, ForeignKey("users.id"))  # 创建者ID
        permissions = Column(JSON, default=dict)  # 自定义权限配置

        # 飞书集成字段
        feishu_user_id = Column(String(255), unique=True)  # 飞书用户ID
        feishu_union_id = Column(String(255))  # 飞书Union ID
        feishu_open_id = Column(String(255))  # 飞书Open ID
        avatar_url = Column(String(1024))  # 头像URL
        email = Column(String(255))  # 邮箱

        # 时间戳
        created_at = Column(DateTime, default=now_cn)
        last_login_at = Column(DateTime)

        reservations = relationship("Reservation", back_populates="user")
        created_users = relationship("User", remote_side=[id])  # 创建的用户

    # 保持向后兼容的Employee表别名
    Employee = User

    class Reservation(Base):
        __tablename__ = "reservations"
        id = Column(Integer, primary_key=True)
        instrument_id = Column(Integer, ForeignKey("instruments.id"), nullable=False)
        user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
        start_time = Column(DateTime, nullable=False)
        end_time = Column(DateTime, nullable=False)
        status = Column(String(32), default="pending")  # pending/approved/rejected/cancelled
        created_at = Column(DateTime, default=now_cn)

        instrument = relationship("Instrument", back_populates="reservations")
        user = relationship("User", back_populates="reservations")

        # 保持向后兼容
        @property
        def employee_id(self):
            return self.user_id

        @employee_id.setter
        def employee_id(self, value):
            self.user_id = value

        @property
        def employee(self):
            return self.user

    class MaintenanceRecord(Base):
        __tablename__ = "maintenance_records"
        id = Column(Integer, primary_key=True)
        instrument_id = Column(Integer, ForeignKey("instruments.id"), nullable=False)
        # 历史兼容：有的库是 user_id NOT NULL；新版本使用 created_by。
        # 两个字段都声明，迁移时互相回填，插入时同时写入。
        created_by = Column(Integer, ForeignKey("users.id"))
        user_id = Column(Integer, ForeignKey("users.id"))
        # 新增：支持维护日期范围；保留 maintenance_date 兼容旧数据
        maintenance_date = Column(DateTime)
        maintenance_start = Column(DateTime)
        maintenance_end = Column(DateTime)
        maintenance_type = Column(String(64), default="general")  # general/repair/calibration/inspection
        description = Column(Text)
        status = Column(String(32), default="done")  # done/pending
        created_at = Column(DateTime, default=now_cn)

        # 轻关系（无需反向）

    Base.metadata.create_all(engine)

    # lightweight migration: ensure slot_minutes exists (SQLite/MySQL)
    with engine.connect() as conn:
        try:
            conn.execute(
                "ALTER TABLE instruments ADD COLUMN slot_minutes INT DEFAULT 15"
            )
        except Exception:
            pass

        # 迁移employees表到users表
        try:
            # 检查是否存在users表
            result = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='users'"))
            if not result.fetchone():
                # 创建users表
                conn.execute(text("""
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY,
                        name VARCHAR(255) NOT NULL,
                        employee_no VARCHAR(255),
                        phone VARCHAR(64),
                        type VARCHAR(32) NOT NULL DEFAULT 'internal',
                        role VARCHAR(32) NOT NULL DEFAULT 'user',
                        allowed_windows JSON DEFAULT '[]',
                        is_active VARCHAR(8) DEFAULT 'active',
                        created_by INTEGER,
                        permissions JSON DEFAULT '{}',
                        feishu_user_id VARCHAR(255) UNIQUE,
                        feishu_union_id VARCHAR(255),
                        feishu_open_id VARCHAR(255),
                        avatar_url VARCHAR(1024),
                        email VARCHAR(255),
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        last_login_at DATETIME
                    )
                """))

                # 从employees表迁移数据
                conn.execute(text("""
                    INSERT INTO users (id, name, employee_no, phone, type, allowed_windows, created_at)
                    SELECT id, name, employee_no, phone, type, allowed_windows, datetime('now')
                    FROM employees
                """))

                # 更新reservations表的外键
                conn.execute(text("ALTER TABLE reservations ADD COLUMN user_id INTEGER"))
                conn.execute(text("UPDATE reservations SET user_id = employee_id"))
                conn.execute(text("ALTER TABLE reservations DROP COLUMN employee_id"))
            else:
                # 如果users表已存在，添加新字段
                try:
                    conn.execute(text("ALTER TABLE users ADD COLUMN is_active VARCHAR(8) DEFAULT 'active'"))
                except Exception:
                    pass
                try:
                    conn.execute(text("ALTER TABLE users ADD COLUMN created_by INTEGER"))
                except Exception:
                    pass
                try:
                    conn.execute(text("ALTER TABLE users ADD COLUMN permissions JSON DEFAULT '{}'"))
                except Exception:
                    pass

        except Exception as e:
            print(f"Migration error: {e}")
            pass

        # 添加仪器表的新字段
        try:
            conn.execute(text("ALTER TABLE instruments ADD COLUMN status VARCHAR(32) DEFAULT 'active'"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE instruments ADD COLUMN keeper_id INTEGER"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE instruments ADD COLUMN requires_approval VARCHAR(8) DEFAULT 'false'"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE instruments ADD COLUMN booking_enabled VARCHAR(8) DEFAULT 'true'"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE instruments ADD COLUMN booking_start_time VARCHAR(8)"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE instruments ADD COLUMN booking_end_time VARCHAR(8)"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE instruments ADD COLUMN keeper_name VARCHAR(255)"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE instruments ADD COLUMN keeper_phone VARCHAR(64)"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE instruments ADD COLUMN keeper_unit VARCHAR(255)"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE instruments ADD COLUMN purpose TEXT"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE instruments ADD COLUMN notes TEXT"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE instruments ADD COLUMN booking_notes TEXT"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE instruments ADD COLUMN asset_code VARCHAR(255)"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE instruments ADD COLUMN factory_code VARCHAR(255)"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE instruments ADD COLUMN qrcode_url VARCHAR(1024)"))
        except Exception:
            pass

        # ensure maintenance_records exists (SQLite/MySQL)
        try:
            conn.execute(text("SELECT 1 FROM maintenance_records LIMIT 1"))
            # 表存在时，补齐缺失列，并进行双向回填
            cols = [row[1] for row in conn.execute(text("PRAGMA table_info(maintenance_records)"))]
            if "created_by" not in cols:
                conn.execute(text("ALTER TABLE maintenance_records ADD COLUMN created_by INTEGER"))
            if "user_id" not in cols:
                conn.execute(text("ALTER TABLE maintenance_records ADD COLUMN user_id INTEGER"))
            # 强制一次性移除 title 列：通过 PRAGMA user_version 控制，仅执行一次
            try:
                current_version = list(conn.execute(text("PRAGMA user_version")))[0][0]
            except Exception:
                current_version = 0
            if current_version < 3:
                try:
                    conn.execute(text("PRAGMA foreign_keys=off"))
                    conn.execute(text(
                        """
                        CREATE TABLE IF NOT EXISTS maintenance_records_new (
                            id INTEGER PRIMARY KEY,
                            instrument_id INTEGER NOT NULL,
                            created_by INTEGER,
                            user_id INTEGER,
                            maintenance_date DATETIME,
                            maintenance_start DATETIME,
                            maintenance_end DATETIME,
                            maintenance_type VARCHAR(64) DEFAULT 'general',
                            description TEXT,
                            status VARCHAR(32) DEFAULT 'done',
                            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY(instrument_id) REFERENCES instruments(id),
                            FOREIGN KEY(created_by) REFERENCES users(id),
                            FOREIGN KEY(user_id) REFERENCES users(id)
                        )
                        """
                    ))
                    conn.execute(text(
                        """
                        INSERT INTO maintenance_records_new (
                            id, instrument_id, created_by, user_id, maintenance_date, maintenance_start, maintenance_end, maintenance_type, description, status, created_at
                        )
                        SELECT 
                            id, instrument_id, created_by, user_id, maintenance_date, maintenance_start, maintenance_end, maintenance_type, description, status, created_at
                        FROM maintenance_records
                        """
                    ))
                    conn.execute(text("DROP TABLE maintenance_records"))
                    conn.execute(text("ALTER TABLE maintenance_records_new RENAME TO maintenance_records"))
                    conn.execute(text("PRAGMA user_version = 3"))
                except Exception:
                    pass
                finally:
                    try:
                        conn.execute(text("PRAGMA foreign_keys=on"))
                    except Exception:
                        pass
            if "maintenance_date" not in cols:
                conn.execute(text("ALTER TABLE maintenance_records ADD COLUMN maintenance_date DATETIME"))
            if "maintenance_start" not in cols:
                conn.execute(text("ALTER TABLE maintenance_records ADD COLUMN maintenance_start DATETIME"))
            if "maintenance_end" not in cols:
                conn.execute(text("ALTER TABLE maintenance_records ADD COLUMN maintenance_end DATETIME"))
            # 其他字段
            if "maintenance_type" not in cols:
                conn.execute(
                    text("ALTER TABLE maintenance_records ADD COLUMN maintenance_type VARCHAR(64) DEFAULT 'general'"))
            if "description" not in cols:
                conn.execute(text("ALTER TABLE maintenance_records ADD COLUMN description TEXT"))
            if "status" not in cols:
                conn.execute(text("ALTER TABLE maintenance_records ADD COLUMN status VARCHAR(32) DEFAULT 'done'"))
            if "created_at" not in cols:
                conn.execute(
                    text("ALTER TABLE maintenance_records ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP"))
            # 尝试互相回填（尽力而为）
            try:
                conn.execute(text(
                    "UPDATE maintenance_records SET created_by = user_id WHERE created_by IS NULL AND user_id IS NOT NULL"))
            except Exception:
                pass
            try:
                conn.execute(text(
                    "UPDATE maintenance_records SET user_id = created_by WHERE user_id IS NULL AND created_by IS NOT NULL"))
            except Exception:
                pass
        except Exception:
            # 表不存在则创建（包含 maintenance_date/maintenance_start/maintenance_end）
            try:
                conn.execute(text(
                    """
                    CREATE TABLE maintenance_records (
                        id INTEGER PRIMARY KEY,
                        instrument_id INTEGER NOT NULL,
                        created_by INTEGER,
                        user_id INTEGER,
                        maintenance_date DATETIME,
                        maintenance_start DATETIME,
                        maintenance_end DATETIME,
                        maintenance_type VARCHAR(64) DEFAULT 'general',
                        description TEXT,
                        status VARCHAR(32) DEFAULT 'done',
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY(instrument_id) REFERENCES instruments(id),
                        FOREIGN KEY(created_by) REFERENCES users(id),
                        FOREIGN KEY(user_id) REFERENCES users(id)
                    )
                    """
                ))
            except Exception:
                pass

        # 独立保障：确保 reservations 表包含 user_id 列，并尽量回填
        try:
            cols = [row[1] for row in conn.execute(text("PRAGMA table_info(reservations)"))]
            if "user_id" not in cols:
                conn.execute(text("ALTER TABLE reservations ADD COLUMN user_id INTEGER"))
                # 回填：若存在旧列 employee_id，则迁移其值
                if "employee_id" in cols:
                    try:
                        conn.execute(text("UPDATE reservations SET user_id = employee_id WHERE user_id IS NULL"))
                    except Exception:
                        pass
            # 如果 employee_id 列仍然存在且为 NOT NULL，需要处理
            if "employee_id" in cols:
                try:
                    # 先确保所有记录都有 user_id 值
                    conn.execute(text("UPDATE reservations SET user_id = employee_id WHERE user_id IS NULL"))
                    # 然后删除 employee_id 列（SQLite 不支持直接删除列，需要重建表）
                    conn.execute(text("""
                        CREATE TABLE reservations_new (
                            id INTEGER PRIMARY KEY,
                            instrument_id INTEGER NOT NULL,
                            user_id INTEGER NOT NULL,
                            start_time DATETIME NOT NULL,
                            end_time DATETIME NOT NULL,
                            status VARCHAR(32) DEFAULT 'pending',
                            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY(instrument_id) REFERENCES instruments(id),
                            FOREIGN KEY(user_id) REFERENCES users(id)
                        )
                    """))
                    conn.execute(text("""
                        INSERT INTO reservations_new (id, instrument_id, user_id, start_time, end_time, status, created_at)
                        SELECT id, instrument_id, user_id, start_time, end_time, status, created_at
                        FROM reservations
                    """))
                    conn.execute(text("DROP TABLE reservations"))
                    conn.execute(text("ALTER TABLE reservations_new RENAME TO reservations"))
                except Exception as e:
                    print(f"Migration reservations table error: {e}")
        except Exception as e:
            print(f"Ensure reservations.user_id error: {e}")

    def get_session():
        return Session()

    @app.teardown_appcontext
    def cleanup_session(exception=None):
        """确保数据库连接正确关闭"""
        Session.remove()

    # ===================== Caching System =====================
    # 用户缓存和JWT token管理
    user_cache = {}
    token_cache = {}
    cache_lock = threading.Lock()
    CACHE_EXPIRE_TIME = 300  # 5分钟缓存过期

    def get_cached_user(user_id):
        """从缓存获取用户信息"""
        with cache_lock:
            if user_id in user_cache:
                user_data, timestamp = user_cache[user_id]
                if time.time() - timestamp < CACHE_EXPIRE_TIME:
                    return user_data
                else:
                    # 缓存过期，删除
                    del user_cache[user_id]
        return None

    def cache_user(user_id, user_data):
        """缓存用户信息"""
        with cache_lock:
            user_cache[user_id] = (user_data, time.time())

    def get_cached_token(token):
        """从缓存获取token信息"""
        with cache_lock:
            if token in token_cache:
                user_data, timestamp = token_cache[token]
                if time.time() - timestamp < CACHE_EXPIRE_TIME:
                    return user_data
                else:
                    # 缓存过期，删除
                    del token_cache[token]
        return None

    def cache_token(token, user_data):
        """缓存token信息"""
        with cache_lock:
            token_cache[token] = (user_data, time.time())

    def clear_user_cache(user_id):
        """清除指定用户的缓存"""
        with cache_lock:
            # 清除用户缓存
            if user_id in user_cache:
                del user_cache[user_id]

            # 清除该用户相关的token缓存
            tokens_to_remove = []
            for token, (cached_user, timestamp) in token_cache.items():
                if hasattr(cached_user, 'id') and cached_user.id == user_id:
                    tokens_to_remove.append(token)

            for token in tokens_to_remove:
                del token_cache[token]

    # ===================== Utility Functions =====================
    def allowed_file(filename):
        """检查文件扩展名是否允许"""
        if not filename or '.' not in filename:
            return False
        return filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

    def ensure_upload_folder():
        """确保上传文件夹存在"""
        upload_folder = app.config['UPLOAD_FOLDER']
        if not os.path.exists(upload_folder):
            try:
                os.makedirs(upload_folder, exist_ok=True)
            except OSError as e:
                print(f"创建上传文件夹失败: {e}")
                return None
        return upload_folder

    def get_current_user():
        """从JWT token或headers获取当前用户信息"""
        # 优先从JWT token获取
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]

            # 先检查token缓存
            cached_user = get_cached_token(token)
            if cached_user:
                return cached_user

            try:
                payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                user_id = payload.get("user_id")
                if user_id:
                    return _get_user_by_id(user_id, token)
            except jwt.InvalidTokenError:
                pass

        # 向后兼容：从headers获取
        role = request.headers.get("X-Role", "user")
        try:
            user_id = int(request.headers.get("X-User-Id", "0"))
        except ValueError:
            user_id = 0

        if user_id:
            return _get_user_by_id(user_id)

        # 创建临时用户对象用于向后兼容
        class TempUser:
            def __init__(self, role, user_id):
                self.role = role
                self.id = user_id
                self.name = f"User {user_id}"

        return TempUser(role, user_id)

    def _get_user_by_id(user_id, token=None):
        """根据用户ID获取用户信息，带缓存"""
        # 检查用户缓存
        cached_user = get_cached_user(user_id)
        if cached_user:
            if token:
                cache_token(token, cached_user)
            return cached_user

        # 从数据库查询
        s = get_session()
        try:
            user = s.query(User).get(user_id)
            if user:
                # 缓存用户和token
                cache_user(user_id, user)
                if token:
                    cache_token(token, user)
                return user
        finally:
            s.close()

        return None

    def get_role():
        """向后兼容函数"""
        user = get_current_user()
        return user.role, user.id

    # ===================== Permission System =====================
    def require_auth():
        """要求用户已认证"""
        user = get_current_user()
        if not hasattr(user, 'feishu_user_id') or not user.feishu_user_id:
            return jsonify({"error": "authentication_required"}), 401
        return None

    def require_admin():
        """要求管理员权限"""
        user = get_current_user()
        if user.role != "admin":
            return jsonify({"error": "admin_only"}), 403
        return None

    def require_admin_or_super_admin():
        """要求管理员或超级管理员权限"""
        user = get_current_user()
        if user.role not in ["admin", "super_admin"]:
            return jsonify({"error": "admin_or_super_admin_required"}), 403
        return None

    def require_super_admin():
        """要求超级管理员权限"""
        user = get_current_user()
        if user.role != "super_admin":
            return jsonify({"error": "super_admin_required"}), 403
        return None

    def require_keeper_or_admin():
        """要求保管员或管理员权限"""
        user = get_current_user()
        if user.role not in ["admin", "super_admin"] and not getattr(user, 'is_keeper', False):
            return jsonify({"error": "keeper_or_admin_required"}), 403
        return None

    def require_instrument_keeper(instrument_id):
        """要求是特定仪器的保管人"""
        user = get_current_user()
        s = get_session()
        instrument = s.query(Instrument).get(instrument_id)
        if not instrument:
            return jsonify({"error": "instrument_not_found"}), 404
        if instrument.keeper_id != user.id and user.role not in ["super_admin", "admin", "manager"]:
            return jsonify({"error": "instrument_keeper_required"}), 403
        return None

    def has_permission(required_role):
        """检查用户是否有指定权限"""
        user = get_current_user()
        role_hierarchy = {"user": 1, "admin": 2, "super_admin": 3}
        user_level = role_hierarchy.get(user.role, 0)
        required_level = role_hierarchy.get(required_role, 0)
        return user_level >= required_level

    def can_manage_instrument(instrument_id):
        """检查用户是否可以管理特定仪器"""
        user = get_current_user()
        if user.role in ["super_admin", "admin"]:
            return True
        # 检查是否为保管员且负责该仪器
        if getattr(user, 'is_keeper', False):
            s = get_session()
            instrument = s.query(Instrument).get(instrument_id)
            return instrument and instrument.keeper_id == user.id
        return False

    # Instruments
    @app.get("/api/instruments")
    def list_instruments():
        s = get_session()
        q = s.query(Instrument)
        keyword = request.args.get("q")
        category = request.args.get("category")
        page = int(request.args.get("page", 1))
        page_size = int(request.args.get("page_size", 10))
        manageable = request.args.get("manageable")

        if keyword:
            like = f"%{keyword}%"
            q = q.filter(or_(Instrument.name.like(like), Instrument.brand.like(like), Instrument.model.like(like)))
        if category:
            q = q.filter(Instrument.category == category)

        # 若指定manageable=true，则仅返回当前用户可以管理的仪器（管理员不受限）
        if (manageable in ["1", "true", "True"]):
            user = get_current_user()
            if user.role not in ["admin", "super_admin"] and getattr(user, 'is_keeper', False):
                q = q.filter(Instrument.keeper_id == user.id)

        # 检查是否请求分页数据
        if page > 1 or page_size != 10 or request.args.get("page") is not None:
            # 分页模式
            total = q.count()
            offset = (page - 1) * page_size
            items = q.order_by(Instrument.id.desc()).offset(offset).limit(page_size).all()

            total_pages = (total + page_size - 1) // page_size
            has_prev = page > 1
            has_next = page < total_pages

            return jsonify({
                "items": [serialize_instrument(i) for i in items],
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total": total,
                    "total_pages": total_pages,
                    "has_prev": has_prev,
                    "has_next": has_next
                }
            })
        else:
            # 兼容模式：返回所有数据
            items = q.order_by(Instrument.id.desc()).all()
            return jsonify([serialize_instrument(i) for i in items])

    @app.get("/api/instruments/<int:instrument_id>")
    def get_instrument(instrument_id: int):
        s = get_session()
        inst = s.query(Instrument).get(instrument_id)
        if not inst:
            return jsonify({"error": "not_found"}), 404
        return jsonify(serialize_instrument(inst))

    @app.post("/api/instruments")
    def create_instrument():
        # 只有管理员和超级管理员可以添加仪器
        guard = require_admin_or_super_admin()
        if guard:
            return guard
        s = get_session()
        data = request.json or {}

        # 检查用户权限，只有管理员可以设置预约刻度
        user = get_current_user()
        if "slot_minutes" in data and user.role not in ["admin", "super_admin"]:
            # 普通用户不能设置预约刻度，使用默认值
            data["slot_minutes"] = 15

        # normalize date fields (accept 'YYYY-MM-DD')
        for k in ["production_date", "start_use_date"]:
            v = data.get(k)
            if isinstance(v, str) and v:
                try:
                    data[k] = datetime.fromisoformat(v)
                except Exception:
                    # try plain date
                    try:
                        data[k] = datetime.strptime(v, "%Y-%m-%d")
                    except Exception:
                        data[k] = None
        # normalize slot_minutes
        if "slot_minutes" in data:
            try:
                data["slot_minutes"] = int(data["slot_minutes"]) or 15
            except Exception:
                data["slot_minutes"] = 15
        inst = Instrument(**data)
        s.add(inst)
        s.commit()
        # 生成并保存带仪器名的二维码图片
        try:
            inst.qrcode_url = generate_and_save_instrument_qrcode(inst)
            s.commit()
        except Exception as e:
            print(f"QR generation failed: {e}")
        return jsonify(serialize_instrument(inst))

    @app.put("/api/instruments/<int:instrument_id>")
    def update_instrument(instrument_id: int):
        # 检查权限：管理员或仪器保管人
        user = get_current_user()
        s = get_session()
        inst = s.query(Instrument).get(instrument_id)
        if not inst:
            return jsonify({"error": "not_found"}), 404

        # 检查权限：超级管理员、管理员、经理或仪器保管人
        if user.role not in ["super_admin", "admin"] and inst.keeper_id != user.id:
            return jsonify({"error": "permission_denied"}), 403

        data = request.json or {}

        # 只有管理员可以修改预约刻度
        if "slot_minutes" in data and user.role not in ["super_admin", "admin"]:
            data.pop("slot_minutes", None)

        # 只有管理员可以修改管理信息
        admin_only_fields = ["vendor_company", "price", "production_date", "start_use_date",
                             "warranty_years", "warranty_company", "admin_notes"]
        if user.role not in ["super_admin", "admin"]:
            for field in admin_only_fields:
                data.pop(field, None)

        # 非管理员禁止在通用更新接口中修改 keeper_id（需走专门接口）
        if user.role not in ["super_admin", "admin"] and "keeper_id" in data:
            data.pop("keeper_id", None)

        for k in ["production_date", "start_use_date"]:
            v = data.get(k)
            if isinstance(v, str) and v:
                try:
                    data[k] = datetime.fromisoformat(v)
                except Exception:
                    try:
                        data[k] = datetime.strptime(v, "%Y-%m-%d")
                    except Exception:
                        data[k] = None
        if "slot_minutes" in data:
            try:
                data["slot_minutes"] = int(data["slot_minutes"]) or 15
            except Exception:
                data["slot_minutes"] = 15
        old_name = inst.name
        for k, v in data.items():
            setattr(inst, k, v)
        s.commit()
        # 若名称变更或尚未生成二维码，则重新生成
        try:
            if (old_name != inst.name) or (not inst.qrcode_url):
                inst.qrcode_url = generate_and_save_instrument_qrcode(inst)
                s.commit()
        except Exception as e:
            print(f"QR regeneration failed: {e}")
        return jsonify(serialize_instrument(inst))

    @app.delete("/api/instruments/<int:instrument_id>")
    def delete_instrument(instrument_id: int):
        guard = require_admin_or_super_admin()
        if guard:
            return guard
        s = get_session()
        inst = s.query(Instrument).get(instrument_id)
        if not inst:
            return jsonify({"error": "not_found"}), 404
        # 先删除依赖记录，避免 NOT NULL 外键约束错误
        try:
            s.query(Reservation).filter(Reservation.instrument_id == instrument_id).delete(synchronize_session=False)
        except Exception:
            pass
        try:
            s.query(MaintenanceRecord).filter(MaintenanceRecord.instrument_id == instrument_id).delete(
                synchronize_session=False)
        except Exception:
            pass
        # 最后删除仪器本身
        s.delete(inst)
        s.commit()
        return jsonify({"ok": True})

    # 图片上传API
    @app.post("/api/upload/image")
    def upload_image():
        """上传图片文件"""
        guard = require_auth()
        if guard:
            return guard

        if 'file' not in request.files:
            return jsonify({"error": "no_file"}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "no_file_selected"}), 400

        if file and allowed_file(file.filename):
            # 确保上传文件夹存在
            upload_folder = ensure_upload_folder()

            # 生成唯一文件名
            filename = secure_filename(file.filename)
            file_extension = filename.rsplit('.', 1)[1].lower()
            unique_filename = f"{uuid.uuid4()}.{file_extension}"

            # 保存文件
            file_path = os.path.join(upload_folder, unique_filename)
            file.save(file_path)

            # 返回文件URL
            base_url = request.host_url.rstrip("/")
            file_url = f"{base_url}/uploads/{unique_filename}"

            return jsonify({"url": file_url, "filename": unique_filename})

        return jsonify({"error": "invalid_file_type"}), 400

    @app.get("/uploads/<filename>")
    def uploaded_file(filename):
        """提供上传的图片文件访问"""
        upload_folder = ensure_upload_folder()
        return send_from_directory(upload_folder, filename)

    # Excel export/import
    @app.get("/api/instruments/export")
    def export_instruments():
        try:
            import pandas as pd
            from io import BytesIO
        except Exception:
            return jsonify({"error": "pandas_required"}), 500
        s = get_session()
        items = s.query(Instrument).all()
        df = pd.DataFrame([serialize_instrument(i) for i in items])
        bio = BytesIO()
        df.to_excel(bio, index=False)
        bio.seek(0)
        return send_file(bio, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                         as_attachment=True, download_name="instruments.xlsx")

    @app.get("/api/reservations/export")
    def export_reservations():
        """导出预约记录到Excel"""
        try:
            import pandas as pd
            from io import BytesIO
        except Exception:
            return jsonify({"error": "pandas_required"}), 500

        s = get_session()

        # 支持通过URL参数传递token（用于飞书环境）
        token_from_url = request.args.get('token')
        if token_from_url:
            try:
                payload = jwt.decode(token_from_url, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                user_id = payload.get("user_id")
                if user_id:
                    user = s.query(User).get(user_id)
                    if user:
                        s.close()
                        s = get_session()
                    else:
                        user = get_current_user()
                else:
                    user = get_current_user()
            except jwt.InvalidTokenError:
                user = get_current_user()
        else:
            user = get_current_user()
        from sqlalchemy.orm import joinedload
        q = s.query(Reservation).options(joinedload(Reservation.user), joinedload(Reservation.instrument))

        # 应用筛选条件
        instrument_id = request.args.get("instrument_id")
        status = request.args.get("status")
        start_date = request.args.get("start_date")
        end_date = request.args.get("end_date")

        if instrument_id:
            q = q.filter(Reservation.instrument_id == int(instrument_id))
        if status:
            q = q.filter(Reservation.status == status)
        if start_date:
            start_dt = datetime.strptime(start_date, "%Y-%m-%d")
            q = q.filter(Reservation.start_time >= start_dt)
        if end_date:
            end_dt = datetime.strptime(end_date, "%Y-%m-%d")
            q = q.filter(Reservation.start_time < end_dt)

        # 权限控制：非管理员只能看到自己的预约
        if user.role not in ["admin", "super_admin"] and hasattr(user, 'id') and user.id and user.id > 0:
            q = q.filter(Reservation.user_id == user.id)

        # 获取所有匹配的记录（不分页）
        items = q.order_by(Reservation.created_at.desc()).all()

        # 准备导出数据
        export_data = []
        for r in items:
            export_data.append({
                "预约ID": r.id,
                "仪器名称": r.instrument.name if r.instrument else "未知仪器",
                "预约人": r.user.name if r.user else "未知用户",
                "开始时间": r.start_time.strftime("%Y-%m-%d %H:%M") if r.start_time else "",
                "结束时间": r.end_time.strftime("%Y-%m-%d %H:%M") if r.end_time else "",
                "状态": r.status,
                "创建时间": r.created_at.strftime("%Y-%m-%d %H:%M") if r.created_at else "",
                "预约人电话": r.user.phone if r.user and r.user.phone else "",
                "仪器位置": r.instrument.location if r.instrument and r.instrument.location else "",
            })

        df = pd.DataFrame(export_data)
        bio = BytesIO()
        df.to_excel(bio, index=False, engine='openpyxl')
        bio.seek(0)

        # 生成文件名
        now = datetime.now()
        filename = f"预约记录_{now.strftime('%Y%m%d_%H%M%S')}.xlsx"

        return send_file(bio, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                         as_attachment=True, download_name=filename)

    @app.post("/api/instruments/import")
    def import_instruments():
        guard = require_admin()
        if guard:
            return guard
        try:
            import pandas as pd
        except Exception:
            return jsonify({"error": "pandas_required"}), 500
        if "file" not in request.files:
            return jsonify({"error": "file_missing"}), 400
        f = request.files["file"]
        df = pd.read_excel(f)
        s = get_session()
        created = 0
        for _, row in df.iterrows():
            data = row.to_dict()
            if not data.get("name"):
                continue
            inst = Instrument(name=str(data.get("name")))
            for k in [
                "asset_code", "factory_code", "model", "brand", "category", "quantity", "location", "keeper_unit",
                "keeper_name", "keeper_phone", "purpose", "notes", "booking_notes", "vendor_company", "price",
                "warranty_years", "warranty_company", "admin_notes", "photo_url"
            ]:
                if k in data and not (pd.isna(data[k])):
                    setattr(inst, k, data[k])
            s.add(inst)
            created += 1
        s.commit()
        return jsonify({"created": created})

    # Employees (向后兼容)
    @app.get("/api/employees")
    def list_employees():
        s = get_session()
        items = s.query(User).order_by(User.id.desc()).all()
        return jsonify([serialize_employee(e) for e in items])

    @app.post("/api/employees")
    def create_employee():
        guard = require_admin_or_super_admin()
        if guard:
            return guard
        s = get_session()
        data = request.json or {}
        emp = User(**data)
        s.add(emp)
        s.commit()
        return jsonify(serialize_employee(emp))

    @app.put("/api/employees/<int:employee_id>")
    def update_employee(employee_id: int):
        guard = require_admin_or_super_admin()
        if guard:
            return guard
        s = get_session()
        emp = s.query(User).get(employee_id)
        if not emp:
            return jsonify({"error": "not_found"}), 404
        data = request.json or {}
        for k, v in data.items():
            setattr(emp, k, v)
        s.commit()
        return jsonify(serialize_employee(emp))

    @app.delete("/api/employees/<int:employee_id>")
    def delete_employee(employee_id: int):
        guard = require_admin()
        if guard:
            return guard
        s = get_session()
        emp = s.query(User).get(employee_id)
        if not emp:
            return jsonify({"error": "not_found"}), 404
        s.delete(emp)
        s.commit()
        return jsonify({"ok": True})

    # Reservations
    @app.get("/api/reservations")
    def list_reservations():
        s = get_session()
        user = get_current_user()
        q = s.query(Reservation)
        instrument_id = request.args.get("instrument_id")
        status = request.args.get("status")
        start_date = request.args.get("start_date")
        end_date = request.args.get("end_date")
        page = int(request.args.get("page", 1))
        page_size = int(request.args.get("page_size", 10))

        if instrument_id:
            q = q.filter(Reservation.instrument_id == int(instrument_id))
        if status:
            if status == 'all':
                # 显示所有状态的记录，不进行状态筛选
                pass
            elif status == 'default':
                # 默认状态：不显示已取消的记录
                q = q.filter(Reservation.status != 'cancelled')
            else:
                # 具体状态筛选
                q = q.filter(Reservation.status == status)
        if start_date:
            start_dt = datetime.strptime(start_date, "%Y-%m-%d")
            q = q.filter(Reservation.start_time >= start_dt)
        if end_date:
            end_dt = datetime.strptime(end_date, "%Y-%m-%d")
            q = q.filter(Reservation.start_time < end_dt)
        # 权限：
        # - 管理员/超管：可查看所有预约
        # - 保管员管理视图（manage_scope=true）：查看自己负责仪器的预约
        # - 其他情况下（我的预约）：仅查看自己的预约
        # - 未认证：返回空
        manage_scope = request.args.get("manage_scope")
        if user.role not in ["admin", "super_admin"]:
            if not getattr(user, 'id', None):
                q = q.filter(text("1=0"))
            else:
                if manage_scope in ["1", "true", "True"] and getattr(user, 'is_keeper', False):
                    q = q.join(Instrument, Instrument.id == Reservation.instrument_id).filter(
                        Instrument.keeper_id == user.id)
                else:
                    q = q.filter(Reservation.user_id == user.id)

        # 检查是否请求分页数据
        if page > 1 or page_size != 10 or request.args.get("page") is not None:
            # 分页模式，使用 joinedload 优化查询
            from sqlalchemy.orm import joinedload
            total = q.count()
            offset = (page - 1) * page_size
            items = q.options(joinedload(Reservation.user), joinedload(Reservation.instrument)).order_by(
                Reservation.created_at.desc()).offset(offset).limit(page_size).all()

            total_pages = (total + page_size - 1) // page_size
            has_prev = page > 1
            has_next = page < total_pages

            return jsonify({
                "items": [serialize_reservation(r) for r in items],
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total": total,
                    "total_pages": total_pages,
                    "has_prev": has_prev,
                    "has_next": has_next
                }
            })
        else:
            # 兼容模式：返回所有数据，使用 joinedload 优化查询
            from sqlalchemy.orm import joinedload
            items = q.options(joinedload(Reservation.user), joinedload(Reservation.instrument)).order_by(
                Reservation.created_at.desc()).all()
            return jsonify([serialize_reservation(r) for r in items])

    @app.get("/api/instruments/<int:instrument_id>/reservations")
    def list_reservations_for_instrument(instrument_id: int):
        s = get_session()
        from sqlalchemy.orm import joinedload
        q = s.query(Reservation).options(joinedload(Reservation.user), joinedload(Reservation.instrument)).filter(
            Reservation.instrument_id == instrument_id)
        items = q.order_by(Reservation.start_time.asc()).all()
        return jsonify([serialize_reservation(r) for r in items])

    @app.get("/api/instruments/<int:instrument_id>/stats")
    def get_instrument_stats(instrument_id: int):
        """获取仪器统计信息，包括预约率和下一个使用者"""
        s = get_session()
        user = get_current_user()

        # 获取日期参数
        start_date = request.args.get("start_date")
        end_date = request.args.get("end_date")

        # 查询该仪器的所有预约（不限制用户权限，用于统计）
        q = s.query(Reservation).filter(Reservation.instrument_id == instrument_id)

        if start_date:
            start_dt = datetime.strptime(start_date, "%Y-%m-%d")
            q = q.filter(Reservation.start_time >= start_dt)
        if end_date:
            end_dt = datetime.strptime(end_date, "%Y-%m-%d")
            q = q.filter(Reservation.start_time < end_dt)

        reservations = q.order_by(Reservation.start_time.asc()).all()

        # 获取仪器信息
        instrument = s.query(Instrument).get(instrument_id)
        if not instrument:
            return jsonify({"error": "instrument_not_found"}), 404

        # 计算工作时间
        work_start_hour = 8
        work_start_minute = 0
        work_end_hour = 18
        work_end_minute = 0
        if instrument.booking_start_time:
            time_parts = instrument.booking_start_time.split(':')
            work_start_hour = int(time_parts[0])
            work_start_minute = int(time_parts[1]) if len(time_parts) > 1 else 0
        if instrument.booking_end_time:
            time_parts = instrument.booking_end_time.split(':')
            work_end_hour = int(time_parts[0])
            work_end_minute = int(time_parts[1]) if len(time_parts) > 1 else 0

        slot_minutes = instrument.slot_minutes or 15
        # 计算总工作分钟数，然后除以时间段长度
        total_work_minutes = (work_end_hour * 60 + work_end_minute) - (work_start_hour * 60 + work_start_minute)
        total_slots = total_work_minutes // slot_minutes

        # 计算已预约的时间段（只计算approved状态）
        approved_reservations = [r for r in reservations if r.status == 'approved']
        booked_slots = 0
        for reservation in approved_reservations:
            # 计算每个预约占用的时间段数
            duration_minutes = (reservation.end_time - reservation.start_time).total_seconds() / 60
            slots_used = int(duration_minutes // slot_minutes)
            booked_slots += slots_used

        # 计算预约率
        booking_rate = round((booked_slots / total_slots) * 100) if total_slots > 0 else 0

        # 找到下一个使用者（忽略日期过滤，面向所有未来approved预约）
        from sqlalchemy.orm import joinedload
        now = now_cn()
        next_res_obj = (
            s.query(Reservation)
            .options(joinedload(Reservation.user))
            .filter(
                Reservation.instrument_id == instrument_id,
                Reservation.status == 'approved',
                Reservation.start_time > now,
            )
            .order_by(Reservation.start_time.asc())
            .first()
        )
        next_user = None
        if next_res_obj:
            next_user = {
                "name": getattr(getattr(next_res_obj, "user", None), "name", None) or "未知用户",
                "start_time": next_res_obj.start_time.isoformat() if next_res_obj.start_time else None,
                "end_time": next_res_obj.end_time.isoformat() if next_res_obj.end_time else None,
            }

        return jsonify({
            "booking_rate": booking_rate,
            "next_user": next_user,
            "total_slots": total_slots,
            "booked_slots": booked_slots,
            "work_start_hour": work_start_hour,
            "work_end_hour": work_end_hour,
            "slot_minutes": slot_minutes
        })

    @app.post("/api/reservations")
    def create_reservation():
        s = get_session()
        user = get_current_user()
        data = request.json or {}
        instrument_id = int(data.get("instrument_id"))
        target_user_id = int(data.get("employee_id") or user.id)
        start_time = parse_iso8601(data.get("start_time"))
        end_time = parse_iso8601(data.get("end_time"))

        if not start_time or not end_time or start_time >= end_time:
            return jsonify({"error": "invalid_time"}), 400

        # 禁止预约当前时间之前的时段（使用UTC对齐后端存储）
        if start_time < now_cn():
            return jsonify({"error": "cannot_book_past"}), 400

        if user.role not in ["admin", "super_admin"] and user.id != target_user_id:
            return jsonify({"error": "cannot_create_for_other"}), 403

        # grid enforcement by instrument slot
        inst = s.query(Instrument).get(instrument_id)
        slot = inst.slot_minutes or 15
        if (start_time.minute % slot != 0) or (end_time.minute % slot != 0):
            return jsonify({"error": f"must_align_{slot}min"}), 400

        target_user = s.query(User).get(target_user_id)
        if not target_user:
            return jsonify({"error": "user_not_found"}), 404

        # 不再区分内部/外部员工，不做时间窗口限制

        # 维护期内禁止预约
        active_maint = get_current_maintenance_for_instrument(instrument_id)
        if active_maint:
            return jsonify({"error": "instrument_in_maintenance", "maintenance": active_maint}), 423

        # conflict detection against approved or pending
        if has_conflict(s, instrument_id, start_time, end_time):
            return jsonify({"error": "time_conflict"}), 409

        # 检查仪器是否需要审批
        # 规则：
        # - 若仪器开启审批：保管员本人预约则直批通过，其余用户为待审批
        # - 若仪器未开启审批：直接通过
        requires_approval = inst.requires_approval == "true"
        is_keeper_self_booking = bool(getattr(inst, "keeper_id", None)) and (target_user_id == inst.keeper_id)

        res = Reservation(
            instrument_id=instrument_id,
            user_id=target_user_id,
            start_time=start_time,
            end_time=end_time,
            status=("approved" if (not requires_approval or is_keeper_self_booking) else "pending"),
        )
        s.add(res)
        s.commit()
        # 若需要审批，给保管员发送飞书卡片
        try:
            if res.status == "pending" and inst and getattr(inst, "keeper_id", None):
                send_feishu_approval_card_to_keeper(res)
        except Exception:
            pass
        return jsonify(serialize_reservation(res))

    @app.post("/api/reservations/<int:reservation_id>/approve")
    def approve_reservation(reservation_id: int):
        s = get_session()
        res = s.query(Reservation).get(reservation_id)
        if not res:
            return jsonify({"error": "not_found"}), 404
        # 仅允许对待审批的预约执行通过操作
        if res.status != "pending":
            return jsonify({"error": "invalid_status"}), 400
        # 权限：仅该仪器保管人可审核
        if not can_manage_instrument(res.instrument_id):
            return jsonify({"error": "permission_denied"}), 403
        if has_conflict(s, res.instrument_id, res.start_time, res.end_time, exclude_id=res.id):
            return jsonify({"error": "time_conflict"}), 409
        res.status = "approved"
        s.commit()
        from sqlalchemy.orm import joinedload
        res = s.query(Reservation).options(joinedload(Reservation.user), joinedload(Reservation.instrument)).get(
            reservation_id)
        # 通知预约人
        try:
            reserver = s.query(User).get(res.user_id)
            inst = s.query(Instrument).get(res.instrument_id)
            if reserver and reserver.feishu_user_id:
                start_str = res.start_time.strftime("%Y-%m-%d %H:%M")
                end_str = res.end_time.strftime("%Y-%m-%d %H:%M")
                send_feishu_text_to_user(reserver.feishu_user_id,
                                         f"您的仪器预约已通过：{inst.name if inst else ''}，{start_str}-{end_str}")
        except Exception:
            pass
        return jsonify(serialize_reservation(res))

    @app.post("/api/reservations/<int:reservation_id>/reject")
    def reject_reservation(reservation_id: int):
        s = get_session()
        res = s.query(Reservation).get(reservation_id)
        if not res:
            return jsonify({"error": "not_found"}), 404
        # 仅允许对待审批的预约执行驳回操作
        if res.status != "pending":
            return jsonify({"error": "invalid_status"}), 400
        # 权限：仅该仪器保管人可驳回
        if not can_manage_instrument(res.instrument_id):
            return jsonify({"error": "permission_denied"}), 403
        res.status = "rejected"
        s.commit()
        from sqlalchemy.orm import joinedload
        res = s.query(Reservation).options(joinedload(Reservation.user), joinedload(Reservation.instrument)).get(
            reservation_id)
        # 通知预约人
        try:
            reserver = s.query(User).get(res.user_id)
            inst = s.query(Instrument).get(res.instrument_id)
            if reserver and reserver.feishu_user_id:
                start_str = res.start_time.strftime("%Y-%m-%d %H:%M")
                end_str = res.end_time.strftime("%Y-%m-%d %H:%M")
                send_feishu_text_to_user(reserver.feishu_user_id,
                                         f"您的仪器预约已被驳回：{inst.name if inst else ''}，{start_str}-{end_str}")
        except Exception:
            pass
        return jsonify(serialize_reservation(res))

    @app.post("/api/feishu/card/callback")
    def feishu_card_callback():
        """处理飞书卡片按钮交互回调"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({"error": "invalid_request"}), 400

            # 飞书卡片/事件回调的 URL 校验：需要原样返回 challenge
            # 兼容不同结构：顶层 challenge 或 event.challenge
            challenge = data.get("challenge") or (data.get("event") or {}).get("challenge")
            if challenge:
                return jsonify({"challenge": challenge})

            # 解析回调数据（兼容新版 card.action.trigger 的 event 包裹，以及旧版直出结构）
            event = data.get("event") or {}
            action_value = (
                (event.get("action") or {}).get("value", {})
                if isinstance(event, dict) and event.get("action")
                else (data.get("action") or {}).get("value", {})
            )
            # 新版回调会提供更新卡片所需的 token 与 message id
            update_token = (event.get("token") if isinstance(event, dict) else None) or data.get("token")
            open_message_id = ((event.get("context") or {}).get("open_message_id") if isinstance(event, dict) else None)
            reservation_id = action_value.get("reservation_id")
            keeper_id = action_value.get("keeper_id")
            action = action_value.get("action")

            if not all([reservation_id, keeper_id, action]):
                # 按飞书规范返回 200 + toast，避免 200672
                return jsonify({"toast": {"type": "error", "content": "无效的操作数据"}})

            if action not in ("approve", "reject"):
                return jsonify({"toast": {"type": "error", "content": "无效操作"}})

            s = get_session()
            try:
                res = s.query(Reservation).get(reservation_id)
                if not res:
                    return jsonify({"error": "reservation_not_found"}), 404

                inst = s.query(Instrument).get(res.instrument_id)
                if not inst or getattr(inst, "keeper_id", None) != keeper_id:
                    return jsonify({"error": "permission_denied"}), 403

                if res.status != "pending":
                    # 返回当前状态的卡片（需包在 card 字段内，指定 type=raw）
                    return jsonify({
                        "card": {
                            "type": "raw",
                            "data": build_status_card(res, inst, action)
                        }
                    })

                # 处理审批
                if action == "approve":
                    if has_conflict(s, res.instrument_id, res.start_time, res.end_time, exclude_id=res.id):
                        # 返回 toast 提示，维持原卡片不变
                        return jsonify({
                            "toast": {"type": "error", "content": "时间冲突，无法通过"}
                        })
                    res.status = "approved"
                else:
                    res.status = "rejected"

                s.commit()

                # 通知预约人
                try:
                    reserver = s.query(User).get(res.user_id)
                    if reserver and reserver.feishu_user_id:
                        start_str = res.start_time.strftime("%Y-%m-%d %H:%M")
                        end_str = res.end_time.strftime("%Y-%m-%d %H:%M")
                        msg = (
                            f"您的仪器预约已通过：{inst.name}，{start_str}-{end_str}" if res.status == "approved"
                            else f"您的仪器预约已被驳回：{inst.name}，{start_str}-{end_str}"
                        )
                        send_feishu_text_to_user(reserver.feishu_user_id, msg)
                except Exception:
                    pass

                # 构建更新后的卡片
                card_response = build_status_card(res, inst, action)
                # 主动调用飞书更新接口，确保原卡片被替换
                try:
                    if open_message_id and update_token:
                        update_feishu_card(open_message_id, card_response, update_token)
                except Exception:
                    pass
                toast_text = "已同意" if action == "approve" else "已驳回"

                return jsonify({
                    "card": {
                        "type": "raw",
                        "data": card_response
                    },
                    "toast": {"type": "success", "content": toast_text}
                })

            finally:
                s.close()

        except Exception as e:
            print(f"飞书卡片回调处理错误: {e}")
            return jsonify({"error": "internal_error"}), 500

    @app.get("/api/feishu/action")
    def feishu_action_callback():
        """处理飞书卡片中同意/驳回按钮的签名链接。
        链接中包含短期有效的签名token，不依赖登录状态。
        """
        token = request.args.get("token")
        if not token:
            return "invalid token", 400
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except Exception:
            return "invalid token", 400
        if data.get("typ") != "feishu_action_v1":
            return "invalid token", 400
        reservation_id = int(data.get("rid") or 0)
        keeper_id = int(data.get("kid") or 0)
        action = data.get("act")
        if reservation_id <= 0 or keeper_id <= 0 or action not in ("approve", "reject"):
            return "invalid token", 400
        s = get_session()
        try:
            res = s.query(Reservation).get(reservation_id)
            if not res:
                return "not found", 404
            inst = s.query(Instrument).get(res.instrument_id)
            if not inst or getattr(inst, "keeper_id", None) != keeper_id:
                return "permission denied", 403
            if res.status != "pending":
                return "already processed", 200
            if action == "approve":
                if has_conflict(s, res.instrument_id, res.start_time, res.end_time, exclude_id=res.id):
                    return "time conflict", 409
                res.status = "approved"
            else:
                res.status = "rejected"
            s.commit()
            # 通知预约人
            try:
                reserver = s.query(User).get(res.user_id)
                if reserver and reserver.feishu_user_id:
                    start_str = res.start_time.strftime("%Y-%m-%d %H:%M")
                    end_str = res.end_time.strftime("%Y-%m-%d %H:%M")
                    msg = (
                        f"您的仪器预约已通过：{inst.name}，{start_str}-{end_str}" if res.status == "approved"
                        else f"您的仪器预约已被驳回：{inst.name}，{start_str}-{end_str}"
                    )
                    send_feishu_text_to_user(reserver.feishu_user_id, msg)
            except Exception:
                pass
            # 返回JSON响应，包含操作结果
            return jsonify({
                "success": True,
                "message": f"操作成功：{'已同意' if res.status == 'approved' else '已驳回'}",
                "status": res.status
            })
        finally:
            s.close()

    @app.post("/api/reservations/<int:reservation_id>/cancel")
    def cancel_reservation(reservation_id: int):
        s = get_session()
        user = get_current_user()
        res = s.query(Reservation).get(reservation_id)
        if not res:
            return jsonify({"error": "not_found"}), 404
        if user.role not in ["admin", "super_admin"] and res.user_id != user.id:
            return jsonify({"error": "forbidden"}), 403
        res.status = "cancelled"
        s.commit()
        return jsonify(serialize_reservation(res))

    @app.put("/api/reservations/<int:reservation_id>")
    def update_reservation(reservation_id: int):
        s = get_session()
        user = get_current_user()
        res = s.query(Reservation).get(reservation_id)
        if not res:
            return jsonify({"error": "not_found"}), 404
        if user.role not in ["admin", "super_admin"] and res.user_id != user.id:
            return jsonify({"error": "forbidden"}), 403
        data = request.json or {}
        new_start = parse_iso8601(data.get("start_time")) or res.start_time
        new_end = parse_iso8601(data.get("end_time")) or res.end_time
        if new_start >= new_end:
            return jsonify({"error": "invalid_time"}), 400
        inst = s.query(Instrument).get(res.instrument_id)
        slot = inst.slot_minutes or 15
        if (new_start.minute % slot != 0) or (new_end.minute % slot != 0):
            return jsonify({"error": f"must_align_{slot}min"}), 400
        if has_conflict(s, res.instrument_id, new_start, new_end, exclude_id=res.id):
            return jsonify({"error": "time_conflict"}), 409
        res.start_time = new_start
        res.end_time = new_end
        # 检查仪器是否需要审批，与创建逻辑保持一致：
        # - 开启审批：保管员本人修改则直批通过，其余为待审批
        # - 未开启审批：直接通过
        requires_approval = inst.requires_approval == "true"
        is_keeper_self_booking = bool(getattr(inst, "keeper_id", None)) and (res.user_id == inst.keeper_id)
        res.status = ("approved" if (not requires_approval or is_keeper_self_booking) else "pending")
        s.commit()
        return jsonify(serialize_reservation(res))

    @app.delete("/api/reservations/<int:reservation_id>")
    def delete_reservation(reservation_id: int):
        s = get_session()
        user = get_current_user()
        res = s.query(Reservation).get(reservation_id)
        if not res:
            return jsonify({"error": "not_found"}), 404
        if user.role not in ["admin", "super_admin"] and res.user_id != user.id:
            return jsonify({"error": "forbidden"}), 403
        s.delete(res)
        s.commit()
        return jsonify({"ok": True})

    # Utilities
    def parse_iso8601(sval):
        try:
            # 标准化：将输入时间视为北京时或带偏移的时间，统一转为北京时 naive
            dt = datetime.fromisoformat(sval.replace("Z", "+00:00"))
            if dt.tzinfo is not None:
                # 转换到北京时间
                dt = (dt.astimezone(timezone(timedelta(hours=8)))).replace(tzinfo=None)
            return dt
        except Exception:
            return None

    def has_conflict(s, instrument_id, start_time, end_time, exclude_id=None):
        q = s.query(Reservation).filter(Reservation.instrument_id == instrument_id)
        q = q.filter(Reservation.status.in_(["approved", "pending"]))
        if exclude_id:
            q = q.filter(Reservation.id != exclude_id)
        overlap = q.filter(
            and_(Reservation.start_time < end_time, Reservation.end_time > start_time)
        ).first()
        return overlap is not None

    def is_within_allowed_windows(start_time, end_time, windows):
        # windows: list of {weekday:0-6, start:"HH:MM", end:"HH:MM"}
        cur = start_time
        while cur < end_time:
            weekday = cur.weekday()
            matched = False
            for w in windows:
                if int(w.get("weekday")) != weekday:
                    continue
                s_h, s_m = [int(x) for x in w.get("start", "00:00").split(":")]
                e_h, e_m = [int(x) for x in w.get("end", "23:59").split(":")]
                day_start = cur.replace(hour=s_h, minute=s_m, second=0, microsecond=0)
                day_end = cur.replace(hour=e_h, minute=e_m, second=0, microsecond=0)
                slot_end = min(cur.replace(minute=(cur.minute // 15) * 15) + timedelta(minutes=15), end_time)
                if cur >= day_start and slot_end <= day_end:
                    matched = True
                    break
            if not matched:
                return False
            cur += timedelta(minutes=15)
        return True

    def get_keeper_name_safe(keeper_id, fallback_name):
        if not keeper_id:
            return fallback_name
        s = get_session()
        try:
            u = s.query(User).get(keeper_id)
            return u.name if u else fallback_name
        except Exception:
            return fallback_name
        finally:
            s.close()

    def serialize_instrument(i: "Instrument"):
        return {
            "id": i.id,
            "name": i.name,
            "slot_minutes": i.slot_minutes or 15,
            "asset_code": i.asset_code,
            "factory_code": i.factory_code,
            "model": i.model,
            "brand": i.brand,
            "category": i.category,
            "quantity": i.quantity,
            "location": i.location,
            "keeper_unit": i.keeper_unit,
            # 避免懒加载 keeper 关系导致 DetachedInstanceError
            "keeper_name": get_keeper_name_safe(getattr(i, 'keeper_id', None), getattr(i, 'keeper_name', None)),
            "keeper_phone": i.keeper_phone,
            "purpose": i.purpose,
            "notes": i.notes,
            "booking_notes": i.booking_notes,
            "status": i.status,
            "keeper_id": i.keeper_id,
            "requires_approval": i.requires_approval,
            "booking_enabled": i.booking_enabled,
            "booking_start_time": i.booking_start_time,
            "booking_end_time": i.booking_end_time,
            "vendor_company": i.vendor_company,
            "price": i.price,
            "production_date": iso(i.production_date),
            "start_use_date": iso(i.start_use_date),
            "warranty_years": i.warranty_years,
            "warranty_company": i.warranty_company,
            "admin_notes": i.admin_notes,
            "photo_url": i.photo_url,
            "qrcode_url": i.qrcode_url,
            # 附带当前维护信息（如有）
            "current_maintenance": get_current_maintenance_for_instrument(i.id),
        }

    def serialize_employee(e: "User"):
        return {
            "id": e.id,
            "name": e.name,
            "employee_no": e.employee_no,
            "phone": e.phone,
            "type": e.type,
            "role": e.role,
            "allowed_windows": e.allowed_windows or [],
            "avatar_url": e.avatar_url,
            "email": e.email,
        }

    def serialize_reservation(r: "Reservation"):
        return {
            "id": r.id,
            "instrument_id": r.instrument_id,
            "employee_id": r.user_id,  # 向后兼容
            "user_id": r.user_id,
            "start_time": iso(r.start_time),
            "end_time": iso(r.end_time),
            "status": r.status,
            "instrument_name": r.instrument.name if r.instrument else None,
            "employee_name": r.user.name if r.user else None,  # 向后兼容
            "user_name": r.user.name if r.user else None,
        }

    def serialize_maintenance(m: "MaintenanceRecord"):
        return {
            "id": m.id,
            "instrument_id": m.instrument_id,
            "created_by": m.created_by,
            "user_id": m.user_id,
            "maintenance_date": iso(m.maintenance_date) if hasattr(m, 'maintenance_date') else None,
            "maintenance_start": iso(getattr(m, 'maintenance_start', None)) if hasattr(m,
                                                                                       'maintenance_start') else None,
            "maintenance_end": iso(getattr(m, 'maintenance_end', None)) if hasattr(m, 'maintenance_end') else None,
            "maintenance_type": m.maintenance_type,
            "description": m.description,
            "status": m.status,
            "created_at": iso(m.created_at),
        }

    def iso(dt):
        # 输出统一追加 +08:00 显式北京时区偏移，便于前端识别
        if not dt:
            return None
        return dt.strftime("%Y-%m-%dT%H:%M:%S+08:00")

    # 维护期工具函数
    def is_now_within(dt_start: datetime, dt_end: datetime, now: datetime) -> bool:
        if dt_start and dt_end:
            return (dt_start <= now <= dt_end)
        return False

    def normalize_day_range(single_date: datetime) -> (datetime, datetime):
        if not single_date:
            return (None, None)
        day_start = single_date.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1) - timedelta(microseconds=1)
        return (day_start, day_end)

    def get_current_maintenance_for_instrument(instrument_id: int):
        s = get_session()
        try:
            # 查找任何未完成的维护记录（不限制时间范围）
            q = s.query(MaintenanceRecord).filter(MaintenanceRecord.instrument_id == instrument_id)
            q = q.filter(MaintenanceRecord.status != "done")
            record = q.order_by(MaintenanceRecord.created_at.desc()).first()
            if record:
                return {
                    "id": record.id,
                    "maintenance_start": iso(getattr(record, 'maintenance_start', None)),
                    "maintenance_end": iso(getattr(record, 'maintenance_end', None)),
                    "status": record.status,
                    "type": record.maintenance_type,
                }
            return None
        finally:
            s.close()

    def sync_instrument_booking_by_maintenance(instrument_id: int):
        s = get_session()
        try:
            inst = s.query(Instrument).get(instrument_id)
            if not inst:
                return
            # 若存在任一未完成维护记录，则暂停预约并标记维护
            has_open = (
                    s.query(MaintenanceRecord)
                    .filter(MaintenanceRecord.instrument_id == instrument_id, MaintenanceRecord.status != "done")
                    .first()
                    is not None
            )
            if has_open:
                # 维护期：暂停预约并标记状态为 maintenance
                inst.booking_enabled = "false"
                inst.status = "maintenance"
            else:
                # 非维护期：若状态因维护被置为维护，则恢复为 active，并启用预约
                if inst.status == "maintenance":
                    inst.status = "active"
                if inst.booking_enabled == "false":
                    # 仅在维护导致暂停时自动恢复，这里简单恢复为可预约
                    inst.booking_enabled = "true"
            s.commit()
        finally:
            s.close()

    @app.get("/api/health")
    def health():
        return jsonify({"ok": True})

    @app.post("/api/sync-maintenance-status")
    def sync_all_maintenance_status():
        """同步所有仪器的维护状态（管理员接口）"""
        guard = require_admin_or_super_admin()
        if guard:
            return guard

        s = get_session()
        try:
            instruments = s.query(Instrument).all()
            synced = 0
            for inst in instruments:
                try:
                    sync_instrument_booking_by_maintenance(inst.id)
                    synced += 1
                except Exception:
                    pass
            return jsonify({"message": f"已同步 {synced} 个仪器的维护状态"})
        finally:
            s.close()

    # Avoid 404 noise for favicon in browsers
    @app.get("/favicon.ico")
    def favicon():
        return ("", 204)

    @app.get("/")
    def root():
        # 重定向到登录页面
        return redirect("/login.html")

    # Serve frontend static HTML directly via Flask for convenience
    FRONTEND_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "frontend"))

    @app.get("/home")
    def serve_home():
        return send_from_directory(FRONTEND_DIR, "home.html")

    @app.get("/reserve")
    def serve_reserve():
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.get("/instrument/new")
    def serve_instrument_form():
        return send_from_directory(FRONTEND_DIR, "instrument_form.html")

    # direct file paths
    @app.get("/index.html")
    def serve_index_html():
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.get("/home.html")
    def serve_home_html():
        return send_from_directory(FRONTEND_DIR, "home.html")

    @app.get("/instrument_form.html")
    def serve_instr_form_html():
        return send_from_directory(FRONTEND_DIR, "instrument_form.html")

    @app.get("/admin.html")
    def serve_admin_html():
        return send_from_directory(FRONTEND_DIR, "admin.html")

    @app.get("/admin_users.html")
    def serve_admin_users_html():
        return send_from_directory(FRONTEND_DIR, "admin_users.html")

    @app.get("/admin_instruments.html")
    def serve_admin_instruments_html():
        return send_from_directory(FRONTEND_DIR, "admin_instruments.html")

    @app.get("/admin_reservations.html")
    def serve_admin_reservations_html():
        return send_from_directory(FRONTEND_DIR, "admin_reservations.html")

    @app.get("/admin_maintenance.html")
    def serve_admin_maintenance_html():
        return send_from_directory(FRONTEND_DIR, "admin_maintenance.html")

    @app.get("/frontend/<path:filename>")
    def serve_frontend_assets(filename: str):
        return send_from_directory(FRONTEND_DIR, filename)

    @app.get("/reservations.html")
    def serve_reservations_html():
        return send_from_directory(FRONTEND_DIR, "reservations.html")

    @app.get("/feishu-reserve")
    def serve_feishu_reserve_html():
        return send_from_directory(FRONTEND_DIR, "feishu_reserve.html")

    @app.get("/feishu_reserve.html")
    def serve_feishu_reserve_html_compat():
        return send_from_directory(FRONTEND_DIR, "feishu_reserve.html")

    @app.get("/login.html")
    def serve_login_html():
        return send_from_directory(FRONTEND_DIR, "login.html")

    @app.get("/maintenance.html")
    def serve_maintenance_html():
        return send_from_directory(FRONTEND_DIR, "maintenance.html")

    # 飞书OAuth认证相关API
    @app.get("/api/auth/feishu/login")
    def feishu_login():
        """生成飞书登录URL（使用 /authen/v1/index 流程），支持 state 透传 next。"""
        next_url = request.args.get("next", "") or ""
        do_redirect = request.args.get("redirect") in ("1", "true", "yes")
        from urllib.parse import quote
        state = quote(next_url, safe="") if next_url else ""
        auth_url = (
                f"https://open.feishu.cn/open-apis/authen/v1/index"
                f"?app_id={FEISHU_APP_ID}"
                f"&redirect_uri={FEISHU_REDIRECT_URI}"
                + (f"&state={state}" if state else "")
        )
        if do_redirect:
            return redirect(auth_url)
        return jsonify({"auth_url": auth_url})

    @app.get("/api/auth/feishu/callback")
    def feishu_callback():
        """处理飞书OAuth回调：两步换取用户token，拉取用户信息，发JWT并重定向前端。"""
        code = request.args.get("code")
        state_next = request.args.get("state")  # 透传的 next URL（已编码）
        if not code:
            return jsonify({"error": "missing_code"}), 400

        try:
            # 1) 获取 app_access_token（内部应用）
            app_token_url = "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal"
            app_token_payload = {"app_id": FEISHU_APP_ID, "app_secret": FEISHU_APP_SECRET}
            app_token_resp = requests.post(app_token_url, json=app_token_payload, timeout=10)
            app_token_json = app_token_resp.json()
            app_access_token = app_token_json.get("app_access_token") or (app_token_json.get("data", {}) or {}).get(
                "app_access_token")
            if app_token_resp.status_code != 200 or not app_access_token:
                return jsonify(
                    {"error": "app_token_error", "status": app_token_resp.status_code, "details": app_token_json}), 400

            # 2) 使用 app_access_token 作为 Bearer，交换用户 access_token
            user_token_url = "https://open.feishu.cn/open-apis/authen/v1/access_token"
            headers = {
                "Authorization": f"Bearer {app_access_token}",
                "Content-Type": "application/json; charset=utf-8",
            }
            body = {"grant_type": "authorization_code", "code": code}
            resp = requests.post(user_token_url, json=body, headers=headers, timeout=10)
            token_result = resp.json()
            if resp.status_code != 200:
                return jsonify({"error": "token_http_error", "status": resp.status_code, "details": token_result}), 400
            user_access_token = (token_result or {}).get("data", {}).get("access_token") or token_result.get(
                "access_token")
            if not user_access_token:
                return jsonify({"error": "token_error", "details": token_result}), 400

            # 3) 拉取用户信息（非OIDC：/authen/v1/user_info）
            user_info_url = "https://open.feishu.cn/open-apis/authen/v1/user_info"
            u_headers = {
                "Authorization": f"Bearer {user_access_token}",
                "Content-Type": "application/json",
            }
            u_resp = requests.get(user_info_url, headers=u_headers, timeout=10)
            u_json = u_resp.json()
            if u_resp.status_code != 200 or u_json.get("code") not in (0, None):
                return jsonify({"error": "user_info_error", "status": u_resp.status_code, "details": u_json}), 400
            u_data = u_json.get("data") or {}

            feishu_user_id = u_data.get("user_id") or (u_data.get("user") or {}).get("user_id")
            name = u_data.get("name") or (u_data.get("user") or {}).get("name") or "未知用户"
            avatar_url = u_data.get("avatar_url") or (u_data.get("user") or {}).get("avatar_url")
            email = u_data.get("email") or (u_data.get("user") or {}).get("email")
            # 优先从 user_info 获取手机号（若有）
            phone = (
                    u_data.get("mobile")
                    or (u_data.get("user") or {}).get("mobile")
                    or (u_data.get("mobile_visible") if isinstance(u_data.get("mobile_visible"), str) else None)
            )

            # 获取用户详细信息（包括手机号）
            if not phone:
                try:
                    me_resp = requests.get(
                        "https://open.feishu.cn/open-apis/contact/v3/users/me",
                        headers={
                            "Authorization": f"Bearer {user_access_token}",
                            "Content-Type": "application/json",
                        },
                        timeout=10,
                    )
                    me_json = me_resp.json()
                    if me_resp.status_code == 200 and (me_json.get("code") in (0, None)):
                        me_data = (me_json.get("data") or {}).get("user") or me_json.get("data") or {}
                        phone = me_data.get("mobile") or phone
                except Exception:
                    pass

            # 4) upsert 用户
            s = get_session()
            try:
                user = s.query(User).filter(User.feishu_user_id == feishu_user_id).first()
                if not user:
                    # 角色规则：默认 user；若姓名为黄敏青，则设为 super_admin
                    role_val = "super_admin" if (name == "黄敏青") else "user"
                    user = User(name=name, feishu_user_id=feishu_user_id, avatar_url=avatar_url, email=email,
                                phone=phone, role=role_val)
                    s.add(user)
                    s.commit()
                else:
                    user.name = name or user.name
                    user.avatar_url = avatar_url or user.avatar_url
                    user.email = email or user.email
                    if phone:
                        user.phone = phone
                    # 每次登录基于姓名提升权限
                    try:
                        nm = (name or "").strip()
                        if nm == "黄敏青" and user.role != "super_admin":
                            user.role = "super_admin"
                    except Exception:
                        pass
                    user.last_login_at = now_cn()
                    s.commit()

                # 5) 签发JWT (延长有效期到30天)
                payload = {"user_id": user.id, "exp": datetime.utcnow() + timedelta(days=30)}
                jwt_token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

                # 缓存用户信息
                cache_user(user.id, user)
                cache_token(jwt_token, user)

            finally:
                s.close()

            # 6) 重定向：优先 state 指定的 next，否则首页
            base_url = request.host_url.rstrip("/")
            next_url = None
            try:
                if state_next:
                    from urllib.parse import unquote, urlparse
                    cand = unquote(state_next)
                    # 仅允许相同站点或以 / 开头的路径，避免开放重定向
                    if cand.startswith("/"):
                        next_url = f"{base_url}{cand}"
                    else:
                        u = urlparse(cand)
                        if u.scheme and u.netloc and f"{u.scheme}://{u.netloc}" == base_url:
                            next_url = cand
            except Exception:
                next_url = None
            if not next_url:
                next_url = f"{base_url}/home.html"
            glue = '&' if ('?' in next_url) else '?'
            redirect_url = f"{next_url}{glue}token={jwt_token}&success=true"
            return redirect(redirect_url)
        except Exception as e:
            return jsonify({"error": "auth_failed", "details": str(e)}), 500

    @app.get("/api/auth/me")
    def get_current_user_info():
        """获取当前用户信息"""
        user = get_current_user()
        if not hasattr(user, 'feishu_user_id') or not user.feishu_user_id:
            return jsonify({"error": "not_authenticated"}), 401
        return jsonify(serialize_user(user))

    @app.post("/api/auth/logout")
    def logout():
        """登出（客户端删除token即可）"""
        return jsonify({"message": "登出成功"})

    # 权限管理API
    @app.get("/api/users")
    def list_users():
        """获取用户列表（管理员可见）"""
        guard = require_admin_or_super_admin()
        if guard:
            return guard

        s = get_session()
        users = s.query(User).order_by(User.id.desc()).all()
        return jsonify([serialize_user(u) for u in users])

    @app.post("/api/users")
    def create_user():
        """创建用户（仅超级管理员和管理员可操作）"""
        guard = require_admin_or_super_admin()
        if guard:
            return guard

        s = get_session()
        data = request.json or {}
        current_user = get_current_user()

        # 只有超级管理员可以创建管理员
        if data.get("role") in ["admin", "super_admin"] and current_user.role != "super_admin":
            return jsonify({"error": "insufficient_permission"}), 403

        data["created_by"] = current_user.id
        user = User(**data)
        s.add(user)
        s.commit()
        return jsonify(serialize_user(user))

    @app.put("/api/users/<int:user_id>/role")
    def update_user_role(user_id: int):
        """更新用户角色（仅超级管理员可操作）"""
        guard = require_super_admin()
        if guard:
            return guard

        s = get_session()
        user = s.query(User).get(user_id)
        if not user:
            return jsonify({"error": "user_not_found"}), 404

        data = request.json or {}
        new_role = data.get("role")

        if new_role not in ["user", "admin", "super_admin"]:
            return jsonify({"error": "invalid_role"}), 400

        user.role = new_role
        s.commit()

        # 清除用户缓存，强制下次登录时重新获取最新信息
        clear_user_cache(user_id)

        return jsonify(serialize_user(user))

    @app.put("/api/users/<int:user_id>")
    def update_user(user_id: int):
        """更新用户信息（管理员/超管）。仅超管可修改角色。"""
        guard = require_admin_or_super_admin()
        if guard:
            return guard

        s = get_session()
        u = s.query(User).get(user_id)
        if not u:
            return jsonify({"error": "user_not_found"}), 404

        data = request.json or {}
        current_user = get_current_user()

        # 只有超级管理员可以更改角色
        if current_user.role != "super_admin" and "role" in data:
            data.pop("role", None)

        # 允许更新的字段白名单
        allowed_fields = {
            "name", "phone", "email",
            "is_keeper", "allowed_windows", "is_active", "permissions", "role"
        }
        for k, v in list(data.items()):
            if k not in allowed_fields:
                data.pop(k, None)

        for k, v in data.items():
            setattr(u, k, v)

        s.commit()

        # 如果修改了角色，清除用户缓存
        if "role" in data:
            clear_user_cache(user_id)

        return jsonify(serialize_user(u))

    @app.put("/api/users/<int:user_id>/status")
    def update_user_status(user_id: int):
        """更新用户状态（激活/暂停）"""
        guard = require_admin_or_super_admin()
        if guard:
            return guard

        s = get_session()
        user = s.query(User).get(user_id)
        if not user:
            return jsonify({"error": "user_not_found"}), 404

        data = request.json or {}
        new_status = data.get("status")

        if new_status not in ["active", "suspended"]:
            return jsonify({"error": "invalid_status"}), 400

        user.is_active = new_status
        s.commit()

        return jsonify(serialize_user(user))

    @app.delete("/api/users/<int:user_id>")
    def delete_user(user_id: int):
        """删除用户（仅超级管理员可操作）"""
        guard = require_super_admin()
        if guard:
            return guard

        s = get_session()
        user = s.query(User).get(user_id)
        if not user:
            return jsonify({"error": "user_not_found"}), 404

        # 检查是否尝试删除自己
        current_user = get_current_user()
        if user.id == current_user.id:
            return jsonify({"error": "cannot_delete_self"}), 400

        # 检查用户是否有相关的预约记录
        reservations = s.query(Reservation).filter(Reservation.user_id == user_id).count()
        if reservations > 0:
            return jsonify({"error": "user_has_reservations", "count": reservations}), 400

        # 检查用户是否是仪器保管人
        instruments = s.query(Instrument).filter(Instrument.keeper_id == user_id).count()
        if instruments > 0:
            return jsonify({"error": "user_is_keeper", "count": instruments}), 400

        # 删除用户
        s.delete(user)
        s.commit()

        return jsonify({"message": "用户删除成功"})

    @app.put("/api/instruments/<int:instrument_id>/keeper")
    def assign_instrument_keeper(instrument_id: int):
        """分配仪器保管人（仅管理员可操作）"""
        guard = require_admin_or_super_admin()
        if guard:
            return guard

        s = get_session()
        instrument = s.query(Instrument).get(instrument_id)
        if not instrument:
            return jsonify({"error": "instrument_not_found"}), 404

        data = request.json or {}
        keeper_id = data.get("keeper_id")

        if keeper_id:
            keeper = s.query(User).get(keeper_id)
            if not keeper:
                return jsonify({"error": "keeper_not_found"}), 404
            instrument.keeper_id = keeper_id
        else:
            instrument.keeper_id = None

        s.commit()
        return jsonify(serialize_instrument(instrument))

    @app.put("/api/instruments/<int:instrument_id>/status")
    def update_instrument_status(instrument_id: int):
        """更新仪器状态（管理员或仪器保管人可操作）"""
        user = get_current_user()
        s = get_session()
        instrument = s.query(Instrument).get(instrument_id)
        if not instrument:
            return jsonify({"error": "instrument_not_found"}), 404

        # 检查权限：管理员或仪器保管人
        if user.role not in ["super_admin", "admin"] and instrument.keeper_id != user.id:
            return jsonify({"error": "permission_denied"}), 403

        data = request.json or {}
        new_status = data.get("status")

        if new_status not in ["active", "suspended", "maintenance"]:
            return jsonify({"error": "invalid_status"}), 400

        instrument.status = new_status
        s.commit()

        return jsonify(serialize_instrument(instrument))

    @app.put("/api/instruments/<int:instrument_id>/booking")
    def update_instrument_booking(instrument_id: int):
        """更新仪器预约设置（管理员或仪器保管人可操作）"""
        user = get_current_user()
        s = get_session()
        instrument = s.query(Instrument).get(instrument_id)
        if not instrument:
            return jsonify({"error": "instrument_not_found"}), 404

        # 检查权限：管理员或仪器保管人
        if user.role not in ["super_admin", "admin"] and instrument.keeper_id != user.id:
            return jsonify({"error": "permission_denied"}), 403

        data = request.json or {}

        if "booking_enabled" in data:
            instrument.booking_enabled = data["booking_enabled"]
        if "booking_start_time" in data:
            instrument.booking_start_time = data["booking_start_time"]
        if "booking_end_time" in data:
            instrument.booking_end_time = data["booking_end_time"]
        if "requires_approval" in data:
            instrument.requires_approval = data["requires_approval"]

        s.commit()
        return jsonify(serialize_instrument(instrument))

    # 仪器二维码生成API
    @app.get("/api/instruments/<int:instrument_id>/qrcode")
    def generate_instrument_qrcode(instrument_id: int):
        """生成仪器预约二维码"""
        s = get_session()
        instrument = s.query(Instrument).get(instrument_id)
        if not instrument:
            return jsonify({"error": "instrument_not_found"}), 404

        # 生成二维码URL（优先使用当前请求域名，避免跨域或失效）
        try:
            base_url = request.host_url.rstrip("/")
        except Exception:
            base_url = os.getenv("BASE_URL", "http://1.13.176.116:5011").rstrip("/")
        qr_url = f"{base_url}/feishu-reserve?instrument_id={instrument_id}&autologin=1"

        # 若已生成并保存过二维码文件，且域名与当前请求一致，则直接重定向；否则重新生成并更新
        try:
            from urllib.parse import urlparse
            if instrument.qrcode_url and instrument.qrcode_url.startswith("http"):
                parsed = urlparse(instrument.qrcode_url)
                current_host = urlparse(base_url).netloc
                if parsed.netloc == current_host:
                    return redirect(instrument.qrcode_url)
                # 否则，继续生成新的并更新存储
        except Exception:
            pass

        # 动态生成（不带名称）作为兜底
        try:
            import qrcode as qrcode_lib  # type: ignore
            img = qrcode_lib.make(qr_url)
            from io import BytesIO
            bio = BytesIO()
            img.save(bio, format='PNG')
            bio.seek(0)
            return send_file(bio, mimetype='image/png', as_attachment=False)
        except Exception as e:
            return jsonify({"error": "qrcode_generation_failed", "details": str(e)}), 500

    def generate_and_save_instrument_qrcode(instrument: "Instrument") -> str:
        """生成带仪器名的二维码图片，保存到 uploads，并返回可访问URL"""
        # 确保上传目录存在
        upload_folder = ensure_upload_folder()
        # 目标URL
        try:
            base_url = request.host_url.rstrip("/")
        except Exception:
            base_url = os.getenv("BASE_URL", "http://1.13.176.116:5011").rstrip("/")
        qr_target_url = f"{base_url}/feishu-reserve?instrument_id={instrument.id}&autologin=1"

        # 生成二维码图像（PIL Image）
        import qrcode as qrcode_lib  # type: ignore
        from PIL import Image, ImageDraw, ImageFont  # type: ignore
        qr_img = qrcode_lib.make(qr_target_url)
        qr_img = qr_img.convert("RGB")

        # 在二维码下方增加白色条并写入仪器名
        padding = 12
        text_height = 36
        width, height = qr_img.size
        canvas = Image.new("RGB", (width, height + padding + text_height), "white")
        canvas.paste(qr_img, (0, 0))

        draw = ImageDraw.Draw(canvas)
        # 尝试加载系统字体，失败则用默认字体
        try:
            font_path_candidates = [
                "/System/Library/Fonts/Supplemental/PingFang.ttc",
                "/System/Library/Fonts/PingFang.ttc",
                "/Library/Fonts/Arial Unicode.ttf",
            ]
            used_font = None
            for fp in font_path_candidates:
                if os.path.exists(fp):
                    try:
                        used_font = ImageFont.truetype(fp, 18)
                        break
                    except Exception:
                        pass
            if not used_font:
                used_font = ImageFont.load_default()
        except Exception:
            used_font = ImageFont.load_default()

        instrument_name = (instrument.name or "").strip() or f"Instrument {instrument.id}"
        # 计算文本居中位置
        try:
            bbox = draw.textbbox((0, 0), instrument_name, font=used_font)
            text_width = (bbox[2] - bbox[0]) if bbox else 0
        except Exception:
            # Fallback measurement
            text_width = min(width, len(instrument_name) * 10)
        text_x = max(0, (width - text_width) // 2)
        text_y = height + (padding // 2)
        draw.text((text_x, text_y), instrument_name, fill=(0, 0, 0), font=used_font)

        # 保存文件
        filename = f"instrument_{instrument.id}_qr.png"
        file_path = os.path.join(upload_folder, filename)
        canvas.save(file_path, format="PNG")

        # 可访问URL
        public_url = f"{base_url}/uploads/{filename}"
        return public_url

    @app.get("/api/instruments/<int:instrument_id>/qrcode-url")
    def get_instrument_qrcode_url(instrument_id: int):
        """获取仪器预约二维码URL"""
        try:
            base_url = request.host_url.rstrip("/")
        except Exception:
            base_url = os.getenv("BASE_URL", "http://1.13.176.116:5011").rstrip("/")
        qr_url = f"{base_url}/feishu-reserve?instrument_id={instrument_id}&autologin=1"
        return jsonify({"qrcode_url": qr_url})

    def serialize_user(u: "User"):
        """序列化用户信息"""
        return {
            "id": u.id,
            "name": u.name,
            "employee_no": u.employee_no,
            "phone": u.phone,
            "type": u.type,
            "role": u.role,
            "is_active": u.is_active,
            "is_keeper": u.is_keeper,
            "created_by": u.created_by,
            "permissions": u.permissions or {},
            "allowed_windows": u.allowed_windows or [],
            "avatar_url": u.avatar_url,
            "email": u.email,
            "created_at": iso(u.created_at),
            "last_login_at": iso(u.last_login_at),
        }

    # Maintenance APIs
    @app.get("/api/maintenance")
    def list_maintenance():
        s = get_session()
        user = get_current_user()
        q = s.query(MaintenanceRecord)
        instrument_id = request.args.get("instrument_id")
        maint_type = request.args.get("maintenance_type")
        start_date = request.args.get("start_date")
        end_date = request.args.get("end_date")
        page = int(request.args.get("page", 1))
        page_size = int(request.args.get("page_size", 10))

        if instrument_id:
            q = q.filter(MaintenanceRecord.instrument_id == int(instrument_id))
        if maint_type:
            q = q.filter(MaintenanceRecord.maintenance_type == maint_type)
        # 日期范围过滤（北京时间自然日）：命中开始或结束日期落在区间内，或单日 maintenance_date 落在区间内
        # 区间为 [sd, edNext) 形式，end_date 为当天 00:00 的次日
        if start_date or end_date:
            try:
                sd = datetime.strptime(start_date, "%Y-%m-%d") if start_date else None
            except Exception:
                sd = None
            try:
                ed = datetime.strptime(end_date, "%Y-%m-%d") if end_date else None
            except Exception:
                ed = None
            ed_next = (ed + timedelta(days=1)) if ed else None

            conds = []
            # 命中维护开始时间
            if sd and ed_next:
                conds.append(
                    and_(MaintenanceRecord.maintenance_start != None, MaintenanceRecord.maintenance_start >= sd,
                         MaintenanceRecord.maintenance_start < ed_next))
            elif sd:
                conds.append(
                    and_(MaintenanceRecord.maintenance_start != None, MaintenanceRecord.maintenance_start >= sd))
            elif ed_next:
                conds.append(
                    and_(MaintenanceRecord.maintenance_start != None, MaintenanceRecord.maintenance_start < ed_next))

            # 命中维护结束时间
            if sd and ed_next:
                conds.append(and_(MaintenanceRecord.maintenance_end != None, MaintenanceRecord.maintenance_end >= sd,
                                  MaintenanceRecord.maintenance_end < ed_next))
            elif sd:
                conds.append(and_(MaintenanceRecord.maintenance_end != None, MaintenanceRecord.maintenance_end >= sd))
            elif ed_next:
                conds.append(
                    and_(MaintenanceRecord.maintenance_end != None, MaintenanceRecord.maintenance_end < ed_next))

            # 单日维护日期
            if sd and ed_next:
                conds.append(
                    and_(MaintenanceRecord.maintenance_start == None, MaintenanceRecord.maintenance_date != None,
                         MaintenanceRecord.maintenance_date >= sd, MaintenanceRecord.maintenance_date < ed_next))
            elif sd:
                conds.append(
                    and_(MaintenanceRecord.maintenance_start == None, MaintenanceRecord.maintenance_date != None,
                         MaintenanceRecord.maintenance_date >= sd))
            elif ed_next:
                conds.append(
                    and_(MaintenanceRecord.maintenance_start == None, MaintenanceRecord.maintenance_date != None,
                         MaintenanceRecord.maintenance_date < ed_next))

            if conds:
                q = q.filter(or_(*conds))

        # 权限：管理员/超管可见所有；保管员仅见自己负责仪器；普通用户无权查看
        if user.role not in ["admin", "super_admin"]:
            if getattr(user, 'is_keeper', False) and getattr(user, 'id', None):
                q = q.filter(MaintenanceRecord.instrument_id.in_(
                    s.query(Instrument.id).filter(Instrument.keeper_id == user.id)
                ))
            else:
                return jsonify({"items": [],
                                "pagination": {"page": 1, "page_size": page_size, "total": 0, "total_pages": 0,
                                               "has_prev": False, "has_next": False}})

        total = q.count()
        offset = (page - 1) * page_size
        items = q.order_by(MaintenanceRecord.created_at.desc()).offset(offset).limit(page_size).all()
        total_pages = (total + page_size - 1) // page_size
        return jsonify({
            "items": [serialize_maintenance(m) for m in items],
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total": total,
                "total_pages": total_pages,
                "has_prev": page > 1,
                "has_next": page < total_pages
            }
        })

    @app.post("/api/maintenance")
    def create_maintenance():
        s = get_session()
        user = get_current_user()
        data = request.json or {}
        instrument_id = int(data.get("instrument_id"))

        # 权限：管理员/超管任意；保管员仅能对自己负责的仪器添加
        if user.role not in ["admin", "super_admin"]:
            inst = s.query(Instrument).get(instrument_id)
            if not inst:
                return jsonify({"error": "instrument_not_found"}), 404
            if not (getattr(user, 'is_keeper', False) and inst.keeper_id == user.id):
                return jsonify({"error": "permission_denied"}), 403

        # 解析日期/日期范围
        m_date = parse_iso8601(data.get("maintenance_date")) if data.get("maintenance_date") else None
        m_start = parse_iso8601(data.get("maintenance_start")) if data.get("maintenance_start") else None
        m_end = parse_iso8601(data.get("maintenance_end")) if data.get("maintenance_end") else None
        if m_start and (not m_end):
            m_end = m_start
        if (not m_start) and m_end:
            m_start = m_end
        # 兼容历史：确保 maintenance_date 始终有值（若未提供则取开始或当前时间）
        if not m_date:
            if m_start:
                m_date = m_start
            elif m_end:
                m_date = m_end
            else:
                m_date = now_cn()

        status = data.get("status") or "done"
        # 如果状态是已完成且没有设置结束时间，则使用当前时间作为结束时间
        if status == "done" and not m_end:
            m_end = now_cn()
        # 如果状态是进行中，确保结束时间为空
        elif status == "pending":
            m_end = None

        rec = MaintenanceRecord(
            instrument_id=instrument_id,
            created_by=user.id,
            user_id=user.id,
            maintenance_date=m_date,
            maintenance_start=m_start,
            maintenance_end=m_end,
            maintenance_type=(data.get("maintenance_type") or "general"),
            description=(data.get("description") or ""),
            status=status
        )
        s.add(rec)
        s.commit()
        # 根据维护期自动同步仪器预约状态
        try:
            sync_instrument_booking_by_maintenance(instrument_id)
        except Exception as _:
            pass
        return jsonify(serialize_maintenance(rec))

    @app.put("/api/maintenance/<int:record_id>")
    def update_maintenance(record_id: int):
        s = get_session()
        user = get_current_user()
        rec = s.query(MaintenanceRecord).get(record_id)
        if not rec:
            return jsonify({"error": "not_found"}), 404
        # 权限：管理员/超管；或保管人且记录所属仪器为其管理
        if user.role not in ["admin", "super_admin"]:
            inst = s.query(Instrument).get(rec.instrument_id)
            if not (getattr(user, 'is_keeper', False) and inst and inst.keeper_id == user.id):
                return jsonify({"error": "permission_denied"}), 403

        data = request.json or {}
        prev_status = rec.status
        # 可更新字段：maintenance_type, description, status, maintenance_date/start/end
        updatable = ["maintenance_type", "description", "status"]
        for k in updatable:
            if k in data:
                setattr(rec, k, data.get(k))
        # 日期处理
        if "maintenance_date" in data:
            rec.maintenance_date = parse_iso8601(data.get("maintenance_date")) if data.get("maintenance_date") else None
        if ("maintenance_start" in data) or ("maintenance_end" in data):
            ms = parse_iso8601(data.get("maintenance_start")) if data.get("maintenance_start") else None
            me = parse_iso8601(data.get("maintenance_end")) if data.get("maintenance_end") else None
            if ms and not me:
                me = ms
            if me and not ms:
                ms = me
            rec.maintenance_start = ms
            rec.maintenance_end = me

        # 若标记完成且没有结束时间，自动补齐结束时间为现在
        if (("status" in data and data.get("status") == "done") or (prev_status != "done" and rec.status == "done")):
            if not getattr(rec, 'maintenance_end', None):
                rec.maintenance_end = now_cn()
            # 若没有开始时间但有单日维护日期，则用该日作为开始
            if (not getattr(rec, 'maintenance_start', None)) and getattr(rec, 'maintenance_date', None):
                rec.maintenance_start = rec.maintenance_date

        s.commit()
        # 若状态或日期调整，尝试同步仪器预约状态
        try:
            sync_instrument_booking_by_maintenance(rec.instrument_id)
        except Exception as _:
            pass
        return jsonify(serialize_maintenance(rec))

    @app.delete("/api/maintenance/<int:record_id>")
    def delete_maintenance(record_id: int):
        s = get_session()
        user = get_current_user()
        rec = s.query(MaintenanceRecord).get(record_id)
        if not rec:
            return jsonify({"error": "not_found"}), 404

        # 权限：管理员/超管；或保管人且记录所属仪器为其管理
        if user.role not in ["admin", "super_admin"]:
            if not (getattr(user, 'is_keeper', False) and getattr(user, 'id', None)):
                return jsonify({"error": "permission_denied"}), 403

            inst = s.query(Instrument).get(rec.instrument_id)
            if not (inst and inst.keeper_id == user.id):
                return jsonify({"error": "permission_denied"}), 403

        # 记录仪器ID以便同步状态
        instrument_id = rec.instrument_id

        # 删除记录
        s.delete(rec)
        s.commit()

        # 同步仪器预约状态
        try:
            sync_instrument_booking_by_maintenance(instrument_id)
        except Exception as _:
            pass

        return jsonify({"message": "deleted"})

    @app.get("/api/maintenance/export")
    def export_maintenance():
        try:
            import pandas as pd
            from io import BytesIO
        except Exception:
            return jsonify({"error": "pandas_required"}), 500
        s = get_session()
        # 支持通过URL参数传递token（用于飞书环境）
        token_from_url = request.args.get('token')
        if token_from_url:
            try:
                payload = jwt.decode(token_from_url, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                user_id = payload.get("user_id")
                if user_id:
                    user = s.query(User).get(user_id)
                    if user:
                        s.close();
                        s = get_session()
                    else:
                        user = get_current_user()
                else:
                    user = get_current_user()
            except jwt.InvalidTokenError:
                user = get_current_user()
        else:
            user = get_current_user()
        q = s.query(MaintenanceRecord)

        instrument_id = request.args.get("instrument_id")
        maint_type = request.args.get("maintenance_type")
        start_date = request.args.get("start_date")
        end_date = request.args.get("end_date")
        if instrument_id:
            q = q.filter(MaintenanceRecord.instrument_id == int(instrument_id))
        if maint_type:
            q = q.filter(MaintenanceRecord.maintenance_type == maint_type)

        # 日期范围过滤（与列表一致）：命中开始或结束时间，或单日日期
        if start_date or end_date:
            try:
                sd = datetime.strptime(start_date, "%Y-%m-%d") if start_date else None
            except Exception:
                sd = None
            try:
                ed = datetime.strptime(end_date, "%Y-%m-%d") if end_date else None
            except Exception:
                ed = None
            ed_next = (ed + timedelta(days=1)) if ed else None

            conds = []
            if sd and ed_next:
                conds.append(
                    and_(MaintenanceRecord.maintenance_start != None, MaintenanceRecord.maintenance_start >= sd,
                         MaintenanceRecord.maintenance_start < ed_next))
            elif sd:
                conds.append(
                    and_(MaintenanceRecord.maintenance_start != None, MaintenanceRecord.maintenance_start >= sd))
            elif ed_next:
                conds.append(
                    and_(MaintenanceRecord.maintenance_start != None, MaintenanceRecord.maintenance_start < ed_next))

            if sd and ed_next:
                conds.append(and_(MaintenanceRecord.maintenance_end != None, MaintenanceRecord.maintenance_end >= sd,
                                  MaintenanceRecord.maintenance_end < ed_next))
            elif sd:
                conds.append(and_(MaintenanceRecord.maintenance_end != None, MaintenanceRecord.maintenance_end >= sd))
            elif ed_next:
                conds.append(
                    and_(MaintenanceRecord.maintenance_end != None, MaintenanceRecord.maintenance_end < ed_next))

            if sd and ed_next:
                conds.append(
                    and_(MaintenanceRecord.maintenance_start == None, MaintenanceRecord.maintenance_date != None,
                         MaintenanceRecord.maintenance_date >= sd, MaintenanceRecord.maintenance_date < ed_next))
            elif sd:
                conds.append(
                    and_(MaintenanceRecord.maintenance_start == None, MaintenanceRecord.maintenance_date != None,
                         MaintenanceRecord.maintenance_date >= sd))
            elif ed_next:
                conds.append(
                    and_(MaintenanceRecord.maintenance_start == None, MaintenanceRecord.maintenance_date != None,
                         MaintenanceRecord.maintenance_date < ed_next))

            if conds:
                q = q.filter(or_(*conds))

        if user.role not in ["admin", "super_admin"]:
            if getattr(user, 'is_keeper', False) and getattr(user, 'id', None):
                q = q.filter(MaintenanceRecord.instrument_id.in_(
                    s.query(Instrument.id).filter(Instrument.keeper_id == user.id)
                ))
            else:
                # 普通用户仅导出自己创建的维护记录
                q = q.filter(MaintenanceRecord.created_by == getattr(user, 'id', -1))

        items = q.order_by(MaintenanceRecord.created_at.desc()).all()
        rows = []
        for m in items:
            inst = s.query(Instrument).get(m.instrument_id)
            creator = s.query(User).get(m.created_by)
            rows.append({
                "记录ID": m.id,
                "仪器ID": m.instrument_id,
                "仪器名称": inst.name if inst else "",
                "开始时间": (m.maintenance_start.strftime("%Y-%m-%d %H:%M") if m.maintenance_start else (
                    m.maintenance_date.strftime("%Y-%m-%d %H:%M") if m.maintenance_date else "")),
                "结束时间": (m.maintenance_end.strftime("%Y-%m-%d %H:%M") if m.maintenance_end else ""),
                "类型": m.maintenance_type,
                "描述": m.description or "",
                "状态": m.status,
                "创建人": creator.name if creator else "",
                "创建时间": m.created_at.strftime("%Y-%m-%d %H:%M") if m.created_at else "",
            })
        df = pd.DataFrame(rows)
        bio = BytesIO()
        df.to_excel(bio, index=False)
        bio.seek(0)
        filename = f"维护记录_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        return send_file(bio, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                         as_attachment=True, download_name=filename)

    # 简单版：无需JWT的飞书授权与回调（返回JSON）
    @app.get("/authorize")
    def feishu_authorize_simple():
        """跳转飞书登录页，完成后回调到 /oauth/callback（按简化示例方式）。"""
        # 使用配置中的回调地址
        use_redirect = FEISHU_REDIRECT_URI or (
                os.getenv("BASE_URL", request.url_root.rstrip("/")) + "/api/auth/feishu/callback")
        auth_url = (
            "https://open.feishu.cn/open-apis/authen/v1/index"
            f"?app_id={FEISHU_APP_ID}&redirect_uri={use_redirect}"
        )
        return redirect(auth_url)

    @app.get("/oauth/callback")
    def feishu_oauth_callback_simple():
        """处理飞书授权回调：两步换取用户token，拉取用户信息，发JWT并重定向前端。"""
        code = request.args.get("code")
        state_next = request.args.get("state")
        if not code:
            return jsonify({"error": "missing_code"}), 400
        try:
            # 1) 获取 app_access_token
            app_token_url = "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal"
            app_token_payload = {"app_id": FEISHU_APP_ID, "app_secret": FEISHU_APP_SECRET}
            app_token_resp = requests.post(app_token_url, json=app_token_payload, timeout=10)
            app_token_json = app_token_resp.json()
            app_access_token = app_token_json.get("app_access_token") or (app_token_json.get("data", {}) or {}).get(
                "app_access_token")
            if app_token_resp.status_code != 200 or not app_access_token:
                return jsonify(
                    {"error": "app_token_error", "status": app_token_resp.status_code, "details": app_token_json}), 400

            # 2) 使用 app_access_token 交换用户 access_token
            user_token_url = "https://open.feishu.cn/open-apis/authen/v1/access_token"
            headers = {
                "Authorization": f"Bearer {app_access_token}",
                "Content-Type": "application/json; charset=utf-8",
            }
            body = {"grant_type": "authorization_code", "code": code}
            token_resp = requests.post(user_token_url, json=body, headers=headers, timeout=10)
            token_json = token_resp.json()
            if token_resp.status_code != 200:
                return jsonify(
                    {"error": "token_http_error", "status": token_resp.status_code, "details": token_json}), 400
            user_access_token = (token_json or {}).get("data", {}).get("access_token") or token_json.get("access_token")
            if not user_access_token:
                return jsonify({"error": "token_error", "details": token_json}), 400

            # 3) 拉取用户信息
            user_info_url = "https://open.feishu.cn/open-apis/authen/v1/user_info"
            u_headers = {
                "Authorization": f"Bearer {user_access_token}",
                "Content-Type": "application/json",
            }
            u_resp = requests.get(user_info_url, headers=u_headers, timeout=10)
            u_json = u_resp.json()
            if u_resp.status_code != 200 or u_json.get("code") not in (0, None):
                return jsonify({"error": "user_info_error", "status": u_resp.status_code, "details": u_json}), 400
            u_data = u_json.get("data") or {}

            feishu_user_id = u_data.get("user_id") or (u_data.get("user") or {}).get("user_id")
            name = u_data.get("name") or (u_data.get("user") or {}).get("name") or "未知用户"
            avatar_url = u_data.get("avatar_url") or (u_data.get("user") or {}).get("avatar_url")
            email = u_data.get("email") or (u_data.get("user") or {}).get("email")
            # 尝试获取手机号
            phone = (
                    u_data.get("mobile")
                    or (u_data.get("user") or {}).get("mobile")
                    or (u_data.get("mobile_visible") if isinstance(u_data.get("mobile_visible"), str) else None)
            )
            if not phone:
                try:
                    me_resp = requests.get(
                        "https://open.feishu.cn/open-apis/contact/v3/users/me",
                        headers={
                            "Authorization": f"Bearer {user_access_token}",
                            "Content-Type": "application/json",
                        },
                        timeout=10,
                    )
                    me_json = me_resp.json()
                    if me_resp.status_code == 200 and (me_json.get("code") in (0, None)):
                        me_data = (me_json.get("data") or {}).get("user") or me_json.get("data") or {}
                        phone = me_data.get("mobile") or phone
                except Exception:
                    pass

            # 4) upsert 用户
            s = get_session()
            user = s.query(User).filter(User.feishu_user_id == feishu_user_id).first()
            if not user:
                role_val = "admin" if (name == "黄敏青") else "user"
                user = User(name=name, feishu_user_id=feishu_user_id, avatar_url=avatar_url, email=email, phone=phone,
                            type="employee", role=role_val)
                s.add(user)
                s.commit()
            else:
                user.name = name or user.name
                user.avatar_url = avatar_url or user.avatar_url
                user.email = email or user.email
                if phone:
                    user.phone = phone
                try:
                    nm = (name or "").strip()
                    if nm == "黄敏青" and user.role != "admin":
                        user.role = "admin"
                except Exception:
                    pass
                user.last_login_at = datetime.utcnow()
                s.commit()

            # 5) 签发JWT
            payload = {"user_id": user.id, "exp": datetime.utcnow() + timedelta(days=7)}
            jwt_token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

            # 6) 重定向：优先 state 指定 next
            base_url = request.host_url.rstrip("/")
            next_url = None
            try:
                if state_next:
                    from urllib.parse import unquote, urlparse
                    cand = unquote(state_next)
                    if cand.startswith("/"):
                        next_url = f"{base_url}{cand}"
                    else:
                        u = urlparse(cand)
                        if u.scheme and u.netloc and f"{u.scheme}://{u.netloc}" == base_url:
                            next_url = cand
            except Exception:
                next_url = None
            if not next_url:
                next_url = f"{base_url}/home.html"
            glue = '&' if ('?' in next_url) else '?'
            redirect_url = f"{next_url}{glue}token={jwt_token}&success=true"
            return redirect(redirect_url)
        except Exception as e:
            return jsonify({"error": "token_request_failed", "details": str(e)}), 500

    @app.get("/app_access_token")
    def get_app_access_token_endpoint():
        """手动获取 app_access_token（内部应用）。"""
        req_body = {"app_id": FEISHU_APP_ID, "app_secret": FEISHU_APP_SECRET}
        try:
            resp = requests.post(
                "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal",
                json=req_body,
                timeout=10,
            )
            data = resp.json()
            token = data.get("app_access_token") or (data.get("data", {}) or {}).get("app_access_token")
            return jsonify({"resp": token, "raw": data}), (200 if token else 400)
        except Exception as e:
            return jsonify({"error": "app_access_token_failed", "details": str(e)}), 500

    @app.post("/access_token")
    def get_user_access_token_endpoint():
        """使用 app_access_token + code 交换用户 access_token。"""
        try:
            data = request.get_json(force=True) or {}
            code = data["code"]
            app_access_token = data["app_access_token"]
        except Exception:
            return jsonify({"error": "invalid_body", "expected": ["code", "app_access_token"]}), 400
        headers = {
            "Authorization": f"Bearer {app_access_token}",
            "Content-Type": "application/json; charset=utf-8",
        }
        body = {"grant_type": "authorization_code", "code": code}
        try:
            resp = requests.post(
                url="https://open.feishu.cn/open-apis/authen/v1/access_token",
                json=body,
                headers=headers,
                timeout=10,
            )
            return jsonify({"resp": resp.json()}), (resp.status_code or 200)
        except Exception as e:
            return jsonify({"error": "user_access_token_failed", "details": str(e)}), 500

    # 简单版：接收webhooks并保存appSecret
    @app.post("/webhooks")
    def handle_feishu_webhooks():
        try:
            payload = request.get_json(force=True, silent=True) or {}
            app_secret_val = None
            data_field = payload.get("data")
            if isinstance(data_field, list) and data_field:
                app_secret_val = (data_field[0] or {}).get("appSecret")
            elif isinstance(data_field, dict):
                app_secret_val = data_field.get("appSecret")
            if app_secret_val:
                target = os.path.join(os.path.dirname(__file__), "app_secret.txt")
                with open(target, "w") as f:
                    f.write(str(app_secret_val))
            return jsonify({
                "errcode": "0",
                "description": "接收成功",
                "data": {"status": "0", "msg": "消息接收成功", "type": payload.get("bizType")},
            })
        except Exception as e:
            return jsonify({
                "errcode": "500",
                "description": "处理失败",
                "data": {"status": "1", "msg": str(e), "type": "app_authorize"},
            }), 500

    return app


def init_database():
    """初始化数据库表"""
    # 创建数据库连接
    database_url = os.getenv('DATABASE_URL', 'sqlite:///instrument_reservation.db')
    engine = create_engine(database_url)
    Base = declarative_base()

    # 重新定义模型（简化版）
    class User(Base):
        __tablename__ = "users"
        id = Column(Integer, primary_key=True)
        name = Column(String(255), nullable=False)
        employee_no = Column(String(255))
        phone = Column(String(64))
        type = Column(String(32), nullable=False, default="internal")
        role = Column(String(32), nullable=False, default="user")
        is_keeper = Column(Boolean, default=False)
        allowed_windows = Column(JSON, default=list)
        is_active = Column(String(8), default="active")
        created_by = Column(Integer, ForeignKey("users.id"))
        permissions = Column(JSON, default=dict)
        feishu_user_id = Column(String(255), unique=True)
        feishu_union_id = Column(String(255))
        feishu_open_id = Column(String(255))
        avatar_url = Column(String(1024))
        email = Column(String(255))
        created_at = Column(DateTime, default=datetime.utcnow)
        last_login_at = Column(DateTime)

    class Instrument(Base):
        __tablename__ = "instruments"
        id = Column(Integer, primary_key=True)
        name = Column(String(255), nullable=False)
        brand = Column(String(255))
        model = Column(String(255))
        category = Column(String(255))
        location = Column(String(255))
        status = Column(String(32), default="active")
        quantity = Column(Integer, default=1)
        slot_minutes = Column(Integer, default=15)
        booking_enabled = Column(Boolean, default=True)
        booking_start_time = Column(String(8))
        booking_end_time = Column(String(8))
        requires_approval = Column(Boolean, default=False)
        keeper_id = Column(Integer, ForeignKey("users.id"))
        vendor_company = Column(String(255))
        price = Column(String(255))
        production_date = Column(DateTime)
        start_use_date = Column(DateTime)
        warranty_years = Column(Integer)
        warranty_company = Column(String(255))
        admin_notes = Column(Text)
        photo_url = Column(String(1024))

    class Reservation(Base):
        __tablename__ = "reservations"
        id = Column(Integer, primary_key=True)
        user_id = Column(Integer, ForeignKey("users.id"))
        instrument_id = Column(Integer, ForeignKey("instruments.id"))
        start_time = Column(DateTime)
        end_time = Column(DateTime)
        status = Column(String(32), default="pending")
        created_at = Column(DateTime, default=datetime.utcnow)
        updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # 创建所有表
    Base.metadata.create_all(engine)
    print("Database tables created successfully.")


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5011")), debug=True)
