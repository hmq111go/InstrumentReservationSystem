#!/usr/bin/env python3
"""
添加数据库索引以提升查询性能
"""
import os
import sys
from sqlalchemy import create_engine, text

def add_indexes():
    # 获取数据库连接
    database_url = os.getenv('DATABASE_URL', 'sqlite:///instrument_reservation.db')
    engine = create_engine(database_url)
    
    # 需要添加的索引
    indexes = [
        # 预约表索引
        "CREATE INDEX IF NOT EXISTS idx_reservations_user_id ON reservations(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_reservations_instrument_id ON reservations(instrument_id)",
        "CREATE INDEX IF NOT EXISTS idx_reservations_status ON reservations(status)",
        "CREATE INDEX IF NOT EXISTS idx_reservations_start_time ON reservations(start_time)",
        "CREATE INDEX IF NOT EXISTS idx_reservations_created_at ON reservations(created_at)",
        
        # 仪器表索引
        "CREATE INDEX IF NOT EXISTS idx_instruments_keeper_id ON instruments(keeper_id)",
        "CREATE INDEX IF NOT EXISTS idx_instruments_category ON instruments(category)",
        "CREATE INDEX IF NOT EXISTS idx_instruments_name ON instruments(name)",
        
        # 用户表索引
        "CREATE INDEX IF NOT EXISTS idx_users_feishu_user_id ON users(feishu_user_id)",
        "CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)",
        "CREATE INDEX IF NOT EXISTS idx_users_is_keeper ON users(is_keeper)",
        
        # 维护记录表索引
        "CREATE INDEX IF NOT EXISTS idx_maintenance_records_instrument_id ON maintenance_records(instrument_id)",
        "CREATE INDEX IF NOT EXISTS idx_maintenance_records_created_by ON maintenance_records(created_by)",
        "CREATE INDEX IF NOT EXISTS idx_maintenance_records_status ON maintenance_records(status)",
    ]
    
    with engine.connect() as conn:
        for index_sql in indexes:
            try:
                conn.execute(text(index_sql))
                print(f"✓ 创建索引: {index_sql}")
            except Exception as e:
                print(f"✗ 创建索引失败: {index_sql} - {e}")
        
        conn.commit()
        print("索引创建完成！")

if __name__ == "__main__":
    add_indexes()
