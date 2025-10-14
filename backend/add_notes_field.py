#!/usr/bin/env python3
"""
数据库迁移脚本：为预约表添加备注字段
"""
import os
import sys
from sqlalchemy import create_engine, text

def add_notes_field():
    """为预约表添加备注字段"""
    # 获取数据库连接
    database_url = os.getenv('DATABASE_URL', 'sqlite:///instrument_reservation.db')
    engine = create_engine(database_url)
    
    try:
        with engine.connect() as conn:
            # 检查字段是否已存在
            result = conn.execute(text("PRAGMA table_info(reservations)"))
            columns = [row[1] for row in result.fetchall()]
            
            if 'notes' not in columns:
                # 添加备注字段
                conn.execute(text("ALTER TABLE reservations ADD COLUMN notes TEXT"))
                print("成功添加备注字段到预约表")
            else:
                print("备注字段已存在，跳过添加")
                
        print("数据库迁移完成")
    except Exception as e:
        print(f"数据库迁移失败: {e}")
        sys.exit(1)

if __name__ == "__main__":
    add_notes_field()
