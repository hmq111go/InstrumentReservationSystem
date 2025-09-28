import os
from flask import Flask
from app import create_app


def main():
    cmd = os.getenv("CMD", "init-db")
    if cmd == "init-db":
        # 实际创建数据库表
        from app import init_database
        init_database()
    else:
        print(f"Unknown CMD {cmd}")


if __name__ == "__main__":
    main()


