Instrument Reservation System (Flask + MySQL + Vue)

## 权限系统说明

### 用户角色
- **超级管理员 (super_admin)**: 系统最高权限，可以管理所有用户和系统设置
- **管理员 (admin)**: 可以管理用户、仪器，设置审批流程
- **使用用户 (user)**: 基础用户，可以预约仪器
- **保管员**: 使用用户中的特殊角色，可以管理被分配的仪器

### 保管员权限
- 拥有使用用户的所有权限（包括预约）
- 可以管理被分配的特定仪器
- 可以审核对应仪器的预约申请
- 可以暂停/启用对应仪器的预约
- 可以设置对应仪器的预约时间

## 快速开始

1) Create and fill .env from .env.example
2) python3 -m venv .venv && source .venv/bin/activate
3) pip install -r backend/requirements.txt
4) Run DB migrations/init: python backend/manage.py init-db
5) **重要**: 运行权限系统迁移: python migrate_add_keeper_field.py
6) Start API: PORT=5010 python backend/app.py
7) Open frontend/index.html in a browser (or serve via any static server)

## 使用提示
- Frontend will try `http://localhost:5010` first; you can set the API base URL at the top of the page and click 保存API.
- Use the 一键示例数据 button to quickly seed one instrument and two users (internal/external). Then select a用户并在网格中点击预约。
- 管理员可以在仪器编辑界面为仪器分配保管员


