#!/usr/bin/env python3
"""
性能监控脚本
"""
import time
import requests
import psutil
import os

def check_performance():
    base_url = "http://1.13.176.116"
    
    # 测试 API 响应时间
    apis = [
        "/api/health",
        "/api/instruments",
        "/api/reservations",
        "/api/users"
    ]
    
    print("=== API 响应时间测试 ===")
    for api in apis:
        try:
            start_time = time.time()
            response = requests.get(f"{base_url}{api}", timeout=10)
            end_time = time.time()
            
            response_time = (end_time - start_time) * 1000  # 转换为毫秒
            status = "✓" if response.status_code == 200 else "✗"
            print(f"{status} {api}: {response_time:.2f}ms (状态码: {response.status_code})")
        except Exception as e:
            print(f"✗ {api}: 请求失败 - {e}")
    
    # 系统资源使用情况
    print("\n=== 系统资源使用情况 ===")
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    print(f"CPU 使用率: {cpu_percent}%")
    print(f"内存使用率: {memory.percent}% ({memory.used // 1024 // 1024}MB / {memory.total // 1024 // 1024}MB)")
    print(f"磁盘使用率: {disk.percent}% ({disk.used // 1024 // 1024}MB / {disk.total // 1024 // 1024}MB)")
    
    # 检查服务状态
    print("\n=== 服务状态检查 ===")
    try:
        # 检查 Nginx
        nginx_status = os.system("systemctl is-active nginx > /dev/null 2>&1")
        print(f"Nginx: {'✓ 运行中' if nginx_status == 0 else '✗ 未运行'}")
        
        # 检查后端服务
        instrument_status = os.system("systemctl is-active instrument > /dev/null 2>&1")
        print(f"后端服务: {'✓ 运行中' if instrument_status == 0 else '✗ 未运行'}")
        
    except Exception as e:
        print(f"服务状态检查失败: {e}")

if __name__ == "__main__":
    check_performance()
