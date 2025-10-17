import json
import os
from typing import Dict, Any, Tuple

import requests


def get_tenant_access_token(app_id: str, app_secret: str) -> Tuple[str, Exception]:
    """获取 tenant_access_token

    Args:
        app_id: 应用ID
        app_secret: 应用密钥

    Returns:
        Tuple[str, Exception]: (access_token, error)
    """
    url = "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal"
    payload = {
        "app_id": app_id,
        "app_secret": app_secret
    }
    headers = {
        "Content-Type": "application/json; charset=utf-8"
    }

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        response.raise_for_status()

        result = response.json()
        if result.get("code", 0) != 0:
            return "", Exception(f"failed to get tenant_access_token: {result.get('msg', 'unknown error')}")

        return result["tenant_access_token"], None

    except Exception as e:
        return "", e


def send_message_to_chat(tenant_access_token: str, chat_id: str, content: str) -> Tuple[Dict[str, Any], Exception]:
    """向群组发送消息

    Args:
        tenant_access_token: 租户访问令牌
        chat_id: 群组ID
        content: 消息内容

    Returns:
        Tuple[Dict[str, Any], Exception]: (响应数据, 错误)
    """
    url = "https://open.feishu.cn/open-apis/im/v1/messages"
    params = {
        "receive_id_type": "chat_id"
    }
    headers = {
        "Authorization": f"Bearer {tenant_access_token}",
        "Content-Type": "application/json; charset=utf-8"
    }

    msg_content = {"text": content}

    payload = {
        "receive_id": chat_id,
        "msg_type": "text",
        "content": json.dumps(msg_content, ensure_ascii=False)
    }

    try:
        response = requests.post(url, params=params, headers=headers, json=payload, timeout=10)
        response.raise_for_status()

        result = response.json()
        if result.get("code", 0) != 0:
            return {}, Exception(f"failed to send message: {result.get('msg', 'unknown error')}")

        return result, None

    except Exception as e:
        return {}, e


def send_group_text_via_env(text: str) -> bool:
    """使用环境变量 APP_ID/APP_SECRET/CHAT_ID 直接向群里发送文本消息。
    供简单脚本或后端调用。
    """
    app_id = os.getenv("FEISHU_APP_ID", "cli_a84d36f557729013")
    app_secret = os.getenv("FEISHU_APP_SECRET", "ZebTrPQlsZKHOA2nJeAv0gjvotAqOiGf")
    #
    # app_id = os.getenv("APP_ID") or os.getenv("FEISHU_APP_ID")
    # app_secret = os.getenv("APP_SECRET") or os.getenv("FEISHU_APP_SECRET")
    chat_id = os.getenv("CHAT_ID", "oc_fddda12d48d3b4007c9494214ea2c0fb")
    if not app_id or not app_secret or not chat_id:
        return False
    token, err = get_tenant_access_token(app_id, app_secret)
    if err or not token:
        return False
    _, err2 = send_message_to_chat(token, chat_id, text)
    return err2 is None
