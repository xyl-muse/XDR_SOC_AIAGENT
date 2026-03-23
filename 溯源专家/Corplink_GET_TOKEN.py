# 导入必要依赖库（需提前安装：pip install requests）
import requests
import json

def get_feilian_access_token(
    endpoint: str,
    access_key_id: str,
    access_key_secret: str,
    expires_in: int = 315360000  # 默认2小时过期，私有化场景可调整
) -> dict:
    """
    调用飞连开放平台接口获取access_token
    :param endpoint: 飞连私有化部署的服务器域名/IP（必填，需联系管理员确认）
    :param access_key_id: 管理后台申请的AccessKey ID（必填）
    :param access_key_secret: 管理后台申请的AccessKey Secret（必填）
    :param expires_in: token过期时长（秒），默认7200，范围7200~315360000
    :return: 包含access_token的响应字典（失败时抛出异常）
    """
    # 1. 接口基础配置（按文档规范定义）
    uri_schema = "https"  # 固定HTTPS协议
    resource_path = "/api/open/v1/token"  # 接口路径
    request_url = f"{uri_schema}://{endpoint}{resource_path}"  # 拼接完整请求URL

    # 2. 构造请求头（Headers参数）
    headers = {
        "Content-Type": "application/json;charset=utf-8"  # 固定值，必填
    }

    # 3. 构造请求体（Body参数，JSON格式）
    request_body = {
        "access_key_id": access_key_id,
        "access_key_secret": access_key_secret
    }
    # 可选参数：仅当需要自定义过期时长时添加（私有化场景生效）
    if expires_in:
        # 校验过期时长范围（文档要求最小值7200）
        if expires_in < 7200:
            raise ValueError(f"expires_in最小值为7200秒，当前传入{expires_in}")
        request_body["expires_in"] = expires_in

    try:
        # 4. 发送POST请求（严格遵循接口Method要求）
        response = requests.post(
            url=request_url,
            headers=headers,
            json=request_body,  # 自动序列化JSON并设置Content-Length
            timeout=30  # 超时时间，避免无限等待
        )

        # 5. 响应状态码校验（HTTP层面）
        response.raise_for_status()

        # 6. 解析JSON响应（接口返回结果）
        result = response.json()
        return result

    # 异常处理：覆盖常见失败场景
    except requests.exceptions.ConnectionError:
        raise Exception(f"连接失败：无法访问{endpoint}，请检查域名/IP是否正确或网络连通性")
    except requests.exceptions.Timeout:
        raise Exception(f"请求超时：连接{endpoint}超过30秒未响应")
    except requests.exceptions.HTTPError as e:
        raise Exception(f"HTTP请求失败：状态码{response.status_code}，响应内容：{response.text}")
    except json.JSONDecodeError:
        raise Exception(f"响应解析失败：接口返回非JSON格式内容，内容为：{response.text}")
    except Exception as e:
        raise Exception(f"获取access_token失败：{str(e)}")

# -------------------------- 调用示例 --------------------------
if __name__ == "__main__":
    # ========== 请替换为实际配置 ==========
    FEILIAN_ENDPOINT = "YOUR_FEILIAN_ENDPOINT"  # 私有化部署的飞连服务器域名/IP
    ACCESS_KEY_ID = "YOUR_ACCESS_KEY_ID"          # 管理后台申请的AccessKey ID
    ACCESS_KEY_SECRET = "YOUR_ACCESS_KEY_SECRET"  # 管理后台申请的AccessKey Secret
    EXPIRES_IN = 7200  # token过期时长，私有化场景可调整为更大值（需管理员配置）
    # =====================================

    try:
        # 调用函数获取access_token
        token_result = get_feilian_access_token(
            endpoint=FEILIAN_ENDPOINT,
            access_key_id=ACCESS_KEY_ID,
            access_key_secret=ACCESS_KEY_SECRET,
            expires_in=EXPIRES_IN
        )
        # 打印响应结果（实际使用时可提取access_token字段）
        print("获取access_token成功，响应结果：")
        print(json.dumps(token_result, ensure_ascii=False, indent=2))
        
        # 提取access_token（需根据接口实际返回字段调整，示例假设返回字段为access_token）
        if "access_token" in token_result:
            access_token = token_result["access_token"]
            print(f"\n提取到access_token：{access_token}")
    except Exception as e:
        print(f"获取access_token失败：{e}")