#!/usr/bin/env python
import base64
import requests
import json

# 禁用SSL警告（测试环境必须）
requests.packages.urllib3.disable_warnings()

# 认证
login_url='YOUR_ITSM_LOGIN_URL'
params = {
"username": "YOUR_USERNAME",
"password": "YOUR_PASSWORD"
}

# 编码
login_info=base64.b64encode(json.dumps(params).encode('utf-8')).decode('utf-8')
# 构建参数
login_data={}
login_data["info"] = login_info
# 打印login_info
print("login_data:",login_data)

# 登录认证（补充必要的请求头+SSL验证+超时）
headers = {"Content-Type": "multipart/form-data"}  # 接口要求的头必须加
resp_data = requests.post(
    login_url,
    data=login_data,
    headers=headers,
    verify=False,  # 测试环境SSL证书问题，必须加
    timeout=30
)

# ========== 关键：打印完整返回数据，定位问题 ==========
print("\n===== 接口返回详情 =====")
print(f"请求状态码：{resp_data.status_code}")  # 看是否200（非200说明接口本身报错）
print(f"原始base64响应：{resp_data.text}")     # 接口返回的原始base64字符串
# 解码后打印完整JSON
data_decode = base64.b64decode(resp_data.text).decode('utf-8')
print(f"解码后完整数据：{data_decode}")
data_dict = json.loads(data_decode)
print(f"JSON解析后完整字典：{data_dict}")
print("========================\n")

# ========== 容错获取token/key ==========
# 先判断rows是否存在，避免None调用get
rows = data_dict.get('rows')  # 先拿到rows的值（可能是None/字典）
if rows is not None:
    token = rows.get('token')
    key = rows.get('key')
    print("token:", token)
    print("key:", key)
else:
    # 打印错误原因（重点看接口返回的msg/code）
    print(f"❌ 未找到rows字段！接口返回的关键信息：")
    print(f"错误码：{data_dict.get('code')}")
    print(f"错误信息：{data_dict.get('msg')}")