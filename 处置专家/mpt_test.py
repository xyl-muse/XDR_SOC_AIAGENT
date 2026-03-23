#!/usr/bin/env python
import base64
import requests
import json
# 认证
login_url='YOUR_MPT_LOGIN_URL'
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
# 登录认证
resp_data = requests.post(login_url,data=login_data)
# 获取token
data_text = resp_data.text
data_decode = base64.b64decode(data_text).decode('utf-8')
data_dict = json.loads(data_decode)
token = data_dict.get('rows').get('token')
key = data_dict.get('rows').get('key')
print("token:",token)