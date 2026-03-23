import json
import requests
import binascii
import hashlib
import hmac
import struct
import urllib.parse
from datetime import datetime
from Crypto.Cipher import AES  # 引用pycryptodome库
from urllib.parse import urlparse

# 常量定义
EXTEND_HEADER = "algorithm=HMAC-SHA256, Access=%s, SignedHeaders=%s, Signature=%s"
SIGNED_HEADERS = "SignedHeaders"
SIGNATURE = "Signature"
ACCESS = "Access"
TOTAL_STR = "HMAC-SHA256\n%s\n%s"
AUTH_HEADER_KEY = "Authorization"
SDK_HOST_KEY = "sdk-host"
CONTENT_TYPE_KEY = "content-type"
SDK_CONTENT_TYPE_KEY = "sdk-content-type"
DEFAULT_CONTENT_TYPE = "application/json"
SIGN_DATE_KEY = "sign-date"
AUTH_CODE_PARAMS = "%s+%s+%s+%s+%s+%s+%s+%s"
AUTH_INFO_MAP_SIZE = 4
MAP_STRING_SIZE = 2
AUTH_CODE_PARAMS_NUM = 14


class Signature(object):
    def __init__(self, auth_code=None, ak=None, sk=None):
        if ak and sk:
            self.__access_key = ak
            self.__secret_key = sk
        elif auth_code:
            self.__access_key, self.__secret_key = self.__decode_auth_code(auth_code)
        else:
            raise Exception("signature init error")

    def signature(self, req):
        if not self.__access_key and self.__secret_key:
            raise Exception("ak sk can't be blank")
        if not req.url or not req.method:
            raise Exception("params illegal,params can't be nil or blank except payload or query string")
        req.json = None if req.json == {} else req.json
        # 提前处理一下payload,兼容json、data、None
        payload = req.data or json.dumps(req.json) if req.data or req.json else ""

        host = self.__get_host(req.url)
        req.headers, sign_date = self.__header_check(req.headers, host)

        # 处理签名头和标准头
        header_str, sign_header_str = self.__sign_header_handler(req.headers)

        # 获取标准字符串
        canonical_str = self.__get_canonical_str(req.method, req.url, req.params, header_str, payload, sign_header_str)

        # 计算 SHA256 哈希值
        hashed_canonical_request = self.__sha256_hex_upper(canonical_str.encode("utf-8"))

        # 拼接总字符串并计算 HMAC-SHA256值
        total_str = TOTAL_STR % (sign_date, hashed_canonical_request)

        # 最终签名值
        signature = self.__hmac_sha256_hex(self.__secret_key, total_str)

        req.headers[AUTH_HEADER_KEY] = EXTEND_HEADER % (self.__access_key, sign_header_str, signature)

    def __decode_auth_code(self, auth_code):
        builder_str = self.__reverse_hex(auth_code)
        builders = str.split(builder_str.decode("utf-8"), "|")
        if len(builders) != AUTH_CODE_PARAMS_NUM:
            raise Exception("auth code decode error")
        aes_secret = self.__calculate_aes_secret(builders)
        ak = self.__aes_cbc_decrypt(builders[9], aes_secret)
        sk = self.__aes_cbc_decrypt(builders[10], aes_secret)
        return ak, sk

    @staticmethod
    def __calculate_aes_secret(builders):
        build_str = AUTH_CODE_PARAMS % (
            builders[0], builders[1], builders[2], builders[3],
            builders[4], builders[5], builders[6], builders[11],
        )
        return hashlib.sha256(build_str.encode("utf-8")).digest()

    @staticmethod
    def __get_host(uri):
        parsed_url = urllib.parse.urlparse(uri)
        return parsed_url.netloc

    @staticmethod
    def __header_check(headers, host):
        if headers is None:
            headers = {}
        elif not isinstance(headers, dict):
            raise Exception("headers format illegal")
        if SDK_HOST_KEY not in headers:
            headers[SDK_HOST_KEY] = host
        if CONTENT_TYPE_KEY not in headers:
            headers[SDK_CONTENT_TYPE_KEY] = DEFAULT_CONTENT_TYPE
        else:
            headers[SDK_CONTENT_TYPE_KEY] = headers[CONTENT_TYPE_KEY]
        if SIGN_DATE_KEY not in headers:
            sign_date = datetime.now().strftime('%Y%m%dT%H%M%SZ')
            headers[SIGN_DATE_KEY] = sign_date
        else:
            sign_date = headers[SIGN_DATE_KEY]
        return headers, sign_date

    @staticmethod
    def __sign_header_handler(headers):
        header_keys = [(k, v) for k, v in headers.items()]
        header_keys.sort(key=lambda x: x[0].lower())
        header_builder = []
        sign_header_builder = []
        for key, value in header_keys:
            header_builder.append(f"{key}:{value}\n")
            sign_header_builder.append(f"{key};")
        sign_header_str = "".join(sign_header_builder)
        header_str = "".join(header_builder)
        length = len(sign_header_str)
        if length > 0:
            sign_header_str = sign_header_str[:length - 1]
        return header_str, sign_header_str

    def __get_canonical_str(self, method, uri, params, headers_str, payload, sign_header_str):
        builder = []
        builder.append(method)
        builder.append("\n")
        builder.append(self.__url_transform(uri))
        builder.append("\n")
        transform = self.__query_str_transform(params)
        builder.append(transform)
        builder.append("\n")
        builder.append(headers_str)
        builder.append(sign_header_str)
        builder.append("\n")
        builder.append(self.__payload_transform(payload))

        return "".join(builder)

    @staticmethod
    def __url_transform(url_str):
        parsed_url = urlparse(url_str)
        relative_path = parsed_url.path
        if not relative_path.endswith("/"):
            relative_path += "/"
        # 此处转换一次处理URL中存在的中文字符
        return urllib.parse.quote(relative_path, encoding='utf-8')

    @staticmethod
    def __query_str_transform(params):
        params = sorted(params.items(), key=lambda x: x[0])
        return urllib.parse.urlencode(params).replace("%3D", "=")

    def __payload_transform(self, payload):
        payload = payload.encode("utf-8")

        byte_values = [struct.unpack('b', bytes([byte]))[0] for byte in payload]
        byte_values.sort()
        new_payload = bytearray()
        for byte_value in byte_values:
            new_payload.append(byte_value)
        new_payload = self.__remove_spaces(new_payload)
        return self.__sha256_hex_upper(new_payload)

    @staticmethod
    def __remove_spaces(b):
        j = 0
        for i in range(len(b)):
            if b[i] != 32:
                if i != j:
                    b[j] = b[i]
                j += 1
        return b[:j]

    @staticmethod
    def __hmac_sha256_hex(secret_key, data):
        mac = hmac.new(secret_key.encode('utf-8'), data.encode('utf-8'), hashlib.sha256)
        sum = mac.digest()
        return binascii.hexlify(sum).decode('utf-8').upper()

    @staticmethod
    def __sha256_hex_upper(b):
        hashed_b = hashlib.sha256(b).digest()
        hex_upper = binascii.hexlify(hashed_b).decode('utf-8').upper()
        return hex_upper

    @staticmethod
    def __reverse_hex(auth_code):
        return binascii.unhexlify(auth_code)

    @staticmethod
    def __aes_cbc_decrypt(cipher_text, key):
        cipher = AES.new(key, AES.MODE_CBC, bytearray(AES.block_size))
        return cipher.decrypt(bytes.fromhex(cipher_text)).decode("utf-8")


def userFunction(input_data):
    # 从输入参数中获取uuid和data
    uuid = input_data.get("uuid")
    data = input_data.get("data")
    
    if not uuid:
        return {"error": "缺少uuid参数"}
    if not data:
        return {"error": "缺少data参数"}
    
    # 固定的认证联动码（请替换为实际的auth_code）
    auth_code = "YOUR_AUTH_CODE"
    
    # 构造请求URL（请替换为实际的回调地址）
    api_url = "https://YOUR_CALLBACK_HOST/callback/incident"
    
    # 构造请求体
    request_body = {
        "uuid": uuid,
        "data": data
    }
    
    # 初始化签名对象
    try:
        signature = Signature(auth_code=auth_code)
    except Exception as e:
        return {"error": f"初始化签名对象失败: {str(e)}"}
    
    # 构造POST请求
    headers = {
        "content-type": "application/json"
    }
    
    # 创建请求对象，注意这里使用json参数传递请求体
    req = requests.Request("POST", api_url, headers=headers, json=request_body)
    
    # 对请求进行签名
    try:
        signature.signature(req=req)
    except Exception as e:
        return {"error": f"签名过程出错: {str(e)}"}
    
    # 发送请求
    try:
        session = requests.Session()
        # 生产环境建议启用SSL证书验证
        # session.verify = True
        session.verify = False  # 测试环境忽略SSL证书验证
        response = session.send(req.prepare())
        
        # 解析响应内容
        result = response.content.decode("utf-8")
        
        # 检查HTTP状态码
        if response.status_code >= 400:
            return {"error": f"请求失败，状态码: {response.status_code}, 响应: {result}"}
        
        # 尝试转换为JSON格式（如果接口返回JSON）
        try:
            json_result = json.loads(result)
            return {"response": json_result}
        except json.JSONDecodeError:
            return {"response": result}
            
    except Exception as e:
        return {"error": f"请求发送出错: {str(e)}"}
    
if __name__ == "__main__":
    """
    本地测试主函数
    在命令行直接运行此文件时会执行此部分代码
    在智能体平台运行时不会执行此部分
    """
    
    # 测试: 使用脱敏测试数据
    print("=== 测试: 直接字典输入 ===")
    test_input = {
        "uuid": "incident-test-0000-0000-0000-000000000001",
        "data": "### 【事件报告示例】\n- **事件等级**：Ⅳ级\n- **事件类型**：终端安全事件\n- **报告日期**：2025-01-01\n- **描述**：这是一个脱敏的测试事件报告示例。\n### 【执行摘要】\n检测到终端存在可疑活动，经研判定为Ⅳ级事件。\n### 【处置建议】\n建议进行隔离排查。"
    }
    result = userFunction(test_input)
    print(f"结果: {json.dumps(result, ensure_ascii=False, indent=2)}\n")
