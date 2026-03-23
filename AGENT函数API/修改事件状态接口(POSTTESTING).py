import json
import requests
import binascii
import hashlib
import hmac
import struct
import urllib.parse
from datetime import datetime
from Crypto.Cipher import AES
from urllib.parse import urlparse

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
    try:
        # 提取必填入参
        # 取暂存值uu_id
        # 注意，为了保证智能体设计简单，这里要求输入为uuId单个字符串
        # 但实际上接口需要的是uuIds列表，后续会对输入做一个列表包装，这些逻辑对用户是无感知的
        uu_id = input_data.get("uuId", "")
        deal_status = input_data.get("dealStatus", 0)
        deal_comment = input_data.get("dealComment", "")
        
        # 验证输入类型
        if not isinstance(uu_ids, str):
            return {"error": "uuId must be an string"}
        if not isinstance(deal_status, int):
            return {"error": "dealStatus must be an integer"}
        if not isinstance(deal_comment, str):
            return {"error": "dealComment must be a string"}
        
        # 固定的认证联动码
        auth_code = "YOUR_AUTH_CODE"
        
        # 构造签名对象
        signature = Signature(auth_code=auth_code)
        
        # 接口URL
        # 如果更换接口，就改写api_url
        api_url = "https://YOUR_XDR_HOST/api/xdr/v1/incidents/:uuid/status"
        
        # 构造请求数据
        # 接口是一个批量接口，变量名是uuIds列表类型，但是受限于agent输入，只能单个传入，所以这里做一个列表包装
        data = {
            "uuIds": [uu_id],
            "dealStatus": deal_status,
            "dealComment": deal_comment
        }
        
        # 请求头
        headers = {
            "content-type": "application/json"
        }
        
        # 构造POST请求
        req = requests.Request("POST", api_url, headers=headers, data=json.dumps(data))
        
        # 对请求进行签名
        signature.signature(req=req)
        
        # 发送请求
        session = requests.Session()
        session.verify = False  # 忽略SSL证书验证，实际生产环境根据需要修改
        response = session.send(req.prepare())
        
        # 解析响应结果
        try:
            result = json.loads(response.content.decode("utf-8"))
        except json.JSONDecodeError:
            result = {"response": response.content.decode("utf-8")}
            
        return result
        
    except Exception as e:
        return {"error": str(e)}