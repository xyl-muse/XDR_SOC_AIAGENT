import re
import ipaddress

# ====================== 预设数据库（固定不可修改） ======================
# 数据库1：资产归属信息库（按原始顺序存储）
# 格式：(大区, 分公司, CIDR网段)
attribution_db = [
    # 示例数据，请替换为实际资产信息
    # ("北京", "北京分公司", "10.0.0.0/8"),
    # ("上海", "上海分公司", "172.16.0.0/12"),
]

# 数据库2：资产类型库（排除最后兜底的办公PC，按原始顺序存储）
# 格式：(资产类型, IP段正则)
asset_type_db = [
    # 示例数据，请替换为实际资产类型信息
    # ("办公系统", "10\\.1\\..*-10\\.2\\..*"),
    # ("生产系统", "192\\.168\\..*"),
]

# ====================== 核心处理函数 ======================
def extract_valid_ip(input_str):
    """从输入字符串提取第一个有效IPv4地址，无效返回None"""
    # 清洗输入：去除首尾空格
    cleaned_input = input_str.strip()
    if not cleaned_input:
        return None
    
    # 正则匹配IPv4格式（0-255四段）
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    ip_matches = re.findall(ip_pattern, cleaned_input)
    
    if not ip_matches:
        return None
    
    # 验证第一个匹配的IP是否真的有效（排除如256.0.0.1这类伪匹配）
    first_ip = ip_matches[0]
    parts = first_ip.split('.')
    if len(parts) != 4:
        return None
    
    for part in parts:
        try:
            num = int(part)
            if num < 0 or num > 255:
                return None
        except ValueError:
            return None
    
    return first_ip

def is_ip_in_cidr(ip_str, cidr_str):
    """判断IP是否在指定CIDR网段内"""
    try:
        ip = ipaddress.IPv4Address(ip_str)
        network = ipaddress.IPv4Network(cidr_str, strict=False)
        return ip in network
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        return False

def is_ip_in_asset_segment(ip_str, segment_str):
    """判断IP是否在资产类型库的复杂网段内（支持范围/通配符/混合/CIDR）"""
    try:
        ip = ipaddress.IPv4Address(ip_str)
        
        # 1. 处理混合格式：优先匹配括号内的范围
        if '(' in segment_str and ')' in segment_str:
            bracket_seg = re.search(r'\((.*?)\)', segment_str).group(1)
            if is_ip_in_asset_segment(ip_str, bracket_seg):
                return True
            # 括号内不匹配则匹配外部CIDR
            cidr_seg = segment_str.split('(')[0].strip()
            return is_ip_in_cidr(ip_str, cidr_seg)
        
        # 2. 处理范围格式（x.x.x.*-x.x.x.*）
        elif '-' in segment_str:
            start_seg, end_seg = segment_str.split('-', 1)
            
            # 通配符转具体IP范围（x.x.x.* → x.x.x.1 到 x.x.x.255）
            def wildcard_to_range(seg):
                parts = seg.strip().split('.')
                if len(parts) != 4 or parts[3] != '*':
                    return seg, seg  # 非通配符直接返回
                return f"{parts[0]}.{parts[1]}.{parts[2]}.1", f"{parts[0]}.{parts[1]}.{parts[2]}.255"
            
            start_ip_str, _ = wildcard_to_range(start_seg)
            end_ip_str, _ = wildcard_to_range(end_seg)
            
            # 验证起始/结束IP有效性
            start_ip = ipaddress.IPv4Address(start_ip_str)
            end_ip = ipaddress.IPv4Address(end_ip_str)
            return start_ip <= ip <= end_ip
        
        # 3. 处理通配符格式（x.x.x.*）
        elif '*' in segment_str:
            seg_parts = segment_str.split('.')
            ip_parts = ip_str.split('.')
            if len(seg_parts) != 4 or seg_parts[3] != '*':
                return False
            # 前三位匹配且第四位1-255
            return (seg_parts[0] == ip_parts[0] and
                    seg_parts[1] == ip_parts[1] and
                    seg_parts[2] == ip_parts[2] and
                    1 <= int(ip_parts[3]) <= 255)
        
        # 4. 处理纯CIDR格式
        else:
            return is_ip_in_cidr(ip_str, segment_str)
    
    except (ipaddress.AddressValueError, IndexError, ValueError):
        return False

def query_attribution(ip_str):
    """查询归属库，返回(大区, 分公司)，未匹配返回([无], [无])"""
    for region, branch, cidr in attribution_db:
        if is_ip_in_cidr(ip_str, cidr):
            return region, branch
    return "[无]", "[无]"

def query_asset_type(ip_str):
    """查询资产类型库，未匹配返回兜底的'办公PC'"""
    for asset_type, segment in asset_type_db:
        if is_ip_in_asset_segment(ip_str, segment):
            return asset_type
    return "办公PC"

def generate_result_json(ip_str):
    """生成符合格式要求的JSON结果字符串"""
    region, branch = query_attribution(ip_str)
    asset_type = query_asset_type(ip_str)
    
    # 严格遵循输出格式：分行、键顺序、英文标点
    json_str = f"""{{
  "受害资产ip": "{ip_str}",
  "资产数据来源": "统计云盘",
  "资产归属大区": "{region}",
  "资产归属分公司": "{branch}",
  "资产类型": "{asset_type}"
}}"""
    return json_str

# ====================== 主函数 ======================
def userFunction(input_data):
    """
    核心入口函数
    :param input_data: 输入字典，格式 {"hostIp": "用户查询字符串"}
    :return: 输出字典，格式 {"result": "查询结果"}
             结果为JSON字符串或"未查询到该资产"
    """
    # 提取输入的查询字符串
    query_str = input_data.get("hostIp", "").strip()
    
    # 步骤1：提取有效IP
    valid_ip = extract_valid_ip(query_str)
    
    # 步骤4：结果整合输出
    if valid_ip is None:
        return {"result": "未查询到该资产"}
    else:
        return {"result": generate_result_json(valid_ip)}

# ====================== 测试示例（可选执行） ======================
"""

if __name__ == "__main__":
    # 示例1：匹配归属+资产类型
    test1 = userFunction({"hostIp": "10.0.64.2"})
    print("示例1结果：")
    print(test1["result"])
    print("-" * 60)
    
    # 示例2：匹配资产类型，未匹配归属
    test2 = userFunction({"hostIp": "172.29.220.1"})
    print("示例2结果：")
    print(test2["result"])
    print("-" * 60)
    
    # 示例3：未匹配资产类型，兜底办公PC
    test3 = userFunction({"hostIp": "查询192.168.1.100"})
    print("示例3结果：")
    print(test3["result"])
    print("-" * 60)
    
    # 示例4：无效IP
    test4 = userFunction({"hostIp": "查询IP：256.256.256.256"})
    print("示例4结果：")
    print(test4["result"])

"""