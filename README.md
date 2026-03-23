# XDR_SOC_AIAGENT

基于XDR安全运营中心与企业智能体平台的智能安全运营集成项目。

## 项目简介

本项目实现了XDR（Extended Detection and Response）安全运营中心与企业智能体平台的无缝对接，通过安全日志聚合、告警分析、智能研判等能力，构建完整的智能安全运营闭环。

### 核心功能

- **安全事件智能研判**：自动化分析安全事件，生成研判报告
- **资产溯源分析**：基于IP的资产归属与类型查询
- **工单自动处置**：对接ITSM/MPT工单系统，实现自动化处置
- **事件回调通知**：将分析结果推送回智能体平台

## 目录结构

```
XDR_SOC_AIAGENT/
├── AGENT函数API/           # 核心API函数模块（生产环境）
│   ├── CALLBACK.py         # 事件回调接口
│   ├── 获取举证信息接口.py   # 获取事件举证信息
│   ├── 事件进程实体接口.py   # 获取事件进程实体
│   └── 修改事件状态接口.py   # 修改事件状态
│
├── 处置专家/                # 工单处置模块
│   ├── itsmgettoken.py     # ITSM认证接口
│   └── mpt_test.py         # MPT工单测试
│
├── 溯源专家/                # 资产溯源模块
│   ├── Corplink_GET_TOKEN.py          # 飞连平台认证
│   ├── 代码_云盘_资产查询1.py          # IP资产查询
│   ├── 获取举证信息接口.py             # 举证信息API
│   ├── 获取事件恶意文件实体接口.py     # 恶意文件实体API
│   └── 事件进程实体接口.py             # 进程实体API
│
├── 研判/                    # 安全研判模块
│   └── MD5.txt             # XDR升级包校验
│
├── DataOpenDocument/        # 数据规范文档（需申请访问）
│   ├── 安全告警规范/
│   ├── 安全事件规范/
│   ├── 端点安全日志规范/
│   ├── 网络安全日志规范/
│   ├── 终端行为日志规范/
│   └── DNS日志规范/
│
├── TEST/                    # 测试脚本
│
└── requirements.txt         # Python依赖
```

## 环境要求

- Python 3.7+
- pip 包管理器

## 快速开始

### 1. 克隆项目

```bash
git clone https://github.com/your-org/XDR_SOC_AIAGENT.git
cd XDR_SOC_AIAGENT
```

### 2. 安装依赖

```bash
pip install -r requirements.txt
```

### 3. 配置认证信息

在各个API文件中，将占位符替换为实际的认证信息：

```python
# 示例：替换认证联动码
auth_code = "YOUR_AUTH_CODE"  # 替换为实际的auth_code

# 示例：替换飞连平台凭据
ACCESS_KEY_ID = "YOUR_ACCESS_KEY_ID"
ACCESS_KEY_SECRET = "YOUR_ACCESS_KEY_SECRET"
```

### 4. 运行测试

```bash
python TEST/test.py
```

## 认证机制

本项目使用HMAC-SHA256签名认证，核心流程：

1. 通过`auth_code`解码获取AK/SK
2. 构造规范请求字符串
3. 计算HMAC-SHA256签名
4. 添加Authorization请求头

详细实现参见各API文件中的`Signature`类。

## 模块说明

### AGENT函数API

企业智能体平台调用的核心API接口，用于：
- 获取安全事件举证信息
- 查询事件相关进程实体
- 修改事件处置状态
- 回调推送分析结果

### 处置专家

对接工单系统（ITSM/MPT），实现：
- 自动创建安全工单
- 工单状态流转
- 处置结果同步

### 溯源专家

安全事件溯源分析，支持：
- IP资产归属查询
- 恶意文件实体获取
- 进程行为关联分析

## 安全注意事项

1. **凭据管理**：切勿将AK/SK、auth_code等凭据提交到代码仓库
2. **敏感数据**：资产信息、日志样例等敏感文件已加入`.gitignore`
3. **网络访问**：生产环境建议启用SSL证书验证

## 贡献指南

1. Fork 本仓库
2. 创建功能分支 (`git checkout -b feature/your-feature`)
3. 提交更改 (`git commit -m 'Add some feature'`)
4. 推送到分支 (`git push origin feature/your-feature`)
5. 创建 Pull Request

## 许可证

本项目仅供内部使用，未经授权不得对外公开或传播。

## 联系方式

如有问题，请联系muse-xyl
