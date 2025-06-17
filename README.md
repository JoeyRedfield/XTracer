# XTracer

XTracer是一个基于Frida的Android应用动态分析工具，用于追踪和记录Android应用的API调用行为，主要用于恶意软件检测和行为分析。

## 项目概述

XTracer通过动态Hook技术监控Android应用的关键API调用，包括：
- Intent相关操作
- 权限请求
- 电话信息获取
- 设备标识符访问
- 位置服务
- 网络连接
- 蓝牙操作
- 相机使用
等479个关键API接口。

## 主要功能

### 1. 动态Hook分析 (XTracer.py)
- 支持单个APK分析和批量分析模式
- 自动安装、运行、监控、卸载APK
- 使用Monkey进行自动化测试
- 实时收集API调用数据

### 2. 设备连接管理 (XT_checker.py)
- 自动启动模拟器
- 检测ADB设备连接状态
- 管理Frida服务器连接
- 端口转发配置

### 3. 日志数据处理 (XT_read_log.py)
- 将Hook数据转换为特征向量
- 支持频率特征提取
- 支持序列特征提取
- 生成机器学习可用的CSV数据集

### 4. 配置管理 (XT_config.py)
- YAML配置文件管理
- 模拟器路径配置
- 设备IP地址配置

## 项目结构

```
XTracer/
├── XTracer.py          # 主程序，负责APK动态分析
├── XTracer.js          # Frida脚本，实现API Hook
├── XT_checker.py       # 设备连接检查和管理
├── XT_read_log.py      # 日志数据处理和特征提取
├── XT_config.py        # 配置文件管理
├── config/
│   └── config.yml      # 配置文件
└── source/
    ├── hook_list_479.csv           # Hook API列表
    └── frida-server_start.bat      # Frida服务器启动脚本
```

## 环境要求

### 软件依赖
- Python 3.x
- Frida
- ADB (Android Debug Bridge)
- Android模拟器 (如BlueStacks)
- PyQt5

### Python包依赖
```bash
pip install frida-tools
pip install PyQt5
pip install pyyaml
```

## 配置说明

### config/config.yml
```yaml
baseConf:
  simulator_path: "模拟器启动路径"
  simulator_ip: "127.0.0.1:5555"  # 模拟器IP地址
```

## 使用方法

### 1. 环境准备
1. 启动Android模拟器
2. 确保ADB连接正常
3. 启动Frida服务器

### 2. 设备检查
```bash
python XT_checker.py
```
此脚本会自动：
- 启动模拟器
- 检查ADB连接
- 验证Frida服务器状态

### 3. 运行分析
```bash
python XTracer.py
```

### 4. 数据处理
```bash
python XT_read_log.py
```

## 分析模式

### 单个APK分析模式
- 设置 `hook_mode = 'single'`
- 分析指定目录中的单个APK
- 生成详细的行为日志

### 批量分析模式
- 设置 `hook_mode = 'mult'`
- 批量处理目录中的所有APK
- 自动记录成功/失败状态

## 输出数据

### 行为日志
- 格式：JSON
- 内容：API调用序列，包括类名、方法名、参数
- 存储路径：`{apk_path}/feature/{md5}.txt`

### 特征数据
- 频率特征：API调用频次统计
- 序列特征：API调用时序信息
- 输出格式：CSV

## Hook的API类别

1. **Intent相关**：Intent创建、参数设置、Action设置
2. **权限相关**：权限请求API
3. **设备信息**：IMEI、设备ID、序列号等
4. **位置服务**：GPS定位、网络定位
5. **网络通信**：WiFi信息、网络状态
6. **传感器**：相机、蓝牙等硬件访问
7. **包管理**：已安装应用列表、包信息查询

## 注意事项

1. 确保模拟器Root权限
2. Frida服务器版本需与客户端匹配
3. 分析过程中保持设备连接稳定
4. 大批量分析时注意磁盘空间

## 故障排除

### 常见问题
1. **ADB连接失败**：检查模拟器状态和端口配置
2. **Frida连接失败**：确认Frida服务器正常运行
3. **Hook失败**：检查目标应用权限和加固情况
4. **APK安装失败**：确认APK完整性和签名

## 许可证

本项目仅用于学术研究和安全分析目的。

## 贡献

欢迎提交Issue和Pull Request来改进这个项目。