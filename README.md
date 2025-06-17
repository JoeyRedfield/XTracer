# XTracer

XTracer是一个基于Frida的Android应用动态分析工具，专为Ubuntu 22.04环境设计，用于追踪和记录Android应用的API调用行为，主要用于恶意软件检测和行为分析。

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
- 支持测试模式的批量APK分析
- 自动处理类别0（良性）和类别1（恶意）样本
- 自动安装、运行、监控、卸载APK
- 使用Monkey进行自动化测试
- 实时收集API调用数据
- 支持断点续传功能

### 2. 设备连接管理 (XT_checker.py)
- 自动启动Android模拟器
- 检测ADB设备连接状态
- 管理Frida服务器连接
- 端口转发配置
- 适配Linux环境命令

### 3. 日志数据处理 (XT_read_log.py)
- 将Hook数据转换为特征向量
- 支持频率特征提取
- 支持序列特征提取
- 生成机器学习可用的CSV数据集
- 自动处理测试结果数据

### 4. 配置管理 (XT_config.py)
- YAML配置文件管理
- 跨平台路径处理
- 自动创建必要目录

## 项目结构

```
XTracer/
├── XTracer.py              # 主程序，负责APK动态分析
├── XTracer.js              # Frida脚本，实现API Hook
├── XT_checker.py           # 设备连接检查和管理
├── XT_read_log.py          # 日志数据处理和特征提取
├── XT_config.py            # 配置文件管理
├── config/
│   └── config.yml          # 配置文件
├── source/
│   ├── hook_list_479.csv   # Hook API列表
│   └── frida-server_start.sh  # Frida服务器启动脚本(Linux)
├── test_apk/               # 测试APK文件夹
│   ├── 0/                  # 类别0（良性样本）
│   └── 1/                  # 类别1（恶意样本）
├── test_result/            # 测试结果文件夹（自动创建）
│   ├── 0/                  # 类别0分析结果
│   ├── 1/                  # 类别1分析结果
│   └── processing_status.yml   # 处理状态记录
└── dataset_output/         # 数据集输出文件夹（自动创建）
    ├── test_dataset_sequence_5.csv    # 序列特征数据集
    └── test_dataset_frequency.csv     # 频率特征数据集
```

## 环境要求（Ubuntu 22.04）

### 系统依赖
```bash
# 安装ADB和相关工具
sudo apt update
sudo apt install adb android-tools-adb
sudo apt install openjdk-8-jdk

# 安装Android SDK Build Tools (包含aapt)
sudo apt install android-sdk
```

### Python依赖
```bash
# Python 3.x (Ubuntu 22.04自带)
sudo apt install python3 python3-pip

# 安装必要的Python包
pip3 install frida-tools
pip3 install PyQt5
pip3 install pyyaml
```

### Android模拟器
- 推荐使用Genymotion、Android Studio AVD或BlueStacks
- 确保模拟器具有Root权限
- 确保ADB可以连接到模拟器

## 配置说明

### config/config.yml
```yaml
baseConf:
  simulator_path: "/path/to/your/emulator/start/command"  # Linux路径格式
  simulator_ip: "127.0.0.1:5555"  # 模拟器IP地址
```

### Frida服务器配置
1. 下载对应架构的frida-server
2. 推送到Android设备：`adb push frida-server /data/local/tmp/`
3. 赋予执行权限：`adb shell chmod 755 /data/local/tmp/frida-server`
4. 确保source/frida-server_start.sh脚本正确配置

## 使用方法

### 1. 准备测试数据
```bash
# 在项目根目录创建测试文件夹结构
mkdir -p test_apk/0  # 放置良性APK样本
mkdir -p test_apk/1  # 放置恶意APK样本

# 将APK文件放入对应文件夹
cp benign_samples/*.apk test_apk/0/
cp malware_samples/*.apk test_apk/1/
```

### 2. 环境检查
```bash
# 启动设备连接检查
python3 XT_checker.py
```
此脚本会自动：
- 启动Android模拟器
- 检查ADB连接状态
- 验证Frida服务器状态
- 配置端口转发

### 3. 运行批量分析
```bash
# 启动批量APK分析
python3 XTracer.py
```
程序会自动：
- 依次处理test_apk/0和test_apk/1中的所有APK
- 将分析结果保存到test_result对应目录
- 记录处理状态，支持断点续传
- 显示处理进度和统计信息

### 4. 提取特征数据
```bash
# 分析完成后，提取特征数据
python3 XT_read_log.py
```
将生成：
- test_dataset_sequence_5.csv（序列特征）
- test_dataset_frequency.csv（频率特征）

## 分析模式

### 批量测试模式（推荐）
- 默认设置：`hook_mode = 'mult'`
- 自动处理两个类别的所有APK文件
- 生成完整的分析报告

### 单个测试模式
- 设置：`hook_mode = 'single'`
- 处理单个APK进行调试
- 适用于问题排查

## 输出数据

### 行为日志
- **格式**：JSON
- **内容**：API调用序列，包括线程ID、类名、方法名、参数
- **存储路径**：
  - 类别0结果：`test_result/0/{apk_name}.txt`
  - 类别1结果：`test_result/1/{apk_name}.txt`

### 处理状态
- **文件**：`test_result/processing_status.yml`
- **内容**：成功/失败统计、已处理文件列表
- **功能**：支持断点续传

### 特征数据
- **频率特征**：479个API的调用频次统计
- **序列特征**：API调用的时序信息（长度为5）
- **格式**：CSV，可直接用于机器学习
- **标签**：类别0标记为良性，类别1标记为恶意

## Hook的API类别

1. **Intent相关**：Intent创建、参数设置、Action设置
2. **权限相关**：动态权限请求API
3. **设备信息**：IMEI、设备ID、序列号、Mac地址等
4. **位置服务**：GPS定位、网络定位、基站信息
5. **网络通信**：WiFi信息、网络状态、IP地址
6. **硬件访问**：相机、蓝牙、传感器
7. **包管理**：已安装应用列表、包信息查询
8. **系统服务**：剪贴板、设备管理、系统设置

## Linux环境适配特性

### 命令适配
- 使用`grep`替代Windows的`findstr`
- 支持Linux路径格式和权限
- Shell脚本使用`.sh`扩展名

### 路径处理
- 使用`os.path.join()`确保跨平台兼容
- 支持用户主目录`~`扩展
- 自动创建必要的目录结构

### 依赖管理
- 适配Ubuntu包管理系统
- 明确的依赖安装指南
- 环境检查和错误提示

## 注意事项

1. **权限要求**：确保模拟器具有Root权限
2. **版本匹配**：Frida服务器版本需与客户端匹配
3. **网络连接**：分析过程中保持ADB连接稳定
4. **存储空间**：大批量分析时注意磁盘空间使用
5. **处理时间**：每个APK分析时间约2-5分钟（包含Monkey测试）

## 故障排除

### 常见问题

#### ADB连接问题
```bash
# 检查ADB状态
adb devices

# 重启ADB服务
adb kill-server
adb start-server

# 检查端口是否被占用
netstat -tulpn | grep 5037
```

#### Frida连接问题
```bash
# 检查Frida服务器状态
adb shell ps | grep frida

# 手动启动Frida服务器
adb shell "su -c '/data/local/tmp/frida-server &'"

# 检查Frida客户端
frida-ps -U
```

#### 权限问题
```bash
# 确保frida-server具有执行权限
adb shell chmod 755 /data/local/tmp/frida-server

# 检查Root权限
adb shell su -c id
```

#### 依赖缺失
```bash
# 安装aapt工具
sudo apt install aapt

# 检查Java环境
java -version
```

## 性能优化

### 批量处理优化
- 设置合理的超时时间
- 定期清理临时文件
- 监控系统资源使用

### 内存管理
- 及时释放Frida脚本资源
- 清理APK安装残留
- 监控进程数量

## 扩展功能

### 自定义Hook列表
- 修改`source/hook_list_479.csv`添加新的API
- 在`XTracer.py`的`hook_list()`函数中添加特殊API

### 分析参数调整
- 修改Monkey运行时间：`--running-minutes`参数
- 调整Hook超时时间
- 自定义特征提取长度

## 许可证

本项目仅用于学术研究和安全分析目的。请遵守相关法律法规，不得用于非法用途。

## 贡献

欢迎提交Issue和Pull Request来改进这个项目。请确保：
- 代码符合项目规范
- 添加必要的注释和文档
- 测试在Ubuntu 22.04环境下的兼容性

## 技术支持

如遇到问题，请提供：
- Ubuntu版本信息
- Python版本信息
- 错误日志和堆栈信息
- 复现步骤