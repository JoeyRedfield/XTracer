# -*- coding: utf-8 -*-
import json
import sys
import threading
import time
import frida
import subprocess
import os
from copy import copy
from PyQt5.QtWidgets import *
import XT_config
from multiprocessing import Process

sys.setrecursionlimit(5000)
# 选择hook方式  single/mult
hook_mode = 'mult'  # 改为批量处理模式

# 获取当前脚本所在目录
current_dir = os.path.dirname(os.path.abspath(__file__))

# 配置测试APK路径 - 使用当前目录下的test_apk文件夹
test_apk_dir = os.path.join(current_dir, 'test_apk')
test_apk_0_path = os.path.join(test_apk_dir, '0')  # 类别0的APK文件夹（良性）
test_apk_1_path = os.path.join(test_apk_dir, '1')  # 类别1的APK文件夹（恶意）

# 配置测试结果保存路径
test_result_dir = os.path.join(current_dir, 'test_result')
test_result_0_path = os.path.join(test_result_dir, '0')  # 类别0的结果保存路径
test_result_1_path = os.path.join(test_result_dir, '1')  # 类别1的结果保存路径

# 确保结果目录存在
os.makedirs(test_result_0_path, exist_ok=True)
os.makedirs(test_result_1_path, exist_ok=True)

# 当前处理的APK路径和结果路径（全局变量，会在处理时动态设置）
chooseApkPath = test_apk_0_path
featurePath = test_result_0_path

# 构建存储配置文件的完整路径（放在test_result根目录）
storage_path = os.path.join(test_result_dir, 'processing_status.yml')

# 记录检测结果
storage = XT_config.config(storage_path)
if storage.data is None:
    storage.data = {
        'category_0_success': 0,  # 类别0成功处理数量
        'category_0_fail': 0,     # 类别0失败处理数量
        'category_1_success': 0,  # 类别1成功处理数量
        'category_1_fail': 0,     # 类别1失败处理数量
        'processed_files': {}     # 已处理的文件记录
    }

XT = None
scripts = []
loadingAPK = ''
hookSuccess = False
run_state = 1


class XTracerData:
    def __init__(self, tracer=None):
        super(XTracerData, self).__init__()
        self.tracer = tracer

    def stop(self):
        global scripts
        for s in copy(scripts):
            try:
                s.unload()
            except frida.InvalidOperationError as e:
                print(e)
                scripts.remove(s)
            else:
                scripts.remove(s)
        print('[G] success unload script')

    def clean(self):
        self.tracer.thread_map = {}

    def export(self):
        global loadingAPK, hookSuccess, featurePath
        # 分离文件路径和文件名
        fpath, fname = os.path.split(loadingAPK)
        # 从APK文件名中提取应用名称（去掉.apk扩展名）
        api = fname.split('.apk')[0]
        # 构建JSON日志文件的完整输出路径（保存到当前处理类别的结果文件夹）
        jobfile = os.path.join(featurePath, api + '.txt')
        thread_map = self.tracer.thread_map.copy()
        if thread_map != {}:
            # 将线程映射数据保存到指定的JSON文件路径
            json.dump(thread_map, open(jobfile, 'w', encoding='utf-8'))
            hookSuccess = True
            print('[G] success get jsonLog')
        else:
            print('[G] jsonLog is None')


class XTracer:
    def __init__(self, ):
        global XT
        XT = self
        self.application_label = None
        self.packageName = None
        self.tracer = QApplication(sys.argv)
        self.trace_data = XTracerData(self)
        self.thread_map = {}
        self.hookComplete = 'false'
        if 'single' in hook_mode:
            self.singleTrace()
        elif 'mult' in hook_mode:
            self.multTrace()
        sys.exit()

    def method_entry(self, tid, clazz, method, args):
        data_list = []
        if tid in self.thread_map:
            data_list = self.thread_map[tid]
        data_list.append([clazz, method, args])
        self.thread_map[tid] = data_list

    def log(self, text):
        text = time.strftime('%Y-%m-%d %H:%M:%S:  [*] ', time.localtime(time.time())) + text
        print(text)

    # 批量检测 - 修改为处理测试文件夹
    def multTrace(self):
        global loadingAPK, chooseApkPath, featurePath
        
        # 处理类别0（良性样本）
        print('[A] ================== 开始处理类别0（良性样本） ==================')
        chooseApkPath = test_apk_0_path
        featurePath = test_result_0_path
        self.processCategory(0, '良性')
        
        # 处理类别1（恶意样本）
        print('[A] ================== 开始处理类别1（恶意样本） ==================')
        chooseApkPath = test_apk_1_path
        featurePath = test_result_1_path
        self.processCategory(1, '恶意')
        
        print('[A] ================== 所有处理完成 ==================')
        self.printSummary()

    def processCategory(self, category, category_name):
        """处理指定类别的APK文件"""
        global loadingAPK
        
        apkPaths = getApkPath(chooseApkPath)
        if not apkPaths:
            print(f'[A] 类别{category}文件夹中没有发现APK文件: {chooseApkPath}')
            return
        
        print(f'[A] 在类别{category}中发现 {len(apkPaths)} 个APK文件')
        
        count = 0
        success_count = 0
        fail_count = 0
        
        for apkPath in apkPaths:
            loadingAPK = apkPath
            fpath, fname = os.path.split(loadingAPK)
            apk_name = fname.split('.apk')[0]
            
            # 生成唯一标识符（包含类别信息）
            file_key = f'category_{category}_{apk_name}'
            
            # 检查是否已经处理过
            if file_key in storage.data['processed_files']:
                print(f'[A] 跳过已处理的文件: {apk_name}')
                continue
            
            count += 1
            print(f'[A] ------------------ 开始处理第{count}个{category_name}APK ------------------')
            print(f'[A] 当前处理: {apk_name}')
            
            if self.appTrace():
                storage.data[f'category_{category}_success'] += 1
                storage.data['processed_files'][file_key] = 'success'
                success_count += 1
                print(f"[J] {category_name}样本处理成功: {loadingAPK}")
            else:
                storage.data[f'category_{category}_fail'] += 1
                storage.data['processed_files'][file_key] = 'fail'
                fail_count += 1
                print(f"[J] {category_name}样本处理失败: {loadingAPK}")
            
            # 保存进度
            storage.saveData()
            print(f'[A] ------------------ 完成第{count}个{category_name}APK ------------------')
        
        print(f'[A] 类别{category}({category_name})处理完成: 成功{success_count}个, 失败{fail_count}个')

    def printSummary(self):
        """打印处理结果摘要"""
        print('\n' + '='*60)
        print('处理结果摘要:')
        print(f'类别0(良性样本): 成功 {storage.data["category_0_success"]} 个, 失败 {storage.data["category_0_fail"]} 个')
        print(f'类别1(恶意样本): 成功 {storage.data["category_1_success"]} 个, 失败 {storage.data["category_1_fail"]} 个')
        total_success = storage.data["category_0_success"] + storage.data["category_1_success"]
        total_fail = storage.data["category_0_fail"] + storage.data["category_1_fail"]
        print(f'总计: 成功 {total_success} 个, 失败 {total_fail} 个')
        print(f'结果保存路径: {test_result_dir}')
        print('='*60)

    # 单独检测 - 修改为支持测试模式
    def singleTrace(self):
        global loadingAPK, run_state, chooseApkPath, featurePath
        run_state = 0
        
        # 默认处理类别0，也可以根据需要修改
        chooseApkPath = test_apk_0_path
        featurePath = test_result_0_path
        
        apkPaths = getApkPath(chooseApkPath)
        if not apkPaths:
            print('当前测试文件夹中没有APK文件')
            return
            
        apk_index = 0
        while True:
            loadingAPK = apkPaths[apk_index]
            fpath, fname = os.path.split(loadingAPK)
            apk_name = fname.split('.apk')[0]
            file_key = f'category_0_{apk_name}'
            
            if file_key in storage.data['processed_files']:
                apk_index += 1
                if apk_index == len(apkPaths):
                    print('当前文件夹已无未处理的APK')
                    return
            else:
                break
                
        print('[A] ------------------ 开始单个测试 ---------------------------')
        if self.appTrace():
            storage.data['category_0_success'] += 1
            storage.data['processed_files'][file_key] = 'success'
            print("[J] 测试成功 ", loadingAPK)
        else:
            storage.data['category_0_fail'] += 1
            storage.data['processed_files'][file_key] = 'fail'
            print("[J] 测试失败 ", loadingAPK)
        storage.saveData()
        print('    ------------------ 测试结束 -----------------------------')
        run_state = 1

    def appTrace(self):
        global hookSuccess
        print('[A] apk_Path:' + str(loadingAPK))
        self.application_label = getPackageLabel()
        self.packageName = getPackageName()
        packageActivity = getPackageActivity()
        # 判断文件是否存在
        if self.packageName is None or packageActivity is None:
            return False
        if apkInstall():
            # 清空上个程序运行残留
            self.trace_data.clean()
            # 运行安装apk
            if runApk(self.packageName, packageActivity):
                # 运行追踪脚本
                if self.runTrace():
                    # 运行monkey
                    runMonkey(self.packageName)
                    # 获取日志
                    self.getJsonLog()
                    # 获取日志后卸载脚本
                    self.trace_data.stop()
                # 无论运行是否成功，都结束运行
                stopApk(self.packageName)
            # 最后卸载app
            apkUninstall(self.packageName)
        if hookSuccess:
            # 初始化hookSuccess
            hookSuccess = False
            return True
        return False

    def runTrace(self):
        print('[E] ------------------ hooking ------------------------')
        threading.Thread(target=self.start_trace).start()
        while True:
            if 'true' in self.hookComplete:
                print('[E] success hook')
                # 重新初始化hookComplete
                self.hookComplete = 'false'
                return True
            if 'fail' in self.hookComplete:
                print('[E] fail hook')
                # 重新初始化hookComplete
                self.hookComplete = 'false'
                return False
            time.sleep(1)

    def start_trace(self):
        global scripts
        hook_process_num = 0
        def _attach(pid):
            failcount = 0
            try:
                session = device.attach(pid)
                session.enable_child_gating()
                # 读取JavaScript hook脚本文件（相对路径）
                source = open('XTracer.js', 'r', encoding='utf-8').read().replace('{hook_list}', str(hook_list()))
                script = session.create_script(source)
                script.on("message", self.FridaReceive)
                script.load()
                scripts.append(script)
                return True
            except frida.ProcessNotFoundError:
                print('[E] fail find process: ' + str(pid))
                return
            except frida.NotSupportedError as e:
                print('[E] NotSupportedError:' + str(e))
                return
            except frida.PermissionDeniedError as e:
                print('[E] PermissionDeniedError:' + str(e))
                return
            except frida.ProtocolError as e:
                print('[E] ProtocolError:' + str(e))
                return
            except frida.TransportError as e:
                print('[E] TransportError:' + str(e))
                if 'timeout was reached' in str(e):
                    return
                failcount += 1
                if failcount > 4:
                    printRed('[E] fail connect')
                    return
                # _attach(pid, failcount)

        def _on_child_added(child):
            print('[E] hook child_process:', child)
            _attach(child.pid)

        device = frida.get_usb_device()
        device.on("child-added", _on_child_added)
        for process in device.enumerate_processes():
            if self.packageName:
                if self.packageName in process.name:
                    print('[E] hook process:', process)
                    if _attach(process.pid):
                        hook_process_num += 1
            elif self.application_label:
                if self.application_label in process.name:
                    print('[E] hook process:', process)
                    if _attach(process.pid):
                        hook_process_num += 1
            # if self.packageName in process.name or self.application_label in process.name:
            #     print('[E] hook process:', process)
            #     if _attach(process.pid):
            #         hook_process_num += 1
        # 若无attach成功则判断hook失败
        time.sleep(5)
        if hook_process_num == 0:
            print('[E] hook process failed')
            self.hookComplete = 'fail'
            return

    def FridaReceive(self, message, data):
        if message['type'] == 'send':
            if message['payload'][:10] == 'XTracer:::':
                packet = json.loads(message['payload'][10:])
                cmd = packet['cmd']
                data = packet['data']
                if cmd == 'log':
                    # 接收hook完成日志
                    if 'Hook Complete' in data:
                        self.hookComplete = 'true'
                elif cmd == 'enter':
                    tid, cls, method, args = data
                    XT.method_entry(tid, cls, method, args)
                # elif cmd == 'exit':
                #     tid, retval = data
                #     XT.method_exit(tid, retval)
        else:
            print(message['stack'])

    def getJsonLog(self):
        print('[G] ------------------ get jsonLog --------------------')
        self.trace_data.export()


def hook_list():
    """读取hook API列表"""
    extend_list = [
        'android.content.Intent/$init',
        'android.content.Intent/putExtra',
        'android.content.Intent/setAction',
        'android.support.v4.app.ActivityCompat/requestPermissions',
        'androidx.core.app.ActivityCompat/requestPermissions'
    ]
    # 从CSV文件读取hook列表（相对路径）
    with open("source/hook_list_479.csv") as f:
        hookList = [row.split(',')[0] for row in f]
    for item in extend_list:
        hookList.append(item)
    del (hookList[0])
    return hookList


def getApkPath(path):
    """
    递归搜索指定路径下的所有APK文件
    path: 要搜索的根目录路径
    返回: 所有APK文件的完整路径列表
    """
    if not os.path.exists(path):
        print(f'[WARNING] 路径不存在: {path}')
        return []
        
    apkPaths = []
    for root, dirs, files in os.walk(path):
        for file in files:
            if file.lower().endswith('.apk'):  # 改为更严格的APK文件检查
                # 使用os.path.join构建完整的APK文件路径（跨平台兼容）
                apkPath = os.path.join(root, file)
                apkPaths.append(apkPath)
    
    print(f'[INFO] 在路径 {path} 中找到 {len(apkPaths)} 个APK文件')
    return apkPaths


def runCMD(command):
    """执行shell命令并返回结果"""
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, encoding="utf-8").stdout
    return result


def getPackageLabel():
    """从APK文件中提取应用标签名称"""
    # 使用aapt工具分析APK文件，通过管道传递给grep过滤（Linux命令）
    adbReturn = runCMD('aapt dump badging "' + loadingAPK + '" | grep application-label:')
    if 'application-label' in adbReturn:
        labelName = adbReturn.split("application-label:'")[1].split("'")[0]
        print('[B] labelName: ' + labelName)
        return labelName
    else:
        return None


def getPackageName():
    """从APK文件中提取包名"""
    # 使用aapt工具分析APK文件，通过管道传递给grep过滤（Linux命令）
    adbReturn = runCMD('aapt dump badging "' + loadingAPK + '" | grep package')
    if 'package: name' in adbReturn:
        package_name = adbReturn.split("package: name='")[1].split("' versionCode")[0]
        print('[B] package_name: ' + package_name)
        return package_name
    else:
        printRed('[B] fail get package_name--apkPath:' + loadingAPK)
        return None


def getPackageActivity():
    """从APK文件中提取主Activity名称"""
    # 使用aapt工具分析APK文件，通过管道传递给grep过滤（Linux命令）
    adbReturn = runCMD('aapt dump badging "' + loadingAPK + '" | grep activity')
    if 'activity: name' in adbReturn:
        activityName = adbReturn.split("activity: name='")[1].split("'  label")[0]
        print('[B] mainActivityName: ' + activityName)
        return activityName
    else:
        printRed('[B] fail get activityName--apkPath:' + loadingAPK)
        return None


def apkInstall():
    """安装APK文件到Android设备"""
    print('[C] ------------------ APK installing -----------------')
    # 使用列表格式构建adb install命令，包含APK文件的完整路径
    command = ['adb', 'install', '-r', loadingAPK]
    proc = subprocess.Popen(command, stdout=subprocess.PIPE)
    try:
        adbReturn = proc.communicate(180)
        for readLine in adbReturn:
            if 'Success' in str(readLine):
                print('[C] APK install success')
                return True
        return False
    except subprocess.TimeoutExpired:
        printRed('[C] APK install fail--apkPath:' + loadingAPK)
        return False


def runApk(package, packageActivity):
    print('[D] ------------------ APK running --------------------')
    command = ['adb', 'shell', 'am', 'start', '-W', '-n', package + '/' + packageActivity]
    proc = subprocess.Popen(command, stdout=subprocess.PIPE)
    try:
        adbReturn = proc.communicate(timeout=60)
        if 'Complete' in str(adbReturn):
            print('[D] start running')
            # 关闭线程
            proc.kill()
            time.sleep(1)
            return True
    except subprocess.TimeoutExpired:
        proc.kill()
        printRed('[D] fail run--TimeoutExpired')
        return False


def runMonkey(package):
    print('[F] ------------------ monkey running -----------------')
    command = ['adb', 'shell', 'CLASSPATH=/sdcard/monkey.jar:/sdcard/framework.jar', 'exec', 'app_process', '/system/bin', 'tv.panda.test.monkey.Monkey', '-p', package, '--uiautomatormix', '--pct-reset', '0', '--pct-rotation', '0', '--running-minutes', '2', '-v']
    proc = subprocess.Popen(command, stdout=subprocess.PIPE)
    try:
        adbReturn = proc.communicate(timeout=300)
        for readline in adbReturn:
            if ' Monkey finished' in str(readline):
                print('[F] success monkey')
                return
    except subprocess.TimeoutExpired:
        printRed('[F] fail run monkey')


def stopApk(package):
    print('[H] ------------------ app stopping -------------------')
    command = ['adb', 'shell', 'pm', 'clear', package]
    proc = subprocess.Popen(command, stdout=subprocess.PIPE)
    try:
        adbReturn = proc.communicate(timeout=120)
        if 'Success' in str(adbReturn):
            print('[H] success stopping')
            return
    except subprocess.TimeoutExpired:
        printRed('[H] fail stop')


def apkUninstall(package):
    print('[I] ------------------ uninstalling -------------------')
    command = ['adb', 'uninstall', package]
    proc = subprocess.Popen(command, stdout=subprocess.PIPE)
    try:
        adbReturn = proc.communicate(timeout=120)
        for readLine in adbReturn:
            if 'Success' in str(readLine):
                print('[I] uninstalled')
                return
    except subprocess.TimeoutExpired:
        printRed('[I] fail uninstall')


def printRed(message):
    print("\033[1;31;48m" + message + "\033[0m")


if __name__ == '__main__':
    # 打印测试配置信息
    print('='*60)
    print('XTracer 测试模式启动')
    print(f'测试APK路径: {test_apk_dir}')
    print(f'  - 类别0(良性): {test_apk_0_path}')
    print(f'  - 类别1(恶意): {test_apk_1_path}')
    print(f'结果保存路径: {test_result_dir}')
    print(f'  - 类别0结果: {test_result_0_path}')
    print(f'  - 类别1结果: {test_result_1_path}')
    print(f'处理模式: {hook_mode}')
    print('='*60)
    
    # 检查测试目录是否存在
    if not os.path.exists(test_apk_dir):
        print(f'[ERROR] 测试APK目录不存在: {test_apk_dir}')
        print('请确保在当前目录下创建test_apk文件夹，并在其中创建0和1子文件夹放置APK文件')
        sys.exit(1)
    
    while True:
        if run_state:
            adbReturn = subprocess.run('frida-ps -U', shell=True, stdout=subprocess.PIPE, encoding="utf-8").stdout
            if "Failed" in adbReturn:
                print('Frida Disconnect, Waiting Frida')
            if "PID" in adbReturn:
                hookThread = Process(target=XTracer)
                hookThread.start()
                hookThread.join()
                # 在批量模式下，处理完成后退出
                if hook_mode == 'mult':
                    break
        else:
            print(run_state)
        time.sleep(10)
