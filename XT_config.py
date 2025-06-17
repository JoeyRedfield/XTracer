import yaml,os


class config:
    def __init__(self, path):
        # 保存配置文件路径，支持相对路径和绝对路径
        self.path = path
        self.data = self.loadData()

    def loadData(self):
        # 检查配置文件是否存在，如果不存在则创建空文件
        if not os.path.exists(self.path):
            # 创建空的配置文件（如果目录不存在会报错）
            with open(self.path, 'w', encoding='utf-8'):
                print('')
        # 读取YAML配置文件内容
        with open(self.path, encoding='utf-8') as c:
            return yaml.load(c, Loader=yaml.FullLoader)

    def saveData(self):
        # 将数据保存到配置文件路径
        with open(self.path, "w", encoding='utf-8') as f:
            yaml.dump(self.data, f)
