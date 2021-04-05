#-*- coding:utf-8 -*-
# python3
import json
import xlwt

# json文件内容必须是字典数组
# [{},{},{}···]
def read_json_file(file_name):
    return json.load(open(file_name,'r'))

class Sina_Excel():
    def __init__(self, file_pth):
        # file_pth 格式 xxxx/xxx.json
        self.pth = file_pth
        self.fn = file_pth.split('/')[-1].split('.')[0]
    def json_to_excel(self, json_data):
        # 初始化一个excel
        work_excel = xlwt.Workbook(encoding='utf-8')

        # 创建一个sheet
        sheet = work_excel.add_sheet(self.fn)
        # 初始化样式
        style = xlwt.XFStyle()
        # 创建字体
        font = xlwt.Font()
        # 字体类型
        font.name = u'微软雅黑'
        #字体颜色
        font.colour_index = 6
        # 下划线
        font.underline = False
        # 字体斜体
        font.italic = False
        # 字体大小
        font.height = 400
        # 设定样式
        style.font = font

        # 写入数据
        # 第一行的内容
        raw_1 = list(get_json_keys(json_data))
        # 记录一共有多少列
        line_max = len(raw_1)
        for i in range(line_max):
            sheet.write(0,i, raw_1[i])
        # 逐行写入数据
        for i in range(len(json_data)):
            # 记录每一行的读写指针
            m = 0
            ls = list(json_data[i].values())
            for j in ls:
                # 最后以列图片单独处理
                if m==5:
                    print('='*20)
                    j_str = '\n'.join(j)
                    sheet.write(i + 1, m, j)
                    print(j_str)
                else:
                    sheet.write(i + 1, m, j)

                m = m + 1



        work_excel.save("spider_sample.xls")


def get_json_keys(json_list):
    return json_list[0].keys()

if __name__ == '__main__':
    # file_path 是文件名
    file_path = '期待海王/期待海王.json'
    json_data = read_json_file(file_path)
    Sina_Excel(file_path).json_to_excel(json_data)

