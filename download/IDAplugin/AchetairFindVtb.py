# -*- coding:utf-8 -*-
# python 2.7

import idaapi
import idautils
import re
from pprint import pprint

# table structure
vtb_model = {
    "vtb_start_addr":0,
    "vtb_func_lists":[]
}

vtb_func_lists_model = {
    "func_name":"",
    "func_addr":0,
    "vPtr":0
}

def read_ea(ea):
    return (ea+4, idaapi.get_32bit(ea))

def read_signed_32bit(ea):
    return (ea+4, idaapi.as_signed(idaapi.get_32bit(ea), 32))

# 检测是否为虚表的开始
def is_vtb_begin(ea):
    # 如果虚表有名字了则是虚表的开始
    if idaapi.get_name(ea)== None or idaapi.get_name(ea)=="":
        return False
    return True
    # return idaapi.get_name(ea)[0:3] == "off"


# if the address is a function name
def isFunction(ptr):
    '''
    func_name = idaapi.get_name(ea)
    if func_name==None or func_name=="":
        return False
    return True
    '''
    if ptr in idautils.Functions():
        return True
    return False

# 有些地址是RVA，需要加上IMAGE_BASE
def change_rva(rva):
    # 对RVA进行检测
    if rva<idaapi.get_imagebase():
        return idaapi.get_imagebase()+rva
    return rva


# give an addr check func
def store_segVtb(ea):
    # init structure
    # vtb = vtb_model
    vtb = {}
    # vtb['vtb_start_addr'] = hex(ea)
    vtb['vtb_start_addr'] = ea
    vtb["vtb_func_lists"] = []
    while True:
        prev_ea = ea
        # vfuncs = vtb_func_lists_model
        vfuncs = {}

        ea, func_ptr = read_ea(ea)
        # print hex(func_ptr)


        # 检测是否为函数，不是则跳出，一个虚表的保存完成
        if not isFunction(func_ptr):
            func_ptr = change_rva(func_ptr)
            if not isFunction(func_ptr):
                break

        # 函数的名称
        func_name = idaapi.get_name(func_ptr)
        vfuncs['func_name'] = func_name
        # vfuncs['func_addr'] = hex(func_ptr)
        # vfuncs['vPtr'] = hex(prev_ea)
        vfuncs['func_addr'] = func_ptr
        vfuncs['vPtr'] = prev_ea
        # 放在一个续表的列表中
        vtb["vtb_func_lists"].append(vfuncs)
        # 检测下一个地址是否为虚表的开始
        # 防止出现虚表连在一起的情况
        if is_vtb_begin(ea):
            break

        # print "0x%x" % ea
    # 返回当前的地址指针，保存的虚表
    return ea, vtb

def find_tablegroups(segname=".data"):
    '''
    Returns a list of (start, end) ea pairs for the
    vtable groups in 'segname'
    '''

    # 设置计数的返回值
    # count = 0

    seg = idaapi.get_segm_by_name(segname)
    ea = seg.startEA
    vtbs = []
    # print hex(seg.endEA)
    while ea < seg.endEA:
        # 记录之前ea的值
        prev_ea = ea
        ea, ptr = read_ea(ea)
        if ptr==0:
            continue
        # 检测是否为方法
        if isFunction(ptr):
            # print hex(ea)
            # 如果是off开头，则可以确认为虚表
            # if is_vtb_begin(prev_ea):
            ea, vtb = store_segVtb(prev_ea)
            # 空的列表则不添加
            if vtb.get('vtb_func_lists') == []:
                continue
            vtbs.append(vtb)
        # count = count + 1
        # if count==4:
        #     break

    # pprint(vtbs)
    return vtbs

# 获取一个类型的指针
def ptr_type(type_name):
    if not isinstance(type_name, str):
        raise Exception
    tinfo = idaapi.create_typedef(type_name)
    ptr_tinfo = idaapi.tinfo_t()
    ptr_tinfo.create_ptr(tinfo)
    return ptr_tinfo

# 创建结构体的信息
def structure_info_create(vtbs):
    for vtb in vtbs:
        vtb_name = "vtb_" + (hex(vtb.get("vtb_start_addr"))[2:-1]).upper()
        # 创建结构体
        udt_data = idaapi.udt_type_data_t()

        # 函数名称记录列表
        func_name_records_list = []

        # 添加结构体的成员
        for mem in vtb.get('vtb_func_lists'):
            # 创建成员
            udt_member = idaapi.udt_member_t()
            udt_member.type = ptr_type("DWORD")
            udt_member.name = name_filter(mem.get('func_name'))
            # 如果名字为空，需要进行特殊的处理
            # MEMORY[xxxx]
            # print udt_member.name
            if udt_member.name == None or udt_member.name == "":
                udt_member.name = "memory_" + (hex(mem.get("func_addr"))[2:]).upper()
            # 防止函数名称重复
            if udt_member.name in func_name_records_list:
                udt_member.name += "1"
            func_name_records_list.append(udt_member.name)
            # print udt_member.name
            # 插入结构体
            udt_data.push_back(udt_member)
        build_structure_in_ida(udt_data, vtb_name)

# 字符串清理
def name_filter(name):
    rstr = r"[\/\\\:\*\?\"\>\<\|]"
    new_title = re.sub(rstr, '_', name)
    name = new_title.split("@")
    return "_".join(name)


# 向IDA中插入结构体
def build_structure_in_ida(udt_data, structure_name):
    # 结构体的创建
    final_tinfo = idaapi.tinfo_t()
    final_tinfo.create_udt(udt_data, idaapi.BTF_STRUCT)
    cdecl = idaapi.print_tinfo(None, 4, 5, idaapi.PRTYPE_MULTI | idaapi.PRTYPE_TYPE | idaapi.PRTYPE_SEMI,
                               final_tinfo, structure_name, None)

    print cdecl
    # cdecl = "struct Test_Python_Type{int filed_1;};"

    # structure_name = idaapi.idc_parse_decl(idaapi.cvar.idati, cdecl, idaapi.PT_TYP)[0]

    # 先删除
    # tid = idaapi.del_numbered_type(idaapi.cvar.idati, struct_ordinal)
    # print tid
    # struct_ordinal = 21
    previous_ordinal = idaapi.get_type_ordinal(idaapi.cvar.idati, structure_name)
    if previous_ordinal:
        struct_ordinal = previous_ordinal
        # 如果之前的编号存在，则删除编号，重新创建
        idaapi.del_numbered_type(idaapi.cvar.idati, previous_ordinal)
        # 创建type
        tid = idaapi.idc_set_local_type(struct_ordinal, cdecl, idaapi.PT_TYP)
        # print tid
    else:
        tid = idaapi.idc_set_local_type(-1, cdecl, idaapi.PT_TYP)

    # 结构体之前的序号
    # while idaapi.idc_get_local_type_raw(struct_ordinal):
    #     # 从某个序号开始遍历，如果序号不为空，则下一个
    #     struct_ordinal += 1
    #
    # ordinal = idaapi.idc_set_local_type(struct_ordinal, cdecl, idaapi.PT_TYP)
    # print ordinal
    # GetString


if __name__ == '__main__':
    vtbs = find_tablegroups(".data")
    structure_info_create(vtbs)




