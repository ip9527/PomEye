import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from bs4 import BeautifulSoup
from variables import *
from check_vul import check_vul
from config import SUPPORTED_ENCODINGS, VERBOSE_LOGGING

'''
解析pom文件模块
'''


# 构建父子依赖关系树
def construct_pom_tree():
    for file, ga_pga in ga_record.items():
        ga = ga_pga[0]
        parent_ga = ga_pga[1]
        # 再次遍历ga_record寻找该文件的父项目的pom文件
        for n_file, n_ga_pga in ga_record.items():
            if parent_ga == n_ga_pga[0]:
                pom_tree[file] = n_file


# 当pom文件中组件的version为空时，会继承父项目中该组件的版本
def dependence_inherit():
    for i in range(len(xml_res)):
        info = xml_res[i]
        if info[2] == "*":
            version = find_parent_version(info[-1], f"{info[0]}.{info[1]}")
            if version == None:
                version = "*"
            xml_res[i] = [info[0], info[1], version, info[3], info[4]]


# 查找pom文件x的父项目中y组件的依赖的版本
def find_parent_version(x, y):
    if pom_tree.get(x) == None:
        return "*"
    parent = pom_tree.get(x)
    for r in xml_res:
        if r[-1] == parent and y == f"{r[0]}.{r[1]}":
            if r[2] == "*":
                return find_parent_version(r[-1], y)
            return r[2]


# 从文件夹中寻找所有的pom文件
file_list = []
def find_pom(filename):
    file = os.listdir(filename)
    for f in file:
        real_filename = os.path.join(filename, f)
        if os.path.isfile(real_filename):
            if real_filename.lower().endswith(".xml"):
                file_list.append(os.path.abspath(real_filename))
        elif os.path.isdir(real_filename):
            find_pom(real_filename)
        else:
            pass


# 线程锁，用于保护共享的全局变量
xml_res_lock = threading.Lock()
ga_record_lock = threading.Lock()


def parse_single_pom(pom_file):
    """
    解析单个 POM 文件（线程安全）
    返回: (dependencies_list, ga_record_item) 或 (None, None) 如果解析失败
    """
    # 使用bs4开始解析，尝试多种编码（从配置文件读取）
    pom_content = None
    for encoding in SUPPORTED_ENCODINGS:
        try:
            pom_content = open(pom_file, 'r', encoding=encoding).read()
            break
        except (UnicodeDecodeError, LookupError):
            continue
    
    if pom_content is None:
        if VERBOSE_LOGGING:
            print(f"警告：无法读取文件 {pom_file}，跳过")
        return None, None
    
    pom = BeautifulSoup(pom_content, "xml")
    # 只处理符合 Maven POM 结构的 xml 文件
    if pom.select("project > artifactId") == []:
        return None, None
    
    # 查找所有的 dependency 标签
    dependencies = pom.find_all("dependency")
    
    if len(dependencies) == 0:
        return [], None
    
    # 解析依赖列表
    dependencies_list = []
    for d in dependencies:
        try:
            # 解析 groupId 和 artifactId
            groupId_elem = d.find("groupId")
            artifactId_elem = d.find("artifactId")
            
            if not groupId_elem or not artifactId_elem:
                continue
            
            groupId = groupId_elem.text.strip()
            artifactId = artifactId_elem.text.strip()
            
            # 解析 version
            version_elem = d.find("version")
            if version_elem and version_elem.text:
                version = version_elem.text.strip()
                # 处理变量引用，如 ${fastjson.version}
                if version.startswith('${') and version.endswith('}'):
                    var_name = version[2:-1]  # 提取变量名
                    var_elem = pom.find(var_name)
                    if var_elem and var_elem.text:
                        version = var_elem.text.strip()
                    else:
                        version = "*"
            else:
                # 没有 version 标签，设置为 *
                version = "*"
            
            dependencies_list.append([groupId, artifactId, version, "*", pom_file])
            
        except Exception as e:
            if VERBOSE_LOGGING:
                print(f"解析 dependency 时出错: {e}")
            continue
    
    # 提取父子项目依赖关系
    ga_record_item = None
    try:
        # 先找到父项目的groupId和artifactId
        if (pom.find_all("parent") == []):
            parent_ga = "*"
        else:
            parent_ga = pom.select("parent > groupId")[0].text + "." + pom.select("parent > artifactId")[0].text
        # 找到本项目的artifactId
        ad = pom.select("project > artifactId")[0].text
        # 如果本项目没提供groupId，则和父项目一样
        if pom.select("project > groupId") == []:
            gd = pom.select("parent > groupId")[0].text
        else:
            gd = pom.select("project > groupId")[0].text
        ga = gd + "." + ad
        ga_record_item = (pom_file, [ga, parent_ga])
    except Exception as e:
        if VERBOSE_LOGGING:
            print(f"提取父子关系时出错: {e}")
    
    return dependencies_list, ga_record_item


# 解析pom文件，返回版本信息和漏洞信息
def parse(files, progressbarOne, root, progressbar_tips):
    # 清空所有全局变量，避免多次运行时数据累积
    global xml_res, pom_tree, ga_record, vul_details_dict, file_list
    
    # 使用 clear() 方法清空，而不是重新赋值，以保持全局引用
    xml_res.clear()
    pom_tree.clear()
    ga_record.clear()
    vul_details_dict.clear()
    file_list.clear()
    
    pom_files = []

    # 如果传入的是多个文件
    if isinstance(files, tuple) and len(files) > 0 and os.path.isfile(files[0]):
        for file in files:
            if file.lower().endswith(".xml"):
                pom_files.append(file)
    # 如果传入的是文件夹
    elif isinstance(files, str) and os.path.isdir(files):
        find_pom(files)
        for file in file_list:
            pom_files.append(file)
    else:
        # 无效的输入
        progressbar_tips.set("❌ 错误：未选择有效的文件或文件夹")
        return

    if len(pom_files) == 0:
        progressbar_tips.set("⚠️ 警告：未找到任何 XML 文件")
        return

    # 设置进度条最大值为文件数量
    progressbarOne['maximum'] = len(pom_files)
    progressbarOne['value'] = 0

    # 使用线程池并发解析文件
    # 根据 CPU 核心数设置线程数，最多 8 个线程
    max_workers = min(8, (os.cpu_count() or 1) * 2)
    
    if VERBOSE_LOGGING:
        print(f"ℹ️  开始并发解析 {len(pom_files)} 个文件，使用 {max_workers} 个线程")

    completed_count = 0
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有解析任务
        future_to_file = {
            executor.submit(parse_single_pom, pom_file): pom_file 
            for pom_file in pom_files
        }
        
        # 处理完成的任务
        for future in as_completed(future_to_file):
            pom_file = future_to_file[future]
            try:
                dependencies_list, ga_record_item = future.result()
                
                # 线程安全地更新全局变量
                if dependencies_list is not None:
                    with xml_res_lock:
                        xml_res.extend(dependencies_list)
                
                if ga_record_item is not None:
                    with ga_record_lock:
                        ga_record[ga_record_item[0]] = ga_record_item[1]
                
                completed_count += 1
                progressbarOne['value'] = completed_count
                progressbar_tips.set(f"正在解析文件 ({completed_count}/{len(pom_files)}) {os.path.basename(pom_file)}")
                root.update()
                
            except Exception as e:
                if VERBOSE_LOGGING:
                    print(f"解析文件 {pom_file} 时出错: {e}")
                completed_count += 1
                progressbarOne['value'] = completed_count
                root.update()

    if VERBOSE_LOGGING:
        print(f"✓ 并发解析完成，共解析到 {len(xml_res)} 个依赖")

    # 构建父子依赖关系树
    construct_pom_tree()
    # 子项目继承父项目的依赖
    dependence_inherit()
    
    # 检查是否解析到任何组件
    if not xml_res:
        progressbar_tips.set("⚠️ 警告：未找到任何组件依赖，请检查文件是否为有效的 POM 文件")
        return
    
    # 开始漏洞检测
    check_vul(progressbarOne, root, progressbar_tips)
