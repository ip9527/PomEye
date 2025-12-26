import requests
import re
import random
import time

from variables import *
from config import (
    REQUEST_TIMEOUT,
    RETRY_TIMES,
    REQUEST_DELAY,
    GROUPID_ALIAS_MAP,
    REQUEST_HEADERS_POOL,  # 使用请求头池
    SNYK_BASE_URL,
    LEVEL_MAPPING,
    VERBOSE_LOGGING
)
try:
    from retrying import retry
except ImportError:
    # 如果未安装 retrying 库，则降级为不重试的装饰器
    def retry(*args, **kwargs):
        def decorator(func):
            return func
        return decorator
from bs4 import BeautifulSoup

'''
漏洞检测模块
'''

# 创建全局会话对象，复用 TCP 连接
_session = requests.Session()

# 在程序启动时随机选择一个请求头，整个运行期间使用同一个
SESSION_HEADERS = random.choice(REQUEST_HEADERS_POOL).copy()

# 添加请求延迟，避免触发反爬虫机制
_last_request_time = 0
_request_lock = None


# 比较版本号version1大于version2返回1
def compare_versions(version1, version2):
    # 预处理：移除常见后缀（-SNAPSHOT, -beta, -RC1 等）
    v1_clean = version1.split('-')[0]
    v2_clean = version2.split('-')[0]
    
    # 将版本号字符串转换成列表
    v1 = v1_clean.split('.')
    v2 = v2_clean.split('.')

    # 安全地将版本号列表转换成整数列表，非数字部分设为 0
    v1 = [int(x) if x.isdigit() else 0 for x in v1]
    v2 = [int(x) if x.isdigit() else 0 for x in v2]

    # 补齐版本号列表长度
    while len(v1) < len(v2):
        v1.append(0)
    while len(v2) < len(v1):
        v2.append(0)

    # 逐位比较版本号大小
    for i in range(len(v1)):
        if v1[i] > v2[i]:
            return 1
        elif v1[i] < v2[i]:
            return -1

    # 版本号相等
    return 0


# 漏洞类
class vul_details:
    def __init__(self):
        self.min_version = "*"  # 漏洞影响版本范围的最小值(包括)
        self.max_version = "*"  # 漏洞影响版本范围的最大值(不包括)
        self.name = "*"  # 漏洞名称
        self.level = "*"  # 漏洞等级
        self.cve = "*"  # CVE编号
        self.cwe = "*"  # CWE编号
        self.overview = "*"  # 漏洞概述
        self.href = "*"  # 漏洞信息来源的网站

    def version_is_affected(self, version):
        if "*" in version:
            return False
        version = version.replace("-SNAPSHOT", "").replace("-LATEST", "").replace("-RELEASE", "").strip()
        try:
            if self.min_version != "*" and compare_versions(self.min_version, version) == 1:
                return False
            if self.max_version != "*" and compare_versions(self.max_version, version) == -1:
                return False
            if self.max_version != "*" and compare_versions(self.max_version, version) == 0:
                return False
        except:
            return False
        return True


# groupId 别名映射表已移至 config.py 配置文件
# 但实际使用时会动态尝试多种可能的 groupId 组合，不完全依赖硬编码映射

def _get_random_headers():
    """
    返回程序启动时选择的请求头
    整个运行期间使用同一个请求头，增强反爬虫能力

    Returns:
        dict: 程序启动时选择的请求头
    """
    return SESSION_HEADERS.copy()


def _apply_request_delay():
    """
    应用请求延迟，避免触发反爬虫机制
    """
    global _last_request_time
    current_time = time.time()
    elapsed = current_time - _last_request_time
    
    if elapsed < REQUEST_DELAY:
        sleep_time = REQUEST_DELAY - elapsed
        if VERBOSE_LOGGING:
            print(f"⏳ 请求延迟 {sleep_time:.2f} 秒...")
        time.sleep(sleep_time)
    
    _last_request_time = time.time()


def _generate_search_variants(ga):
    """
    智能生成 groupId:artifactId 的搜索变体
    
    策略：
    1. 优先使用原始 GA
    2. 如果在配置的映射表中，使用配置的别名
    3. 智能推测常见的别名模式：
       - 去除最后一个子包名（com.alibaba.fastjson -> com.alibaba）
       - 去除常见后缀（-parent, -bom, -dependencies）
       - 添加/移除 artifactId 作为子包
    
    Args:
        ga: 格式为 "groupId:artifactId" 的字符串
    
    Returns:
        list: 按优先级排序的搜索变体列表
    """
    variants = [ga]  # 第一优先级：原始 GA
    
    try:
        groupid, artifactid = ga.split(":", 1)
        
        # 策略 1: 使用配置文件中的映射表
        if groupid in GROUPID_ALIAS_MAP:
            mapped_ga = f"{GROUPID_ALIAS_MAP[groupid]}:{artifactid}"
            if mapped_ga not in variants:
                variants.append(mapped_ga)
        
        # 策略 2: 去除最后一个子包名
        # 例如: com.alibaba.fastjson -> com.alibaba:fastjson
        if '.' in groupid:
            parts = groupid.rsplit('.', 1)
            if len(parts) == 2:
                parent_group = parts[0]
                last_part = parts[1]
                
                # 如果最后一部分与 artifactId 相似，尝试去除它
                if last_part.lower() in artifactid.lower() or artifactid.lower() in last_part.lower():
                    alt_ga = f"{parent_group}:{artifactid}"
                    if alt_ga not in variants:
                        variants.append(alt_ga)
        
        # 策略 3: 去除 artifactId 中的常见后缀
        suffixes = ['-parent', '-bom', '-dependencies', '-starter', '-core']
        for suffix in suffixes:
            if artifactid.endswith(suffix):
                base_artifactid = artifactid[:-len(suffix)]
                alt_ga = f"{groupid}:{base_artifactid}"
                if alt_ga not in variants:
                    variants.append(alt_ga)
        
        # 策略 4: 尝试将 artifactId 添加到 groupId
        # 例如: com.alibaba:fastjson -> com.alibaba.fastjson:fastjson
        alt_groupid = f"{groupid}.{artifactid}"
        alt_ga = f"{alt_groupid}:{artifactid}"
        if alt_ga not in variants:
            variants.append(alt_ga)
        
        # 策略 5: 只使用 groupId 的最后一部分
        # 例如: org.springframework.boot:spring-boot -> org.springframework:spring-boot
        if groupid.count('.') >= 2:
            parent_group = '.'.join(groupid.split('.')[:-1])
            alt_ga = f"{parent_group}:{artifactid}"
            if alt_ga not in variants:
                variants.append(alt_ga)
    
    except ValueError:
        # 如果 GA 格式不正确，只返回原始值
        pass
    
    return variants

# 根据给定的 groupId:artifactId和version 在snyk中查找漏洞，存储到vul_details_dict
@retry(stop_max_attempt_number=RETRY_TIMES)
def req_snyk(ga, version):
    # 已经查过的组件直接复用结果，避免重复请求
    if vul_details_dict.get((ga, version)) is not None:
        return
    res = []

    # 应用请求延迟
    _apply_request_delay()

    # 智能生成可能的搜索关键字列表
    search_ga_list = _generate_search_variants(ga)

    # 尝试所有可能的搜索关键字
    r = None
    for search_ga in search_ga_list:
        # 每次请求随机选择请求头
        headers = _get_random_headers()

        try:
            # 使用会话对象发起请求，复用 TCP 连接
            r = _session.get(f"{SNYK_BASE_URL}/vuln?search={search_ga}",
                           headers=headers,
                           timeout=REQUEST_TIMEOUT,
                           allow_redirects=True)

            # 检查响应状态
            if r.status_code == 403:
                if VERBOSE_LOGGING:
                    print(f"⚠️  403 Forbidden: {search_ga} - 可能触发反爬虫机制")
                # 如果是 403，等待更长时间后重试
                time.sleep(REQUEST_DELAY * 3)
                continue

            r.encoding = 'utf-8'
            # 如果找到结果，直接跳出循环
            if "No results found" not in r.text:
                if VERBOSE_LOGGING:
                    if search_ga != ga:
                        print(f"✓ 组件 {ga} 使用别名 {search_ga} 找到结果")
                break
        except requests.exceptions.Timeout:
            if VERBOSE_LOGGING:
                print(f"⏱️  请求超时 ({search_ga})")
            # 超时后继续尝试下一个别名
            continue
        except requests.exceptions.RequestException as e:
            if VERBOSE_LOGGING:
                print(f"❌ 请求 Snyk 失败 ({search_ga}): {e}")
            # 如果是最后一个尝试，标记为请求失败
            if search_ga == search_ga_list[-1]:
                vul_details_dict[(ga, version)] = None  # 使用 None 表示请求失败
                return
            # 否则尝试下一个别名
            continue

    # 所有尝试都未找到结果
    if r is None or "No results found" in r.text:
        vul_details_dict[(ga, version)] = []  # 无漏洞
        return
    soup = BeautifulSoup(r.text, "html.parser")
    # 使用新的CSS选择器获取表格行
    tr_list = soup.select("table.vulns-table__table > tbody > tr")
    for tr in tr_list:
        # 创建一个vul_details对象，记录搜索出来的每一个漏洞
        vul = vul_details()
        # 提取漏洞等级 - 使用新的选择器
        severity_elem = tr.select("span.severity__text")
        if severity_elem:
            vul.level = severity_elem[0].text.strip()
        else:
            # 备用选择器
            severity_elem = tr.select("[class*='severity']")
            if severity_elem:
                vul.level = severity_elem[0].text.strip()
            else:
                continue
        
        # 提取影响版本 - 使用新的选择器
        version_elem = tr.select("td:nth-child(2)")
        if version_elem:
            v_text = version_elem[0].text.strip()
            # 解析版本范围，例如 "org.apache.shiro:shiro-core[,1.10.0)"
            if "[" in v_text and ")" in v_text:
                version_range = v_text.split("[")[1].split(")")[0]
                if "," in version_range:
                    vul.min_version = version_range.split(",")[0].strip() if version_range.split(",")[0].strip() else "*"
                    vul.max_version = version_range.split(",")[1].strip() if version_range.split(",")[1].strip() else "*"
                else:
                    vul.min_version = version_range.strip()
                    vul.max_version = "*"
            else:
                vul.min_version = "*"
                vul.max_version = "*"
        else:
            continue
        # 如果组件版本在漏洞影响版本范围内，继续处理
        if not vul.version_is_affected(version):
            continue
        # 漏洞名字和详情页链接
        name_elem = tr.select("td:nth-child(1) > a")
        if not name_elem:
            continue
        vul.name = name_elem[0].text.strip()
        href = name_elem[0].get("href", "")
        if not href:
            continue
        vul.href = SNYK_BASE_URL + href
        # 访问漏洞详情页（使用会话对象和请求头）
        detail_headers = _get_random_headers()
        try:
            # 应用请求延迟
            _apply_request_delay()

            # 使用会话对象发起请求
            r1 = _session.get(vul.href, headers=detail_headers, timeout=REQUEST_TIMEOUT)

            # 检查响应状态
            if r1.status_code == 403:
                if VERBOSE_LOGGING:
                    print(f"⚠️  详情页 403 Forbidden: {vul.name}")
                # 403 时跳过详情提取，保留基本信息
                continue

            r1.encoding = 'utf-8'
            soup_detail = BeautifulSoup(r1.text, "html.parser")
            # 提取CVE编号 - 使用正则表达式搜索
            cve_match = re.search(r'CVE-\d{4}-\d{4,7}', r1.text)
            vul.cve = cve_match.group(0) if cve_match else "*"

            # 提取CWE编号 - 使用正则表达式搜索
            cwe_match = re.search(r'CWE-\d{1,4}', r1.text)
            vul.cwe = cwe_match.group(0) if cwe_match else "*"

            # 提取漏洞概述 - 查找包含Overview的部分
            overview_elem = soup_detail.find("h2", string=re.compile(r"Overview", re.IGNORECASE))
            if overview_elem:
                # 获取Overview后面的内容
                next_elem = overview_elem.find_next_sibling()
                overview_parts = []
                while next_elem and next_elem.name not in ["h2", "h1"]:
                    if next_elem.name == "p" or next_elem.name == "div":
                        text = next_elem.get_text(strip=True)
                        if text:
                            overview_parts.append(text)
                    next_elem = next_elem.find_next_sibling()
                    if len(overview_parts) >= 3:  # 限制长度
                        break
                vul.overview = " ".join(overview_parts) if overview_parts else "*"
            else:
                # 备用方法：从页面中提取描述文本
                desc_match = re.search(r'"description":"([^"]+)"', r1.text)
                if desc_match:
                    vul.overview = desc_match.group(1).replace('\\n', ' ').strip()
                else:
                    vul.overview = "*"
        except Exception as e:
            if VERBOSE_LOGGING:
                print(f"获取漏洞详情时出错: {e}")
            pass
            
        res.append(vul)
        
    if res:
        vul_details_dict[(ga, version)] = res
    else:
        vul_details_dict[(ga, version)] = []


# 漏洞检测,更新xml_res中的漏洞等级
def check_vul(progressbarOne, root, progressbar_tips):
    if not xml_res:
        return
    
    # 构建唯一组件列表 (ga, version)
    unique_pairs = []
    for info in xml_res:
        ga = f"{info[0]}:{info[1]}"
        version = info[2]
        key = (ga, version)
        if key not in unique_pairs:
            unique_pairs.append(key)

    # 检测所有组件（已移除数量限制）
    to_check = unique_pairs
    
    if VERBOSE_LOGGING:
        print(f"ℹ️  共发现 {len(unique_pairs)} 个唯一组件，开始全部检测")
    
    # 计算进度条最大值：检测次数 + 更新结果次数
    progressbarOne['maximum'] = len(to_check) + len(xml_res)
    # 进度值初始值
    progressbarOne['value'] = 0

    # 顺序请求 Snyk（避免网络超时）
    for ga, version in to_check:
        progressbar_tips.set("正在检测组件 " + ga)
        progressbarOne['value'] += 1
        root.update()
        try:
            req_snyk(ga, version)
        except Exception as e:
            if VERBOSE_LOGGING:
                print(f"检测组件 {ga} 时出错: {e}")

    # 根据 vul_details_dict 更新 xml_res 中的等级，并更新进度条
    for i in range(len(xml_res)):
        info = xml_res[i]
        ga = f"{info[0]}:{info[1]}"
        version = info[2]

        progressbar_tips.set("正在处理结果 " + ga)
        # 刷新进度条
        progressbarOne['value'] += 1
        root.update()

        level = "*"
        vul_list = vul_details_dict.get((ga, version))
        # None 表示请求失败，显示为 '请求失败'
        if vul_list is None:
            level = "请求失败"
        # [] 表示无漏洞，显示为 '*'
        elif len(vul_list) > 0:
            levels = [l.level for l in vul_list]
            # 使用配置文件中的漏洞等级映射
            for level_code, level_name in LEVEL_MAPPING.items():
                if level_code in levels:
                    level = level_name
                    break
            else:
                level = "*"
        xml_res[i] = [info[0], info[1], info[2], level, info[4]]


# 返回该组件在给定的版本中所有的漏洞详情(显示在文本框中的)
def get_details_by_version(ga, version):
    if vul_details_dict.get((ga, version)) != None:
        return vul_details_dict.get((ga, version))
    return []
