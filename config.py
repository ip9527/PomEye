# -*- coding: utf-8 -*-
"""
PomEye 配置文件
用于集中管理可配置参数，方便用户根据实际需求调整

使用方法：
1. 直接修改此文件中的参数值
2. 重启程序即可生效
3. 建议修改前备份此文件

配置说明：
- 所有参数都有详细的注释说明
- 建议值仅供参考，可根据实际情况调整
- 修改配置后无需重新编译，直接运行即可
"""

# ==================== 漏洞检测配置 ====================

# Snyk 请求超时时间（秒）
# 说明：单个 HTTP 请求的超时时间
# 建议值：5-15 秒
REQUEST_TIMEOUT = 15

# 请求重试次数
# 说明：当请求失败时自动重试的次数
# 建议值：2-5 次
RETRY_TIMES = 5

# 请求延迟时间（秒）
# 说明：每次请求之间的延迟，避免触发反爬虫机制
# 建议值：1-3 秒，遇到 403 错误时可以增加此值
REQUEST_DELAY = 2


# ==================== 文件解析配置 ====================

# 支持的文件编码列表
# 说明：按顺序尝试这些编码来读取 XML 文件
# 注意：优先使用 UTF-8，然后是中文编码
SUPPORTED_ENCODINGS = ['utf-8', 'gbk', 'gb2312']

# XML 文件扩展名
# 说明：只处理这些扩展名的文件
XML_FILE_EXTENSIONS = ['.xml']


# ==================== GUI 界面配置 ====================

# 主题名称
# 说明：ttkbootstrap 支持的主题
# 可选值：flatly, darkly, cosmo, journal, litera, lumen, minty, pulse, sandstone, united, yeti, solar
THEME_NAME = "pulse"

# 表格显示行数
# 说明：结果表格一次显示的最大行数
TABLE_HEIGHT = 20

# 窗口大小比例（相对于屏幕）
# 说明：主窗口宽度 = 屏幕宽度 * MAIN_WINDOW_WIDTH_RATIO
MAIN_WINDOW_WIDTH_RATIO = 1 / 3
MAIN_WINDOW_HEIGHT_RATIO = 2 / 3

# 结果窗口使用全屏
RESULT_WINDOW_FULLSCREEN = True


# ==================== 漏洞等级配置 ====================

# 漏洞等级映射
# 说明：Snyk API 返回的等级标识映射到中文显示
LEVEL_MAPPING = {
    'C': '严重',
    'H': '高危',
    'M': '中危',
    'L': '低危',
}

# 漏洞等级排序优先级（数字越小优先级越高）
# 说明：用于结果表格的排序
LEVEL_SORT_ORDER = {
    '严重': 0,
    '高危': 1,
    '中危': 2,
    '低危': 3,
    '*': 4,
    '请求失败': 5,
}

# 漏洞等级颜色配置
# 说明：表格中不同等级的背景颜色
LEVEL_COLORS = {
    '严重': 'tomato',
    '高危': 'orange',
    '中危': 'yellow',
    '低危': 'lightblue',
    '请求失败': ('lightgray', 'red'),  # (背景色, 文字色)
}


# ==================== GroupId 别名映射配置 ====================

# GroupId 别名映射表
# 说明：某些组件在 POM 文件和 Snyk 中的 groupId 不一致，需要手动指定映射
# 格式：{"pom_groupId": "snyk_groupId"}
# 示例：com.alibaba.fastjson 在 Snyk 中实际为 com.alibaba
#
# 🚀 智能映射机制：
# 程序会自动尝试多种可能的 groupId 组合，不完全依赖此映射表。
# 映射表的作用是提供优先级更高的搜索选项。
#
# 自动尝试的策略包括：
# 1. 原始 GA（最高优先级）
# 2. 配置的映射表（如果存在）
# 3. 去除最后一个子包名（com.alibaba.fastjson -> com.alibaba）
# 4. 去除 artifactId 后缀（spring-boot-starter -> spring-boot）
# 5. 添加/移除 artifactId 作为子包
# 6. 只使用 groupId 的父级包
#
# 因此，即使不在此表中的组件，程序也会智能尝试多种可能性。
# 只有在需要提高特定组件的搜索优先级时，才需要手动添加到此表。
GROUPID_ALIAS_MAP = {
   
    # 可以继续添加其他映射，例如：
    # "org.springframework.boot": "org.springframework",
    # "io.netty": "io.netty.netty",
}


# ==================== 网络请求配置 ====================

# HTTP 请求头配置
# 说明：为了避免被反爬虫机制拦截，使用随机现代化浏览器请求头
# 每次请求会从请求头池中随机选择一个，模拟真实用户行为

# 现代化浏览器请求头池（随机选择）
REQUEST_HEADERS_POOL = [
    # Chrome 131+ (Windows 11) - 最新版本
    {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
        'Accept-Encoding': 'gzip, deflate, br',
        'Sec-Ch-Ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'Sec-Ch-Ua-Mobile': '?0',
        'Sec-Ch-Ua-Platform': '"Windows"',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0',
    },
    # Firefox 133+ (Windows 11) - 最新版本
    {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Priority': 'u=0, i',
    },
    # Edge 131+ (Windows 11) - 最新版本
    {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Sec-Ch-Ua': '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'Sec-Ch-Ua-Mobile': '?0',
        'Sec-Ch-Ua-Platform': '"Windows"',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0',
    },
    # Chrome 131+ (macOS) - 最新版本
    {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Sec-Ch-Ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'Sec-Ch-Ua-Mobile': '?0',
        'Sec-Ch-Ua-Platform': '"macOS"',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0',
    },
    # Safari 18+ (macOS) - 最新版本
    {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
    },
    # Chrome 131+ (Linux) - 添加 Linux 支持
    {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Sec-Ch-Ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'Sec-Ch-Ua-Mobile': '?0',
        'Sec-Ch-Ua-Platform': '"Linux"',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0',
    },
]

# 默认请求头（兼容性，不建议直接使用）
REQUEST_HEADERS = REQUEST_HEADERS_POOL[0]

# Snyk 漏洞库 URL
SNYK_BASE_URL = "https://security.snyk.io"


# ==================== 调试配置 ====================

# 是否显示调试信息
# 说明：开启后会在控制台打印更多调试信息
DEBUG_MODE = False

# 是否在检测时打印详细日志
VERBOSE_LOGGING = True
