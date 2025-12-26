# PomEye

🔍 一款根据 pom.xml 获取引用的第三方组件的版本号并识别组件漏洞的工具

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

[FreeBuf介绍文章](https://www.freebuf.com/sectool/366383.html)

---

## ✨ 特性

- 🎨 **精致的图形界面** - 使用 ttkbootstrap 构建的现代化 GUI
- ⚡ **高效解析** - 基于 BeautifulSoup4 快速解析 pom.xml 文件
- 🌳 **父子依赖树** - 自动构建 `<parent>` 关系树，递归查找版本号
- 🔒 **漏洞检测** - 集成 Snyk 漏洞库，实时检测组件安全性
- 🏷️ **详细信息** - 显示漏洞名称、危险等级、影响版本、CVE/CWE 编号及详情链接
- ⚙️ **可配置** - 支持通过 `config.py` 自定义配置参数

---

## 💻 快速开始

### 环境要求

- Python 3.8+
- pip

### 安装步骤

#### 1. 克隆项目

```bash
git clone https://github.com/your-username/PomEye.git
cd PomEye
```

#### 2. 创建虚拟环境（推荐）

**Linux/macOS:**
```bash
python3 -m venv myenv
source myenv/bin/activate
```

**Windows:**
```cmd
python -m venv myenv
myenv\Scripts\activate
```

#### 3. 安装依赖

```bash
pip install -r requirements.txt
```

---

## 🚀 运行方法

### 方法 1：使用启动脚本（推荐）

**Linux/macOS:**
```bash
./run.sh
```

**Windows:**
```cmd
run.bat
```

### 方法 2：直接运行

```bash
python main.py
```

---

## 📸 运行截图

### 主界面
![截图1](img/截图1.png)

### 漏洞检测结果
![截图2](img/截图2.png)

### 漏洞详情
![截图3](img/截图3.png)

---

## 📁 项目结构

```
PomEye/
├── main.py              # 程序入口
├── parse.py             # pom.xml 解析模块
├── check_vul.py         # 漏洞检测模块
├── pom_parse_client.py  # GUI 界面模块
├── variables.py         # 全局变量定义
├── config.py            # 配置文件
├── requirements.txt     # 项目依赖
├── run.sh               # Linux/macOS 启动脚本
├── run.bat              # Windows 启动脚本
├── testxml/             # 测试用 XML 文件
└── img/                 # 截图资源
```

---

## ⚙️ 配置说明

可以通过修改 `config.py` 文件来自定义以下参数：

- **漏洞检测配置**: 请求超时、重试次数
- **文件解析配置**: 支持的编码格式
- **GUI 界面配置**: 主题、表格行数、窗口大小
- **漏洞等级配置**: 颜色映射、排序优先级
- **网络请求配置**: HTTP 请求头、Snyk URL

---

## 📝 使用说明

1. **启动程序**：运行 `run.sh`（Linux/macOS）或 `run.bat`（Windows）
2. **选择文件夹**：点击“选择文件夹”按钮，选择包含 pom.xml 文件的目录
3. **开始检测**：程序将自动解析 pom.xml 并检测漏洞
4. **查看结果**：点击任意组件查看详细的漏洞信息
5. **双击链接**：双击 URL 可在浏览器中打开漏洞详情页

---

## 🔧 技术栈

- **Python** - 主编程语言
- **BeautifulSoup4** - XML 解析
- **ttkbootstrap** - GUI 框架
- **Requests** - HTTP 请求
- **Snyk** - 漏洞数据源

---

## 📝 许可证

MIT License

---

## 👏 贡献

欢迎提交 Issue 和 Pull Request！

---

## 🔗 相关链接

- [FreeBuf 介绍文章](https://www.freebuf.com/sectool/366383.html)
- [Snyk 漏洞库](https://security.snyk.io)

