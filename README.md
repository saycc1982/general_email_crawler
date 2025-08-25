本代码已在Ubuntu 22.04 上测试并运行成功, 如要其他LINUX 系统上运行, 可以自行测试.

配置要求: 8核 8G 内存 10M带宽 Ubuntu 22.04

建议在一台全新云主机上运行以防止软件跟老系统冲突,可以到以下网址线上即时开通云主机

https://www.say.cc

_________________________________________________________________________________

一、运行代码的步骤
将爬虫代码保存为 general_crawler.py
赋予执行权限（可选）：

chmod +x general_crawler.py

运行代码（示例）：
```bash
python3 general_crawler.py "https://www.china.com" -v
```
如果你比较贪心, 想跨域名及大量爬行网页连接来获取更多邮箱, 可以使用以下疯狂模式

(对服务器CPU及内存配置要求更高, 而且长时间在同一网站爬行被封IP风险也会增加)

```bash
python3 general_crawler.py "https://www.china.com" -v -t 2000 -d 1000 -m 100000000 -p 100000000 --ignore-ssl --cross-domain
```
```bash
usage: general_crawler.py [-h] [-d DELAY] [-m MAX_DEPTH] [-p MAX_PAGES] [-v] [--ignore-ssl] [--cookie COOKIE] [--cookie-mode {all,login-only,browsing-only}] [--cookie-frequency COOKIE_FREQUENCY]
                          [--no-frames] [--no-dynamic] [--cross-domain] [-t TIMEOUT]
                          url

通用网络爬虫工具 - 支持自定义超时时间，自动去重邮箱并过滤PDF文件

positional arguments:
  url                   目标URL（支持带GET参数，如：https://example.com/list?id=1&page=2）

options:
  -h, --help            show this help message and exit
  -d DELAY, --delay DELAY
                        爬取间隔(毫秒)，默认2000ms
  -m MAX_DEPTH, --max-depth MAX_DEPTH
                        最大爬取深度，默认3层
  -p MAX_PAGES, --max-pages MAX_PAGES
                        最大爬取页面数，默认50页
  -v, --verbose         显示详细日志
  --ignore-ssl          忽略SSL证书验证
  --cookie COOKIE       初始Cookie文件路径
  --cookie-mode {all,login-only,browsing-only}
                        Cookie处理模式（默认all）
  --cookie-frequency COOKIE_FREQUENCY
                        Cookie保存频率（每爬取多少页保存一次），默认10页
  --no-frames           禁用框架(iframe/frame)处理
  --no-dynamic          禁用动态内容提取
  --cross-domain        允许跨域爬取（默认禁用）
  -t TIMEOUT, --timeout TIMEOUT
                        超时时间(毫秒)，默认2000ms（2秒），例如 -t 3000 表示3秒
```



以下是在 Ubuntu 22.04 系统上准备运行通用爬虫代码所需的完整安装步骤，包括系统依赖和 Python 库：

二、系统更新与基础依赖安装

首先更新系统并安装必要的系统工具：


# 更新系统包列表
sudo apt update

# 升级已安装的包（可选但推荐）
sudo apt upgrade -y

# 安装基础工具（包括Python3和pip3）
sudo apt install -y python3 python3-pip python3-dev python3-distutils

# 安装其他必要的系统依赖
sudo apt install -y build-essential lib libssl-dev libffi-dev-dev libxml2-dev libxslt1-dev zlib1g-dev


这些系统依赖用于支持 Python 库的编译和运行，特别是处理网络请求和 HTML 解析时需要。
三、Python 库安装
使用 pip3 安装爬虫代码所需的 Python 库：

# 升级pip到最新版本
pip3 install --upgrade pip

# 安装主要依赖库
pip3 install requests beautifulsoup4 colorlog

# 安装可选的辅助库（处理特殊情况）
pip3 install lxml  # 更高效的HTML解析器，BeautifulSoup会自动使用
pip3 install urllib3  # 增强的HTTP客户端，requests依赖它

四、安装说明与验证

关键库说明：

requests：用于发送 HTTP 请求，爬取网页内容

beautifulsoup4：解析 HTML 页面，提取链接和信息

colorlog：提供彩色日志输出，使运行过程更易读

lxml：高性能的 HTML/XML 解析器，加速页面解析

验证安装：

安装完成后，可以通过以下命令验证是否安装成功：

# 检查Python版本（应显示3.10.x或类似版本）
python3 --version

# 检查pip版本
pip3 --version

# 验证库是否安装成功
pip3 list | grep -E "requests|beautifulsoup4|colorlog|lxml"

如果输出中能看到这些库及其版本号，说明安装成功。



五、可能遇到的问题及解决

权限问题：

如果安装 Python 库时出现权限错误，可使用--user参数安装到用户目录：

pip3 install --user requests beautifulsoup4 colorlog

代理问题：

如果系统需要通过代理访问网络，需先配置代理：


export http_proxy=http://代理地址:端口

export https_proxy=https://代理地址:端口

SSL 证书问题：

如果遇到 SSL 相关错误，可以安装证书工具：

sudo apt install -y ca-certificates

如果爬行时卡住没有反应, 可能是网络繁忙或对方网站把你的IP临时封锁了, 可以按 CTRL C 来保存己爬到的邮箱

并把爬行间隔时间参数增长如 -d 3000 (3秒) 或更换IP 再爬行

如有BUG 或问题, 欢迎 https://t.me/hongkongisp 联络作者或在GITHUB 上提出.
