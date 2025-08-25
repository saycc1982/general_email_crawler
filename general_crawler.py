# 作者 ED, Telegram 联络 https://t.me/hongkongisp
#服务器赞助 顺安云 https://say.cc
#线上即时开通云主机, 请到顺安云
import re
import argparse
import socket
import logging
import time
import requests
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse, unquote
from datetime import datetime
from http.cookiejar import LWPCookieJar, Cookie
import warnings
import os
from bs4 import BeautifulSoup

# 尝试导入colorlog，如果没有则使用普通日志
try:
    import colorlog
    has_colorlog = True
except ImportError:
    has_colorlog = False

# 忽略SSL证书验证的警告
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# 配置日志（支持颜色输出）
def setup_logger(verbose):
    log_level = logging.DEBUG if verbose else logging.INFO
    
    if has_colorlog:
        log_format = (
            '%(asctime)s - '
            '%(log_color)s%(levelname)s%(reset)s - '
            '%(message)s'
        )
        color_formatter = colorlog.ColoredFormatter(
            log_format,
            datefmt='%Y-%m-%d %H:%M:%S',
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'red,bg_white',
            },
            secondary_log_colors={},
            style='%'
        )
        
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(color_formatter)
        file_handler = logging.FileHandler('general_crawler.log')
        file_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        
        logger = logging.getLogger(__name__)
        logger.setLevel(log_level)
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)
        return logger
    else:
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            handlers=[
                logging.FileHandler('general_crawler.log'),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)

# 通用请求头
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Accept-Encoding": "gzip, deflate, br"
}

# 创建会话，保持cookies
session = requests.Session()
session.headers.update(HEADERS)
session.cookies = LWPCookieJar()
session.verify = False  # 全局禁用SSL证书验证

class FrameHandler:
    """处理iframe/frame框架内容"""
    @staticmethod
    def extract_frame_sources(page_source, base_url, logger):
        frame_sources = []
        try:
            soup = BeautifulSoup(page_source, 'html.parser')
            for tag in ['iframe', 'frame']:
                elements = soup.find_all(tag)
                for elem in elements:
                    src = elem.get('src')
                    if src:
                        full_url = urljoin(base_url, src)
                        frame_sources.append(full_url)
                        logger.debug(f"发现{tag}框架: {full_url}")
        except Exception as e:
            logger.warning(f"提取框架内容时出错: {str(e)}")
        return frame_sources
    
    @staticmethod
    def fetch_frame_content(url, session, logger, timeout=10):
        # 检查是否为PDF文件，如果是则跳过
        if FrameHandler.is_pdf_url(url, logger):
            return None
            
        try:
            response = session.get(url, timeout=timeout)
            response.raise_for_status()
            
            # 检查响应内容是否为PDF
            content_type = response.headers.get('Content-Type', '').lower()
            if 'application/pdf' in content_type:
                logger.debug(f"跳过PDF内容: {url}")
                return None
                
            logger.debug(f"成功获取框架内容: {url}")
            return response.text
        except Exception as e:
            logger.warning(f"获取框架内容失败 {url}: {str(e)}")
            return None
    
    @staticmethod
    def is_pdf_url(url, logger):
        """检查URL是否指向PDF文件"""
        # 检查URL路径是否以.pdf结尾
        parsed = urlparse(url)
        if parsed.path.lower().endswith('.pdf'):
            logger.debug(f"检测到PDF URL: {url}")
            return True
        return False

class DynamicContentHandler:
    """提取JavaScript动态生成的链接"""
    @staticmethod
    def extract_dynamic_links(page_source, base_url, logger):
        dynamic_links = []
        patterns = [
            r'window\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
            r'location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
            r'window\.open\s*\(["\']([^"\']+)["\']',
            r'(?:redirect|goTo|loadPage)\s*\(["\']([^"\']+)["\']'
        ]
        for pattern in patterns:
            matches = re.findall(pattern, page_source, re.IGNORECASE)
            for match in matches:
                # 解码URL编码字符
                decoded_match = unquote(match)
                full_url = urljoin(base_url, decoded_match)
                # 检查是否为PDF链接，如果是则跳过
                if not FrameHandler.is_pdf_url(full_url, logger):
                    dynamic_links.append(full_url)
                    logger.debug(f"发现动态链接: {full_url}")
        return list(set(dynamic_links))

def force_load_cookies(cookie_file, domain, logger):
    """强制加载Cookie文件"""
    try:
        with open(cookie_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        cookies_added = 0
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            fields = re.split(r'[\t\s]+', line)
            if len(fields) != 7:
                logger.warning(f"跳过无效行 {line_num}：字段数量不正确（{len(fields)}个，需7个）")
                continue
            
            domain_cookie, flag, path, secure, expiry, name, value = fields
            if not (domain_cookie == domain or 
                    domain_cookie.startswith(f'.{domain}') or
                    domain.endswith(domain_cookie)):
                continue
            
            try:
                expiry = int(expiry) if expiry else None
                secure = secure.upper() == 'TRUE'
                domain_specified = domain_cookie.startswith('.')
                
                cookie = Cookie(
                    version=0, name=name, value=value, port=None, port_specified=False,
                    domain=domain_cookie, domain_specified=domain_specified,
                    domain_initial_dot=domain_cookie.startswith('.'),
                    path=path, path_specified=True, secure=secure, expires=expiry,
                    discard=False, comment=None, comment_url=None, rest={}, rfc2109=False
                )
                session.cookies.set_cookie(cookie)
                cookies_added += 1
                logger.debug(f"强制加载Cookie: {name}={value}（域名: {domain_cookie}）")
            except Exception as e:
                logger.warning(f"解析行 {line_num} 失败: {str(e)}")
                continue
        
        logger.info(f"✅ 强制加载完成，共添加 {cookies_added} 个Cookie")
        return cookies_added > 0
    except Exception as e:
        logger.error(f"❌ 强制加载Cookie失败: {str(e)}")
        return False

def save_cookies_to_file(cookies, url, logger, suffix=""):
    """保存Cookie到cookie文件夹"""
    try:
        if not os.path.exists('cookie'):
            os.makedirs('cookie')
            logger.debug("创建cookie文件夹")
        
        parsed_url = urlparse(url)
        safe_domain = re.sub(r'[^\w\-_.]', '_', parsed_url.netloc)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        filename = f"cookie/{safe_domain}_{timestamp}_{suffix}.txt" if suffix else f"cookie/{safe_domain}_{timestamp}.txt"
        
        content = [
            "# Netscape HTTP Cookie File\n",
            "# https://curl.se/docs/http-cookies.html\n",
            f"# 来源URL: {url}\n",
            f"# 保存时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n",
            "\n"
        ]
        for cookie in cookies:
            domain = cookie.domain
            flag = "TRUE" if cookie.domain_specified else "FALSE"
            path = cookie.path
            secure = "TRUE" if cookie.secure else "FALSE"
            expiry = cookie.expires if cookie.expires else 0
            line = f"{domain}\t{flag}\t{path}\t{secure}\t{expiry}\t{cookie.name}\t{cookie.value}\n"
            content.append(line)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.writelines(content)
        
        logger.debug(f"已保存 {len(cookies)} 个Cookie到 {filename}")
        return filename
    except Exception as e:
        logger.error(f"❌ 保存Cookie到文件失败: {str(e)}")
        return None

class CookieFileFixer:
    """修复Cookie文件格式"""
    @staticmethod
    def fix_cookie_file(input_path, output_path=None, logger=None):
        if not output_path:
            base, ext = os.path.splitext(input_path)
            output_path = f"{base}_fixed{ext}"
        
        try:
            with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            has_netscape_header = any(
                line.strip().lower().startswith('# netscape http cookie file') 
                for line in lines
            )
            fixed_lines = []
            
            if not has_netscape_header:
                fixed_lines.extend([
                    "# Netscape HTTP Cookie File\n",
                    "# https://curl.se/docs/http-cookies.html\n",
                    "# Fixed by General Crawler\n",
                    "\n"
                ])
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                if ' ' in line and '\t' not in line:
                    fields = line.split()
                    if len(fields) == 7:
                        fixed_line = '\t'.join(fields) + '\n'
                        fixed_lines.append(fixed_line)
                        logger.debug(f"修复行 {line_num}：空格转Tab")
                    else:
                        logger.warning(f"跳过无效行 {line_num}：字段数{len(fields)}（需7个）")
                elif '\t' in line:
                    fields = line.split('\t')
                    if len(fields) == 7:
                        if fields[1].lower() in ['true', 'false']:
                            fields[1] = fields[1].upper()
                        if fields[3].lower() in ['true', 'false']:
                            fields[3] = fields[3].upper()
                        fixed_lines.append('\t'.join(fields) + '\n')
                    else:
                        logger.warning(f"跳过无效行 {line_num}：字段数{len(fields)}（需7个）")
                else:
                    logger.warning(f"跳过无法识别的行 {line_num}")
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.writelines(fixed_lines)
            logger.info(f"✅ Cookie文件修复完成：{output_path}")
            return output_path
        except Exception as e:
            logger.error(f"❌ 修复Cookie文件失败: {str(e)}")
            return None

class GeneralCrawler:
    def __init__(self, target_url, delay_ms=2000, max_depth=3, max_pages=50, 
                 ignore_ssl=False, cookie_file=None, cookie_mode='all', 
                 save_cookies_frequency=10, logger=None, allow_cross_domain=False,
                 timeout_ms=2000):  # 新增超时参数
        # 过滤规则 - 包含PDF文件过滤
        self.exclude_extensions = r'\.(pdf|jpg|jpeg|png|gif|bmp|tiff|webp|ico|doc|docx|xls|xlsx|ppt|pptx|zip|rar|tar|gz|7z|exe|dll|bin|iso|mp3|mp4|avi|mov|flv|wmv)$'
        self.exclude_prefixes = r'^(javascript:|data:|tel:|sms:|ftp:|irc:|magnet:|mailto:)'
        # 通用GET参数集合
        self.keep_params = {'id', 'cate', 'fid', 'gid', 'action', 'q', 'query', 'page', 'p', 
                           'wd', 'lang', 'hl', 'offset', 'limit', 'sort', 'order'}
        self.login_paths = r'(/login|/signin|/account/login|/user/login|/auth/login|/session/new)'
        
        # Cookie检测参数
        self.cookie_check_params = {'cookie', 'cookies', 'ck', 'cookie_support', 'cookie_check', 'session', 'sid'}
        
        # 内容页面模式
        self.content_page_patterns = [
            r'/detail\.html\?id=\d+',
            r'/view\.php\?id=\d+',
            r'/article/\d+',
            r'/news/\d+',
            r'/post/\d+'
        ]
        
        # 框架和动态内容处理开关
        self.handle_frames = True
        self.handle_dynamic_content = True
        
        # 调试和性能配置
        self.max_links_per_page = 5000  # 每页最大处理链接数
        self.link_queue_warning_threshold = 10000  # 队列警告阈值
        
        # Cookie处理配置
        self.cookie_mode = cookie_mode
        self.login_cookie_keywords = {'session', 'token', 'user', 'auth', 'login', 'sid', 'uid', 'sessionid'}
        self.browsing_cookie_keywords = {'theme', 'lang', 'view', 'layout', 'font', 'preference', 'cookie_accepted'}
        self.save_cookies_frequency = save_cookies_frequency  # Cookie保存频率
        self.last_saved_cookie_count = 0  # 上次保存的Cookie数量
        self.saved_cookie_files = []  # 保存的Cookie文件列表
        
        # 超时设置 - 新增
        self.timeout = timeout_ms / 1000.0  # 转换为秒
        self.frame_timeout = max(5.0, self.timeout)  # 框架超时至少5秒
        
        # 目标URL处理 - 支持带GET参数的URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = f'https://{target_url}'
        parsed_url = urlparse(target_url)
        self.base_domain = parsed_url.netloc
        self.start_url = target_url
        self.allow_cross_domain = allow_cross_domain  # 是否允许跨域爬取
        
        # 加载Cookie文件
        self.cookie_file = cookie_file
        self.fixed_cookie_file = None
        if self.cookie_file and logger:
            load_success = self.load_cookies(self.cookie_file, logger)
            if not load_success:
                logger.info("尝试自动修复Cookie文件...")
                self.fixed_cookie_file = CookieFileFixer.fix_cookie_file(self.cookie_file, logger=logger)
                if self.fixed_cookie_file:
                    load_success = self.load_cookies(self.fixed_cookie_file, logger, is_fixed=True)
            if not load_success:
                logger.info("标准加载失败，尝试强制加载Cookie...")
                force_load_cookies(self.cookie_file, self.base_domain, logger)
                if self.fixed_cookie_file:
                    force_load_cookies(self.fixed_cookie_file, self.base_domain, logger)
        
        # 存储结构 - 邮箱去重机制：使用小写邮箱作为键
        self.visited_urls = set()
        self.processed_frames = set()
        self.queue = [(self._standardize_url(target_url, keep_all_get_params=True), 0)]
        self.emails = {}  # 键：小写邮箱，值：原始邮箱（保留原始大小写）
        self.blocked_urls = {"login": set(), "captcha": set()}
        self.pdf_urls = set()  # 记录检测到的PDF文件URL
        
        # 控制参数
        self.delay = delay_ms / 1000.0
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.crawled_count = 0
        
        # 统计信息 - 包含邮箱去重和超时统计
        self.status_stats = {"200":0,"404":0,"403":0,"超时":0,"其他错误":0,"被login拦截":0,"被captcha拦截":0}
        self.depth_stats = {}
        self.speed_stats = []
        self.frame_stats = {"found":0,"processed":0,"failed":0, "超时":0}  # 增加框架超时统计
        self.cookie_stats = {"total":0,"login":0,"browsing":0,"unknown":0}
        self.link_stats = {"extracted":0, "added":0, "duplicates":0, "filtered":0, "pdf":0}
        self.email_stats = {"found":0, "unique":0, "duplicates":0}  # 邮箱统计
        
        # 输出文件
        safe_domain = self.base_domain.replace('.', '_')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_file = f"emails_{safe_domain}_{timestamp}.txt"
        self.blocked_file = f"blocked_urls_{safe_domain}_{timestamp}.txt"
        self.pdf_file = f"pdf_urls_{safe_domain}_{timestamp}.txt"  # 保存检测到的PDF URL
        
        self.logger = logger or logging.getLogger(__name__)

    def _classify_cookie(self, cookie_name):
        """分类Cookie类型"""
        cookie_name_lower = cookie_name.lower()
        for keyword in self.login_cookie_keywords:
            if keyword in cookie_name_lower:
                return "login"
        for keyword in self.browsing_cookie_keywords:
            if keyword in cookie_name_lower:
                return "browsing"
        return "unknown"

    def load_cookies(self, cookie_file, logger, is_fixed=False):
        """加载Cookie文件，并根据模式过滤所需类型的Cookie"""
        try:
            self.cookie_stats = {"total": 0, "login": 0, "browsing": 0, "unknown": 0}
            
            if not os.path.exists(cookie_file):
                logger.warning(f"⚠️ Cookie文件不存在: {cookie_file}")
                return False
                
            if os.path.getsize(cookie_file) == 0:
                logger.warning(f"⚠️ Cookie文件为空: {cookie_file}")
                return False

            temp_cj = LWPCookieJar()
            temp_cj.load(cookie_file, ignore_discard=True, ignore_expires=True)
            
            loaded_count = 0
            for cookie in temp_cj:
                if not (cookie.domain == self.base_domain or 
                        cookie.domain.startswith(f'.{self.base_domain}') or
                        self.base_domain.endswith(cookie.domain)):
                    continue
                
                cookie_type = self._classify_cookie(cookie.name)
                self.cookie_stats["total"] += 1
                self.cookie_stats[cookie_type] += 1
                
                if self.cookie_mode == 'all':
                    session.cookies.set_cookie(cookie)
                    loaded_count += 1
                elif self.cookie_mode == 'login-only' and cookie_type == 'login':
                    session.cookies.set_cookie(cookie)
                    loaded_count += 1
                elif self.cookie_mode == 'browsing-only' and cookie_type == 'browsing':
                    session.cookies.set_cookie(cookie)
                    loaded_count += 1
            
            logger.info(
                f"🍪 Cookie加载统计: 总计{self.cookie_stats['total']}个 "
                f"(登录相关: {self.cookie_stats['login']}, 浏览设置: {self.cookie_stats['browsing']})"
            )
            logger.info(f"📌 根据模式 '{self.cookie_mode}' 加载了 {loaded_count} 个Cookie")
            
            if is_fixed:
                logger.info("✅ 修复后的Cookie文件加载成功！")
                
            # 保存初始加载的Cookie
            if loaded_count > 0:
                cookie_file = save_cookies_to_file(
                    session.cookies, 
                    self.start_url, 
                    self.logger, 
                    suffix="initial"
                )
                if cookie_file:
                    self.saved_cookie_files.append(cookie_file)
                
            return True
            
        except Exception as e:
            logger.warning(f"⚠️ 加载Cookie文件失败: {str(e)}")
            return False

    def _standardize_url(self, url, keep_all_get_params=False):
        """标准化URL：保留GET参数，仅去锚点"""
        parsed = urlparse(url)
        # 移除锚点，但保留所有GET参数
        parsed = parsed._replace(fragment='')
        
        # 如果是起始URL或需要保留所有GET参数，则不过滤参数
        if not keep_all_get_params and parsed.query:
            query_dict = parse_qs(parsed.query)
            filtered_params = {}
            
            for param, values in query_dict.items():
                # 保留重要参数
                if param in self.keep_params:
                    valid_values = [v.strip() for v in values if v.strip()]
                    if valid_values:
                        filtered_params[param] = valid_values[0]
                elif param in self.cookie_check_params:
                    valid_values = [v.strip() for v in values if v.strip()]
                    if valid_values:
                        filtered_params[param] = valid_values[0]
        
            sorted_params = sorted(filtered_params.items())
            parsed = parsed._replace(query=urlencode(sorted_params))
        
        # 解码URL以确保一致性
        standardized = urlunparse(parsed)
        return unquote(standardized)

    def _should_exclude_link(self, link):
        """过滤无效链接，包含PDF文件过滤"""
        if not link or link.strip() == '':
            self.link_stats["filtered"] += 1
            return True
        
        parsed = urlparse(link)
        
        # 特别检查是否为PDF文件
        if parsed.path.lower().endswith('.pdf'):
            self.logger.debug(f"🔍 过滤PDF文件: {link}")
            self.link_stats["filtered"] += 1
            self.link_stats["pdf"] += 1
            self.pdf_urls.add(link)  # 记录PDF URL
            return True
        
        # 过滤登录相关路径
        if re.search(self.login_paths, parsed.path, re.IGNORECASE):
            self.logger.debug(f"🔒 过滤登录相关路径: {link}")
            self.link_stats["filtered"] += 1
            return True
        
        if re.match(self.exclude_prefixes, link, re.IGNORECASE):
            self.link_stats["filtered"] += 1
            return True
        
        # 过滤媒体文件
        media_extensions = r'\.(jpg|jpeg|png|gif|bmp|tiff|webp|ico|mp3|mp4|avi|mov|flv|wmv)$'
        if re.search(media_extensions, link, re.IGNORECASE):
            self.link_stats["filtered"] += 1
            return True
        
        # 处理域名限制
        if parsed.netloc and not self.allow_cross_domain:
            if not (parsed.netloc == self.base_domain or parsed.netloc.endswith(f'.{self.base_domain}')):
                self.link_stats["filtered"] += 1
                return True
        
        return False

    def _is_blocked_page(self, page_source, url):
        """页面检测逻辑"""
        parsed_url = urlparse(url)
        path = parsed_url.path or '/'
        
        # 内容页面模式匹配
        for pattern in self.content_page_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                self.logger.debug(f"📌 内容页面模式匹配: {url} 不判定为登录页")
                return False, None
        
        # 检查URL是否包含内容ID参数
        query_params = parse_qs(parsed_url.query)
        if 'id' in query_params and query_params['id'][0].isdigit():
            self.logger.debug(f"📌 包含内容ID参数，不判定为登录页: {url}")
            return False, None
        
        # 检查URL是否包含Cookie参数
        has_cookie_param = any(param in self.cookie_check_params for param in query_params.keys())
        if has_cookie_param:
            self.logger.debug(f"🍪 包含Cookie参数，不判定为登录页: {url}")
            return False, None
        
        # 解析页面结构
        soup = BeautifulSoup(page_source, 'html.parser')
        page_text = page_source.lower()
        
        # 登录页面检测
        login_keywords = ['登录', '注册', 'sign in', 'login', 'sign up', '请登录', '会员中心']
        keyword_count = sum(1 for kw in login_keywords if kw.lower() in page_text)
        
        # 表单元素检测
        password_fields = soup.find_all('input', {'type': 'password'})
        
        if keyword_count >= 2 and len(password_fields) > 0:
            self.logger.warning(f"🔒 检测到登录页面: {url}")
            return True, "login"
        
        # 验证码页面检测
        captcha_keywords = ['验证码', 'captcha', '图形验证', 'security code', '安全验证']
        has_captcha_keywords = any(kw.lower() in page_text for kw in captcha_keywords)
        
        captcha_elements = (soup.find_all('img', alt=re.compile('|'.join(captcha_keywords), re.IGNORECASE)) or
                          soup.find_all('input', {'name': re.compile('captcha', re.IGNORECASE)}))
        
        if has_captcha_keywords and len(captcha_elements) > 0:
            self.logger.warning(f"🔒 检测到验证码页面: {url}")
            return True, "captcha"
        
        return False, None

    def _process_frames(self, current_url, page_source, current_depth):
        """处理页面中的框架内容，使用自定义超时时间"""
        if not self.handle_frames or current_depth >= self.max_depth:
            return ""
            
        frame_urls = FrameHandler.extract_frame_sources(page_source, current_url, self.logger)
        self.frame_stats["found"] += len(frame_urls)
        
        combined_content = ""
        
        for frame_url in frame_urls:
            # 检查是否为PDF文件
            if FrameHandler.is_pdf_url(frame_url, self.logger):
                self.link_stats["pdf"] += 1
                self.pdf_urls.add(frame_url)
                self.logger.debug(f"跳过PDF框架: {frame_url}")
                continue
                
            standardized_url = self._standardize_url(frame_url)
            
            if standardized_url in self.processed_frames:
                continue
                
            if self._should_exclude_link(standardized_url):
                continue
                
            self.processed_frames.add(standardized_url)
            
            # 使用框架超时时间（至少5秒）
            frame_content = FrameHandler.fetch_frame_content(
                standardized_url, 
                session, 
                self.logger, 
                timeout=self.frame_timeout  # 使用自定义超时
            )
            
            if frame_content:
                self.frame_stats["processed"] += 1
                combined_content += frame_content + "\n\n"
                self._extract_links(standardized_url, frame_content, current_depth)
                self._extract_emails(frame_content)
            else:
                # 检查是否是超时导致的失败
                if "超时" in str(frame_content).lower():
                    self.frame_stats["超时"] += 1
                self.frame_stats["failed"] += 1
        
        return combined_content

    def _save_current_cookies(self, current_url):
        """保存当前会话中的Cookie"""
        current_cookie_count = len(session.cookies)
        
        # 仅在Cookie有变化时才保存
        if current_cookie_count != self.last_saved_cookie_count:
            cookie_file = save_cookies_to_file(
                session.cookies, 
                current_url, 
                self.logger,
                suffix=f"page{self.crawled_count}"
            )
            if cookie_file:
                self.saved_cookie_files.append(cookie_file)
                self.last_saved_cookie_count = current_cookie_count
                self.logger.info(f"💾 已保存Cookie到 {cookie_file} (共 {current_cookie_count} 个)")
        else:
            self.logger.debug(f"Cookie未发生变化，跳过保存 (当前 {current_cookie_count} 个)")

    def _extract_links(self, current_url, page_source, current_depth):
        """从页面源码提取链接，跳过PDF链接"""
        if current_depth >= self.max_depth:
            self.logger.debug(f"📉 已达最大深度 {self.max_depth}，不再提取新链接")
            return
        
        # 提取a标签链接
        link_patterns = [r'<a [^>]*href=["\']([^"\']+)["\']']
        matches = []
        for pattern in link_patterns:
            matches.extend(re.findall(pattern, page_source, re.IGNORECASE))
        
        # 提取动态链接（已在DynamicContentHandler中过滤PDF）
        if self.handle_dynamic_content:
            dynamic_matches = DynamicContentHandler.extract_dynamic_links(page_source, current_url, self.logger)
            matches.extend(dynamic_matches)
        
        # 去重并限制数量，防止内存溢出
        unique_links = list(set(matches))
        self.link_stats["extracted"] += len(unique_links)
        
        # 如果链接过多，进行截断并记录警告
        if len(unique_links) > self.max_links_per_page:
            self.logger.warning(f"⚠️ 页面链接过多，截断为 {self.max_links_per_page} 个（原始数量: {len(unique_links)}）")
            unique_links = unique_links[:self.max_links_per_page]
        
        self.logger.debug(f"从 {current_url} 提取到 {len(unique_links)} 个链接 (累计提取: {self.link_stats['extracted']})")
        
        new_links_added = 0
        for raw_link in unique_links:
            raw_link = raw_link.strip().replace('\\', '')
            # 解码URL编码字符
            decoded_link = unquote(raw_link)
            full_link = urljoin(current_url, decoded_link)
            
            # 检查是否为PDF链接
            if full_link.lower().endswith('.pdf'):
                self.link_stats["pdf"] += 1
                self.pdf_urls.add(full_link)
                self.logger.debug(f"跳过PDF链接: {full_link}")
                continue
                
            standardized_link = self._standardize_url(full_link)
            
            if self._should_exclude_link(standardized_link):
                continue
            
            new_depth = current_depth + 1
            
            if new_depth > self.max_depth:
                self.logger.debug(f"📉 超深度限制（{new_depth} > {self.max_depth}），跳过: {standardized_link}")
                continue
            
            # 检查是否已访问或已在队列中
            already_visited = standardized_link in self.visited_urls
            already_in_queue = any(standardized_link == q[0] for q in self.queue)
            
            if not already_visited and not already_in_queue:
                self.queue.append((standardized_link, new_depth))
                new_links_added += 1
                self.link_stats["added"] += 1
            else:
                self.link_stats["duplicates"] += 1
        
        self.logger.debug(f"从 {current_url} 向队列添加了 {new_links_added} 个新链接 (累计添加: {self.link_stats['added']})")

    def _extract_emails(self, page_source):
        """提取邮箱地址，处理大小写不同的重复邮箱"""
        email_pattern = r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
        found_emails = re.findall(email_pattern, page_source)
        
        for email in found_emails:
            # 转换为小写作为键，用于检测重复
            email_lower = email.lower()
            self.email_stats["found"] += 1  # 累计总发现数
            
            if email_lower not in self.emails:
                # 新邮箱，添加到字典
                self.emails[email_lower] = email
                self.email_stats["unique"] += 1  # 累计唯一数
                self.logger.info(f"📧 发现新邮箱: {email}（总计唯一: {self.email_stats['unique']}）")
            else:
                # 重复邮箱，仅更新统计
                self.email_stats["duplicates"] += 1  # 累计重复数
                self.logger.debug(f"🔄 发现重复邮箱: {email}（原始: {self.emails[email_lower]}）")

    def _get_url_ip(self, url):
        """获取URL对应的IP"""
        try:
            parsed = urlparse(url)
            return socket.gethostbyname(parsed.netloc)
        except Exception as e:
            self.logger.warning(f"⚠️ 无法解析 {url} 的IP地址: {str(e)[:30]}")
            return "未知"

    def _update_status_stats(self, status):
        """更新状态统计"""
        if status in self.status_stats:
            self.status_stats[status] += 1
        else:
            self.status_stats["其他错误"] += 1

    def _save_pdf_urls(self):
        """保存检测到的PDF文件URL"""
        if not self.pdf_urls:
            return
            
        try:
            with open(self.pdf_file, 'w', encoding='utf-8') as f:
                f.write("=== 检测到的PDF文件URL ===\n")
                for url in sorted(self.pdf_urls):
                    f.write(f"{url}\n")
            
            self.logger.info(f"📋 已保存 {len(self.pdf_urls)} 个PDF文件URL到 {self.pdf_file}")
        except IOError as e:
            self.logger.error(f"❌ 保存PDF URL失败: {str(e)}")

    def crawl(self):
        """主爬取逻辑，使用自定义超时时间"""
        self.logger.info("="*50)
        self.logger.info(f"🚀 开始爬取目标: {self.base_domain}")
        self.logger.info(f"🎯 起始URL: {self.start_url}")
        self.logger.info(f"⚙️  配置参数: 间隔={self.delay*1000:.0f}ms | 超时={self.timeout*1000:.0f}ms | 最大深度={self.max_depth} | 最大页面={self.max_pages}")
        self.logger.info(f"🌐 跨域爬取: {'启用' if self.allow_cross_domain else '禁用'}")
        self.logger.info(f"📄 过滤设置: 自动跳过PDF文件及其他媒体文件")
        self.logger.info(f"✉️  邮箱处理: 自动去重（大小写不同视为相同邮箱）")
        self.logger.info(f"🍪 Cookie设置: 每爬取{self.save_cookies_frequency}页保存一次 | 模式={self.cookie_mode}")
        self.logger.info(f"🔧 框架处理: {'启用' if self.handle_frames else '禁用'} | 动态内容处理: {'启用' if self.handle_dynamic_content else '禁用'}")
        self.logger.info(f"🍪 初始Cookie数量: {len(session.cookies)}个")
        if self.cookie_file:
            self.logger.info(f"📂 使用初始Cookie文件: {self.cookie_file}")
        self.logger.info(f"📄 结果将保存到: {self.output_file}")
        self.logger.info("="*50)

        loop_counter = 0  # 用于控制调试信息输出频率
        while self.queue and self.crawled_count < self.max_pages:
            # 每10次循环输出一次队列状态
            loop_counter += 1
            if loop_counter % 10 == 0:
                self.logger.debug(
                    f"📊 队列状态: 待处理={len(self.queue)} | "
                    f"已访问={len(self.visited_urls)} | "
                    f"已爬取={self.crawled_count}/{self.max_pages} | "
                    f"链接统计: 提取={self.link_stats['extracted']} | "
                    f"新增={self.link_stats['added']} | "
                    f"重复={self.link_stats['duplicates']} | "
                    f"过滤={self.link_stats['filtered']} | "
                    f"PDF过滤={self.link_stats['pdf']} | "
                    f"邮箱统计: 发现={self.email_stats['found']} | 唯一={self.email_stats['unique']} | 重复={self.email_stats['duplicates']}"
                )
            
            # 队列过大时发出警告
            if len(self.queue) > self.link_queue_warning_threshold:
                self.logger.warning(f"⚠️ 队列过大 ({len(self.queue)} 个链接)，可能影响性能")

            current_url, current_depth = self.queue.pop(0)
            
            # 检查当前URL是否为PDF文件
            if current_url.lower().endswith('.pdf'):
                self.logger.debug(f"跳过PDF文件爬取: {current_url}")
                self.pdf_urls.add(current_url)
                self.link_stats["pdf"] += 1
                continue
                
            if current_depth > self.max_depth:
                self.logger.debug(f"📉 跳过超深度页面（{current_depth} > {self.max_depth}）: {current_url}")
                continue
            
            if current_url in self.visited_urls:
                self.logger.debug(f"🔄 跳过已访问页面: {current_url}")
                continue
            
            self.depth_stats[current_depth] = self.depth_stats.get(current_depth, 0) + 1
            
            self.visited_urls.add(current_url)
            self.crawled_count += 1
            url_ip = self._get_url_ip(current_url)
            status = "未知"
            response_time = 0

            try:
                start_time = time.time()
                
                # 使用自定义超时时间
                response = session.get(
                    current_url,
                    timeout=self.timeout,  # 关键修改：使用自定义超时
                    allow_redirects=True,
                    verify=False
                )
                
                # 检查响应是否为PDF文件
                content_type = response.headers.get('Content-Type', '').lower()
                if 'application/pdf' in content_type:
                    self.logger.warning(f"检测到PDF内容，跳过处理: {current_url}")
                    self.pdf_urls.add(current_url)
                    self.link_stats["pdf"] += 1
                    continue
                
                response_time = time.time() - start_time
                self.speed_stats.append(response_time)
                
                status = str(response.status_code)
                self._update_status_stats(status)
                
                cookie_count = len(session.cookies)
                self.logger.info(
                    f"📄 爬取 [{self.crawled_count}/{self.max_pages}]: {current_url} "
                    f"(IP: {url_ip}, 深度: {current_depth}, 状态: {status}, Cookie: {cookie_count}个, 耗时: {response_time:.2f}秒)"
                )
                self.logger.debug(
                    f"💨 响应速度: {response_time:.3f}秒 | 内容大小: {len(response.text)/1024:.1f}KB"
                )

                page_source = response.text
                frame_content = self._process_frames(current_url, page_source, current_depth)
                full_content = page_source + "\n\n" + frame_content
                
                is_blocked, block_type = self._is_blocked_page(full_content, current_url)
                if is_blocked:
                    self.blocked_urls[block_type].add(current_url)
                    self._update_status_stats(f"被{block_type}拦截")
                    self.logger.info(f"⏱️ 跳过{block_type}页面: {current_url}")
                else:
                    self._extract_links(current_url, full_content, current_depth)
                    self._extract_emails(full_content)
                
                # 按频率保存Cookie
                if self.crawled_count % self.save_cookies_frequency == 0:
                    self._save_current_cookies(current_url)

            except requests.exceptions.Timeout:
                status = "超时"
                self._update_status_stats("超时")
                self.logger.error(f"⏱️  爬取超时 [{self.crawled_count}]: {current_url}（IP: {url_ip}，超时阈值: {self.timeout}秒）")
            except requests.exceptions.SSLError:
                status = "SSL错误"
                self._update_status_stats("其他错误")
                self.logger.error(f"🔒 SSL证书错误 [{self.crawled_count}]: {current_url}")
            except requests.exceptions.HTTPError as e:
                status = str(e.response.status_code) if e.response else "HTTP错误"
                self._update_status_stats(status)
                self.logger.error(f"❌ HTTP错误 [{self.crawled_count}]: {str(e)[:50]}")
            except requests.exceptions.RequestException as e:
                status = "其他错误"
                self._update_status_stats("其他错误")
                self.logger.error(f"❌ 请求异常 [{self.crawled_count}]: {str(e)[:50]}")
            except Exception as e:
                # 捕获所有其他未处理的异常
                status = "致命错误"
                self._update_status_stats("其他错误")
                self.logger.error(f"💥 处理页面时发生致命错误 [{self.crawled_count}]: {str(e)}", exc_info=True)

            if self.queue:
                self.logger.debug(f"⌛ 等待 {self.delay*1000:.0f}ms 后继续...")
                time.sleep(self.delay)

        # 爬取结束时保存最终的Cookie状态
        self._save_current_cookies(self.start_url)
        
        # 保存检测到的PDF文件URL
        self._save_pdf_urls()
        
        # 输出停止原因
        if not self.queue and self.crawled_count < self.max_pages:
            self.logger.info(f"🛑 爬虫停止：队列已空（已爬取 {self.crawled_count} 页，未达到最大页面数 {self.max_pages}）")
        elif self.crawled_count >= self.max_pages:
            self.logger.info(f"🛑 爬虫停止：已达到最大页面数 {self.max_pages}")

        # 保存结果
        if self.emails:
            self._save_results()
        else:
            self.logger.info("ℹ️ 未发现任何邮箱")
            
        self._save_blocked_urls()
        self._print_summary()

    def _save_results(self):
        """保存邮箱结果，确保每个邮箱只出现一次（忽略大小写）"""
        try:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                # 写入统计信息作为注释
                f.write(f"# 邮箱提取结果 - 共发现{self.email_stats['found']}个，去重后{self.email_stats['unique']}个\n")
                f.write(f"# 去重规则：大小写不同视为相同邮箱\n")
                f.write(f"# 爬取参数：超时时间={self.timeout*1000:.0f}ms | 爬取深度={self.max_depth}\n")
                f.write(f"# 生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# 来源URL：{self.start_url}\n")
                f.write("\n")
                
                # 写入去重后的邮箱（使用原始大小写）
                for email in self.emails.values():
                    f.write(f"{email}\n")
            
            self.logger.info(f"💾 已保存 {len(self.emails)} 个唯一邮箱到 {self.output_file}（总发现数: {self.email_stats['found']}，去重{self.email_stats['duplicates']}个）")
        except IOError as e:
            self.logger.error(f"❌ 保存文件失败: {str(e)}")

    def _save_blocked_urls(self):
        """保存被拦截的URL"""
        if not any(self.blocked_urls.values()):
            return
            
        try:
            with open(self.blocked_file, 'w', encoding='utf-8') as f:
                f.write("=== 需要登录的URL ===\n")
                for url in sorted(self.blocked_urls["login"]):
                    f.write(f"{url}\n")
                
                f.write("\n=== 包含验证码的URL ===\n")
                for url in sorted(self.blocked_urls["captcha"]):
                    f.write(f"{url}\n")
            
            self.logger.info(f"📋 已保存 {len(self.blocked_urls['login'])+len(self.blocked_urls['captcha'])} 个被拦截URL")
        except IOError as e:
            self.logger.error(f"❌ 保存拦截URL失败: {str(e)}")

    def _print_summary(self):
        """打印爬取总结，包含超时统计"""
        self.logger.info("\n" + "="*50)
        self.logger.info("📊 爬取总结")
        self.logger.info(f"总爬取页面: {self.crawled_count}")
        self.logger.info(f"邮箱统计: 共发现 {self.email_stats['found']} 个 | 去重后 {self.email_stats['unique']} 个 | 过滤重复 {self.email_stats['duplicates']} 个")
        self.logger.info(f"连接统计: 成功 {sum(v for k, v in self.status_stats.items() if k not in ['超时', '其他错误', '被login拦截', '被captcha拦截'])} 次 | 超时 {self.status_stats['超时']} 次 | 其他错误 {self.status_stats['其他错误']} 次")
        self.logger.info(f"框架统计: 发现 {self.frame_stats['found']} 个 | 处理 {self.frame_stats['processed']} 个 | 超时 {self.frame_stats['超时']} 个 | 失败 {self.frame_stats['failed']} 个")
        self.logger.info(f"检测到并跳过的PDF文件: {len(self.pdf_urls)} 个")
        self.logger.info(f"被拦截页面: 登录页面 {len(self.blocked_urls['login'])} 个 | 验证码页面 {len(self.blocked_urls['captcha'])} 个")
        
        # Cookie保存统计
        self.logger.info(f"Cookie保存: 共保存 {len(self.saved_cookie_files)} 个文件到 cookie 文件夹")
        if self.saved_cookie_files:
            self.logger.info(f"最新Cookie文件: {self.saved_cookie_files[-1]}")
        
        # 链接统计，增加PDF过滤统计
        self.logger.info(f"链接统计: 提取 {self.link_stats['extracted']} 个 | 新增 {self.link_stats['added']} 个 | 重复 {self.link_stats['duplicates']} 个 | 过滤 {self.link_stats['filtered']} 个 | PDF过滤 {self.link_stats['pdf']} 个")
        
        if self.handle_frames:
            self.logger.info(f"框架处理统计: 发现 {self.frame_stats['found']} 个 | 处理 {self.frame_stats['processed']} 个 | 失败 {self.frame_stats['failed']} 个")
        
        self.logger.info(f"最终Cookie数量: {len(session.cookies)} 个")
        
        if self.speed_stats:
            avg_speed = sum(self.speed_stats) / len(self.speed_stats)
            self.logger.info(f"平均响应时间: {avg_speed:.3f}秒 | 使用的超时阈值: {self.timeout}秒")
        
        self.logger.info("状态分布:")
        for status, count in self.status_stats.items():
            self.logger.info(f"  {status}: {count}次")
        
        self.logger.info("深度分布:")
        for depth, count in sorted(self.depth_stats.items()):
            self.logger.info(f"  深度 {depth}: {count}页")
            
        self.logger.info("="*50)

def main():
    parser = argparse.ArgumentParser(
        description='通用网络爬虫工具 - 支持自定义超时时间，自动去重邮箱并过滤PDF文件',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # 必选参数
    parser.add_argument('url', help='目标URL（支持带GET参数，如：https://example.com/list?id=1&page=2）')
    
    # 可选参数
    parser.add_argument('-d', '--delay', type=int, default=2000, 
                        help='爬取间隔(毫秒)，默认2000ms')
    parser.add_argument('-m', '--max-depth', type=int, default=3, 
                        help='最大爬取深度，默认3层')
    parser.add_argument('-p', '--max-pages', type=int, default=50, 
                        help='最大爬取页面数，默认50页')
    parser.add_argument('-v', '--verbose', action='store_true', 
                        help='显示详细日志')
    parser.add_argument('--ignore-ssl', action='store_true', 
                        help='忽略SSL证书验证')
    parser.add_argument('--cookie', 
                        help='初始Cookie文件路径')
    parser.add_argument('--cookie-mode', 
                        choices=['all', 'login-only', 'browsing-only'], 
                        default='all', 
                        help='Cookie处理模式（默认all）')
    parser.add_argument('--cookie-frequency', type=int, default=10, 
                        help='Cookie保存频率（每爬取多少页保存一次），默认10页')
    parser.add_argument('--no-frames', action='store_false', dest='handle_frames',
                        help='禁用框架(iframe/frame)处理')
    parser.add_argument('--no-dynamic', action='store_false', dest='handle_dynamic_content',
                        help='禁用动态内容提取')
    parser.add_argument('--cross-domain', action='store_true', dest='allow_cross_domain',
                        help='允许跨域爬取（默认禁用）')
    # 新增超时参数
    parser.add_argument('-t', '--timeout', type=int, default=2000, 
                        help='超时时间(毫秒)，默认2000ms（2秒），例如 -t 3000 表示3秒')
    
    args = parser.parse_args()
    
    # 初始化日志
    logger = setup_logger(args.verbose)
    
    # 检查必要的库
    try:
        import bs4
    except ImportError:
        logger.error("❌ 缺少必要的库 'beautifulsoup4'，请先安装: pip install beautifulsoup4")
        return
    
    if not has_colorlog:
        logger.warning("⚠️ 未安装colorlog，无法显示彩色日志。可运行 'pip install colorlog' 安装。")
    
    try:
        crawler = GeneralCrawler(
            target_url=args.url,
            delay_ms=args.delay,
            max_depth=args.max_depth,
            max_pages=args.max_pages,
            ignore_ssl=args.ignore_ssl,
            cookie_file=args.cookie,
            cookie_mode=args.cookie_mode,
            save_cookies_frequency=args.cookie_frequency,
            logger=logger,
            allow_cross_domain=args.allow_cross_domain,
            timeout_ms=args.timeout  # 传递超时参数
        )
        crawler.handle_frames = args.handle_frames
        crawler.handle_dynamic_content = args.handle_dynamic_content
        crawler.crawl()
    except KeyboardInterrupt:
        logger.info("\n⚠️ 用户中断，保存数据中...")
        if hasattr(crawler, 'emails') and crawler.emails:
            crawler._save_results()
        if hasattr(crawler, '_save_blocked_urls'):
            crawler._save_blocked_urls()
        if hasattr(crawler, '_save_pdf_urls'):
            crawler._save_pdf_urls()  # 中断时保存PDF URL
        # 中断时保存当前Cookie
        if hasattr(crawler, '_save_current_cookies'):
            crawler._save_current_cookies(crawler.start_url)
        if hasattr(crawler, '_print_summary'):
            crawler._print_summary()
    except Exception as e:
        logger.error(f"❌ 爬虫启动失败: {str(e)}", exc_info=True)

if __name__ == "__main__":
    main()
    
