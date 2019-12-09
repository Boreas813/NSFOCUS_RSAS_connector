import datetime
import re
import sys
from sys import exit
import time
import ipaddress
import configparser
import optparse
import json

import requests
requests.packages.urllib3.disable_warnings()


from bs4 import BeautifulSoup
from colorama import Fore, Back, Style, init, deinit, reinit

# 初始化彩色cmd
init()

def windows_client(system = sys.platform):
    if system.startswith('win'):
        return True
    else:
        return False

def print_yellow(string):
    if windows_client(): reinit()
    print (Fore.YELLOW + Style.BRIGHT + string + Style.RESET_ALL)
    if windows_client(): deinit()

def print_blue(string):
    if windows_client(): reinit()
    print (Fore.BLUE + Style.BRIGHT + string + Style.RESET_ALL)
    if windows_client(): deinit()

def print_cyan(string):
    if windows_client(): reinit()
    print (Fore.CYAN + Style.BRIGHT + string + Style.RESET_ALL)
    if windows_client(): deinit()

def print_green(string):
    if windows_client(): reinit()
    print (Fore.GREEN + Style.BRIGHT + string + Style.RESET_ALL)
    if windows_client(): deinit()

def print_red(string):
    if windows_client(): reinit()
    print (Fore.RED + Style.BRIGHT + string + Style.RESET_ALL)
    if windows_client(): deinit()

def st_print(text):
    if text.startswith('[+]'):
        text = '{}'.format(text)
        print_green(text)
    elif text.startswith('[*]'):
        text = '{}'.format(text)
        print_yellow(text)
    elif text.startswith('==='):
        text = '{}'.format(text)
        print_cyan(text)
    elif text.startswith('[-]') or text.startswith('[!]') or text.startswith('ERROR'):
        text = '{}'.format(text)
        print_red(text)
    else:
        text = f'{text}'
        print(text)

def start_host_and_password_scan(username, password, scanner_url, task_name, corn_pattern=None):

    USERNAME = username

    PASSWORD = password

    SCANNER_URL = scanner_url if not scanner_url.endswith('/') else scanner_url[0:-1]

    SCANNER_ADDRESS = re.search(r'https://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', SCANNER_URL).group(1)


    st_print('[+] 正在读取IP地址列表...')
    with open('ip.txt', 'r') as ip_file:
        ip_range = ip_file.read()



    st_print('[+] 正在进行IP去重...')
    ip_list = ip_range.split('\n')

    while True:
        try:
            ip_list.remove('')
        except ValueError:
            break

    ip_list_len = len(ip_list)
    new_ip_list = list(set(ip_list))

    if len(new_ip_list) < ip_list_len:
        ip_range = ''
        for ip in new_ip_list:
            ip_range += f'{ip}\n'
        ip_range = ip_range[0:-1]
        st_print('[*] 检测到重复ip，已经进行去重...')



    st_print('[+] 正在登陆扫描器...')
    # 生成用于登录页面的初始请求头
    s = requests.Session()
    s.headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
        'Accept-Encoding':'gzip, deflate, br',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Cache-Control': 'max-age=0',
        'Connection': 'keep-alive',
        'Host': f'{SCANNER_ADDRESS}',
        'Referer': f'{SCANNER_URL}',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.97 Safari/537.36'
    }
    # 访问登陆页面
    r = s.get(f'{SCANNER_URL}/accounts/login/?next=/', verify=False)
    login_soup = BeautifulSoup(r.content, 'html5lib')
    csrfmiddlewaretoken = login_soup.find_all('input')[3]['value']
    # 提交登录请求
    r = s.post(f'{SCANNER_URL}/accounts/login_view/',
           data={'username':USERNAME, 'password':PASSWORD, 'csrfmiddlewaretoken':csrfmiddlewaretoken},
           verify=False)
    # 打印主页信息
    r = s.get(f'{SCANNER_URL}/task/task_entry/', verify=False)

    index_soup = BeautifulSoup(r.content, 'html5lib')

    if '口令猜测任务' in index_soup.text:
        st_print('[+] 扫描器登录成功！')
    else:
        st_print('[!] 扫描器登录失败！')
        exit(0)

    st_print('[+] 正在获取csrfmiddlewaretoken...')
    all_js = index_soup.find_all('script')
    for i in all_js:
        csrfmiddlewaretoken = re.search(r'csrfmiddlewaretoken":\'(.+)\'', str(i)).group(1) if re.search(r'csrfmiddlewaretoken":\'(.+)\'', str(i)) else None
        if csrfmiddlewaretoken:
            st_print('[+] 获取csfrmiddlewaretoken成功，正在重构请求头并发送payload...')
            break
    else:
        st_print('[!] 获取csrfmiddlewaretoken失败！')
        exit(0)
    host_and_password_scan_payload = {
        'csrfmiddlewaretoken': csrfmiddlewaretoken,
        'vul_or_pwd': 'vul',
        'config_task': 'taskname',
        'task_config': '',
        'diff': 'write something',
        'target': 'ip',
        'ipList': ip_range,
        'domainList': '',
        'name': task_name,
        'exec': 'immediate',
        'exec_timing_date':str(datetime.datetime.now())[0:-7],
        'exec_everyday_time': '00:00',
        'exec_everyweek_day': '1',
        'exec_everyweek_time': '00:00',
        'exec_emonthdate_day': '1',
        'exec_emonthdate_time': '00:00',
        'exec_emonthweek_pre': '1',
        'exec_emonthweek_day': '1',
        'exec_emonthweek_time': '00:00',
        'tpl': '0',
        'login_check_type': 'login_check_type_vul',
        'bvs_check_type': 'bvs_check_type_standard',
        'isguesspwd': 'yes',
        'exec_range': '' if corn_pattern is None else corn_pattern,  # 该行代码控制扫描时间段
        'scan_pri': '2',
        'taskdesc': '',
        'report_type_html': 'html',
        'report_type_xls': 'xls',
        'report_content_sum': 'sum',
        'report_content_host': 'host',
        'report_tpl_sum': '1',
        'report_tpl_host': '101',
        'report_ifcreate': 'yes',
        'report_ifsent_type': 'html',
        'report_ifsent_email': '',
        'port_strategy': 'user',
        'port_strategy_userports': '1-65535',
        'port_speed': '3',
        'port_tcp': 'T',
        'sping_delay': '1',
        'scan_level': '3',
        'timeout_plugins': '40',
        'timeout_read': '5',
        'alert_msg': '远程安全评估系统将对您的主机进行安全评估。',
        'scan_oracle': 'yes',
        'encoding': 'UTF-8',
        'bvs_task': 'no',

        'pwd_smb': 'yes',
        'pwd_type_smb': 'c',
        'pwd_user_smb': 'smb_user.default',
        'pwd_pass_smb': 'smb_pass.default',
        'pwd_userpass_smb': 'smb_userpass.default',

        'pwd_rdp': 'yes',
        'pwd_type_rdp': 'c',
        'pwd_user_rdp': 'rdp_user.default',
        'pwd_pass_rdp': 'rdp_pass.default',
        'pwd_userpass_rdp': 'rdp_userpass.default',

        'pwd_telnet': 'yes',
        'pwd_type_telnet': 'c',
        'pwd_user_telnet': 'telnet_user.default',
        'pwd_pass_telnet': 'telnet_pass.default',
        'pwd_userpass_telnet': 'telnet_userpass.default',

        'pwd_ftp': 'yes',
        'pwd_type_ftp': 'c',
        'pwd_user_ftp': 'ftp_user.default',
        'pwd_pass_ftp': 'ftp_pass.default',
        'pwd_userpass_ftp': 'ftp_userpass.default',

        'pwd_ssh': 'yes',
        'pwd_type_ssh': 'c',
        'pwd_user_ssh': 'ssh_user.default',
        'pwd_pass_ssh': 'ssh_pass.default',
        'pwd_userpass_ssh': 'ssh_userpass.default',

        'pwd_tomcat': 'yes',
        'pwd_type_tomcat': 'c',
        'pwd_user_tomcat': 'tomcat_user.default',
        'pwd_pass_tomcat': 'tomcat_pass.default',
        'pwd_userpass_tomcat': 'tomcat_userpass.default',

        'pwd_mssql': 'yes',
        'pwd_type_mssql': 'c',
        'pwd_user_mssql': 'mssql_user.default',
        'pwd_pass_mssql': 'mssql_pass.default',
        'pwd_userpass_mssql': 'mssql_userpass.default',

        'pwd_mysql': 'yes',
        'pwd_type_mysql': 'c',
        'pwd_user_mysql': 'mysql_user.default',
        'pwd_pass_mysql': 'mysql_pass.default',
        'pwd_userpass_mysql': 'mysql_userpass.default',

        'pwd_oracle': 'yes',
        'pwd_type_oracle': 'c',
        'pwd_user_oracle': 'oracle_user.default',
        'pwd_pass_oracle': 'oracle_pass.default',
        'pwd_userpass_oracle': 'oracle_userpass.default',

        'pwd_sybase': 'yes',
        'pwd_type_sybase': 'c',
        'pwd_user_sybase': 'sybase_user.default',
        'pwd_pass_sybase': 'sybase_pass.default',
        'pwd_userpass_sybase': 'sybase_userpass.default',

        'pwd_db2': 'yes',
        'pwd_type_db2': 'c',
        'pwd_user_db2': 'db2_user.default',
        'pwd_pass_db2': 'db2_pass.default',
        'pwd_userpass_db2': 'db2_userpass.default',

        'pwd_mongodb': 'yes',
        'pwd_type_mongodb': 'c',
        'pwd_user_mongodb': 'mongodb_user.default',
        'pwd_pass_mongodb': 'mongodb_pass.default',
        'pwd_userpass_mongodb': 'db2_userpass.default',

        'pwd_snmp': 'yes',
        'pwd_pass_snmp': 'snmp_pass.default',

        'pwd_timeout': '5',
        'pwd_timeout_time': '120',
        'pwd_interval': '0',
        'pwd_num': '0',
        'pwd_threadnum': '5',
        'loginarray': '[{"ip_range": "%s", "admin_id": "", "protocol": "", "port": "", "os": "", "user_name": "", "user_pwd": "", "ostpls": [], "apptpls": [], "dbtpls": [], "virttpls": [], "bdstpls": [], "devtpls": [], "statustpls": "", "tpl_industry": "", "tpllist": [], "tpllistlen": 0, "jhosts": [], "tpltype": "", "protect": "", "protect_level": "", "jump_ifuse": "", "host_ifsave": "", "oracle_ifuse": "", "ora_username": "", "ora_userpwd": "", "ora_port": "", "ora_usersid": "", "weblogic_ifuse": "", "weblogic_system": "", "weblogic_version": "", "weblogic_user": "", "weblogic_path": "", "web_login_wblgc_ifuse": "", "web_login_wblgc_user": "", "web_login_wblgc_pwd": "", "web_login_wblgc_path": ""}, {"ip_range": "210.212.145.105", "admin_id": "", "protocol": "", "port": "", "os": "", "user_name": "", "user_pwd": "", "ostpls": [], "apptpls": [], "dbtpls": [], "virttpls": [], "bdstpls": [], "devtpls": [], "statustpls": "", "tpl_industry": "", "tpllist": [], "tpllistlen": 0, "jhosts": [], "tpltype": "", "protect": "", "protect_level": "", "jump_ifuse": "", "host_ifsave": "", "oracle_ifuse": "", "ora_username": "", "ora_userpwd": "", "ora_port": "", "ora_usersid": "", "weblogic_ifuse": "", "weblogic_system": "", "weblogic_version": "", "weblogic_user": "", "weblogic_path": "", "web_login_wblgc_ifuse": "", "web_login_wblgc_user": "", "web_login_wblgc_pwd": "", "web_login_wblgc_path": ""}]' % ip_range.split('\n')[0]
    }

    # 更新请求头用于新建信息
    s.headers['Accept'] = '*/*'
    s.headers['Content-Type'] = 'application/x-www-form-urlencoded'
    s.headers['Origin'] = f'{SCANNER_URL}'
    s.headers['Referer'] = f'{SCANNER_URL}/task/index/1'
    s.headers['Sec-Fetch-Mode'] = 'cors'
    s.headers['X-Requested-With'] = 'XMLHttpRequest'
    s.cookies['left_menustatue_NSFOCUSRSAS'] = f"0|0|{SCANNER_URL}/task/task_entry/"
    del (s.headers['Sec-Fetch-User'])
    del (s.headers['Cache-Control'])

    r = s.post(f'{SCANNER_URL}/task/vul/tasksubmit', data=host_and_password_scan_payload, verify=False)

    if 'suc' in r.text:
        st_print(f'[+] 新建扫描任务成功，任务编号：{r.text.split(":")[2]}')
    else:
        st_print(f'[!] 新建任务失败，报错信息为：{json.loads(r.text[1:-1])}')


def start_web_scan(username, password, scanner_url, task_name, corn_pattern=None):
    USERNAME = username

    PASSWORD = password

    SCANNER_URL = scanner_url if not scanner_url.endswith('/') else scanner_url[0:-1]

    SCANNER_ADDRESS = re.search(r'https://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', SCANNER_URL).group(1)

    st_print('[+] 正在读取url列表...')
    with open('url.txt', 'r') as url_file:
        url_range = url_file.read()

    url_list = url_range.split('\n')
    while True:
        try:
            url_list.remove('')
        except ValueError:
            break

    st_print('[+] 正在进行url去重...')
    url_list_len = len(url_list)
    new_url_list = list(set(url_list))

    if len(new_url_list) < url_list_len:
        url_list = new_url_list
        st_print('[*] 检测到重复url，已经进行去重...')

    # 最大上限15个url，需要进行地址拆分
    if len(url_list) > 15:
        st_print(f'[*] url大于15个，正在拆分任务...')
        part = 1
        url_count = 0
        task_target = ''
        for url in url_list:
            if task_target == '':
                task_target += url.strip()
            else:
                task_target += f'\n{url.strip()}'
            url_count += 1
            if url_count == 15:
                send_a_web_scan_mission(SCANNER_ADDRESS, SCANNER_URL, USERNAME, PASSWORD, url_count, task_target, task_name, part, url, corn_pattern)
                url_count = 0
                task_target = ''
                part += 1

        if url_count != 0:
            url_count = 0
            send_a_web_scan_mission(SCANNER_ADDRESS, SCANNER_URL, USERNAME, PASSWORD, url_count, task_target, task_name,part, url, corn_pattern)
    else:
        send_a_web_scan_mission(SCANNER_ADDRESS, SCANNER_URL, USERNAME, PASSWORD, str(len(url_list)), url_range, task_name,'1', url_list[0], corn_pattern)


def send_a_web_scan_mission(SCANNER_ADDRESS, SCANNER_URL, USERNAME, PASSWORD, url_count, task_target, task_name, part, url, corn_pattern):
    # 生成用于登录页面的初始请求头
    s = requests.Session()
    s.headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'keep-alive',
        'Cache-Control': 'max-age=0',
        'Host': f'{SCANNER_ADDRESS}',
        'Referer': f'{SCANNER_URL}',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.97 Safari/537.36'
    }
    # 访问登陆页面
    r = s.get(f'{SCANNER_URL}/accounts/login/?next=/', verify=False)
    login_soup = BeautifulSoup(r.content, 'html5lib')
    csrfmiddlewaretoken = login_soup.find_all('input')[3]['value']
    # 提交登录请求
    r = s.post(f'{SCANNER_URL}/accounts/login_view/',
               data={'username': USERNAME, 'password': PASSWORD, 'csrfmiddlewaretoken': csrfmiddlewaretoken},
               verify=False)

    r = s.get(f'{SCANNER_URL}/task/index/8', verify=False)
    index_soup = BeautifulSoup(r.content, 'html5lib')
    all_js = index_soup.find_all('script')
    st_print('[+] 正在获取csrfmiddlewaretoken...')
    for i in all_js:
        csrfmiddlewaretoken = re.search(r'csrfmiddlewaretoken":\'(.+)\'', str(i)).group(1) if re.search(
            r'csrfmiddlewaretoken":\'(.+)\'', str(i)) else None
        if csrfmiddlewaretoken:
            st_print(f'[+] 获取csrfmiddlewaretoken成功，正在下发第{part}批次任务...')
            st_print(f'''===扫描参数===
{task_target}
''')
            break
    else:
        st_print('[!] 未能定位csrfmiddlewaretoken，新建web扫描任务失败！')
        exit(0)
    # 制作payload
    web_scan_payload = {
        'csrfmiddlewaretoken': csrfmiddlewaretoken,
        'target_count': str(url_count),
        'config_task': 'taskname',
        'task_config': '',
        'task_target': task_target,
        'task_name': task_name + f' 拆分{part}',
        'scan_method': '1',
        'subdomains_scan': '0',
        'exec': 'immediate',
        'exec_timing_date': '2019-11-27 16:47:27',
        'exec_everyday_time': '00:00',
        'exec_everyweek_day': '1',
        'exec_everyweek_time': '00:00',
        'exec_emonthdate_day': '1',
        'exec_emonthdate_time': '00:00',
        'exec_emonthweek_pre': '1',
        'exec_emonthweek_day': '1',
        'exec_emonthweek_time': '00:00',
        'tpl': '0',
        'ws_proxy_type': 'HTTP',
        'ws_proxy_auth': 'Basic',
        'ws_proxy_server': '',
        'ws_proxy_port': '',
        'ws_proxy_username': '',
        'ws_proxy_password': '',
        'cron_range': '' if corn_pattern is None else corn_pattern,   # 该参数控制扫描时间段
        'dispatchLevel': '2',
        'target_description': '',
        'report_type_html': 'html',
        'report_type_xls': 'xls',
        'summarizeReport': 'yes',
        'oneSiteReport': 'yes',
        'sum_report_tpl': '201',
        'site_report_tpl': '301',
        'auto_export': 'yes',
        'sendReport_type': 'html',
        'email_address': '',
        'plugin_threads': '100',
        'webscan_timeout': '30',
        'page_encoding': '0',
        'coding': 'UTF8',
        'login_ifuse': 'yes',
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.97 Safari/537.36',
        'dir_level': '1',
        'dir_limit': '3',
        'filetype_to_check_backup': 'shtml,php,jsp,asp,aspx',
        'backup_filetype': 'bak,old',
        'scan_type': '0',
        'dir_files_limit': '-1',
        'dir_depth_limit': '15',
        'scan_link_limit': '-1',
        'case_sensitive': '1',
        'if_javascript': '1',
        'if_repeat': '2',
        'protocalarray': '[{"target": "%s", "protocal_type": "auto", "protocal_name": "", "protocal_pwd": "", "login_scan_type": "no", "cookies": "", "cookie_type": "set_cookie", "black_links": "", "wihte_links": "", "form_switch": "yes", "form_cont": "no", "form_str": ""}]' % url,
    }
    # 更新请求头用于新建信息
    s.headers['Accept'] = '*/*'
    s.headers['Content-Type'] = 'application/x-www-form-urlencoded'
    s.headers['Origin'] = f'{SCANNER_URL}'
    s.headers['Referer'] = f'{SCANNER_URL}/task/index/8'
    s.headers['Sec-Fetch-Mode'] = 'cors'
    s.headers['X-Requested-With'] = 'XMLHttpRequest'
    s.cookies['left_menustatue_NSFOCUSRSAS'] = f"0|0|{SCANNER_URL}/task/task_entry/"
    del (s.headers['Sec-Fetch-User'])
    del (s.headers['Cache-Control'])

    r = s.post(f'{SCANNER_URL}/task/vul/web_newtask/', data=web_scan_payload, verify=False)
    if 'suc' in r.text:
        st_print(f'[+] 第{part}批次web扫描任务创建成功，任务编号：{r.text.split(":")[2]}')
    else:
        st_print(f'[!] 新建web扫描任务失败，报错信息为：{json.loads(r.text[1:-1])}')
        exit(0)

if __name__ == '__main__':
    parser = optparse.OptionParser(
    '''===使用方法===
    1. 打开目录下的config.ini，将用户名，密码，扫描器地址（带协议的完整URL，如：https://1.1.1.1）分别填好
    2. 如果使用主机+弱口令扫描，打开目录下ip.txt将要扫描的IP放进去；如果使用web扫描，打开目录下url.txt将要扫描的url放进去
    3. 主机扫描不会自动拆分IP建立任务，单次最大IP数量为65535个；web扫描会将全部URL拆分成若干任务，每个任务会有后缀<拆分xx>
    4. -n <任务名称>
    5. -m <扫描模式 参数为1时是主机+弱口令扫描 参数为2时是web扫描>
    6. -c <定时执行，选填参数>

    实例：lvmeng_connector.exe -n "测试任务 2333" -m 1
         lvmeng_connector.exe -n "测试任务 2333" -m 2 -c "08:00-12:00"
    '''
    )
    parser.add_option('-n', dest='name', type='string', help='指定任务名')
    parser.add_option('-m', dest='mode', type='string', help='指定扫描模式')
    parser.add_option('-c', dest='corn', type='string', help='指定定时任务参数')
    (options, args) = parser.parse_args()
    mission_name = options.name
    mode = options.mode
    corn_pattern = options.corn
    if (mission_name is None) | (mode is None):
        st_print(parser.usage)
        exit(0)
    st_print(f'[+] 正在读取参数...')
    config = configparser.ConfigParser()
    config.read('config.ini')
    try:
        username = config['USERCONFIG']['User']
        password = config['USERCONFIG']['Password']
        scanner_url = config['USERCONFIG']['ScannerAddress']
    except KeyError as e:
        st_print(f'[!] 配置错误，请检查config.ini配置文件内容，{e}项没有找到')
        exit(0)

    if (username=='') | (password=='') | (scanner_url==''):
        st_print(f'[!] 配置错误，请检查config.ini配置文件内容，有配置项内容为空值')
        exit(0)

    time.sleep(0.5)
    st_print(f'[+] 参数读取成功，用户名：{username} 扫描器地址：{scanner_url}')

    if mode == '1':
        start_host_and_password_scan(username, password, scanner_url, mission_name, corn_pattern)
    elif mode == '2':
        start_web_scan(username, password, scanner_url, mission_name, corn_pattern)
    else:
        st_print('[!] 不正确的扫描模式，请重新输入-m参数')
        exit(0)
