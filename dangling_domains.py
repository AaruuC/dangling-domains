# pylint: disable=invalid-name,broad-except
'''Iterate through SOLIDserver A, MX, and CNAME records to detect if they are dangling'''
import warnings
import socket
from multiprocessing import Pool
from telnetlib import Telnet
import json
from dns import resolver
import urllib3
from bs4 import BeautifulSoup
import requests
import pandas as pd
import paramiko
from ddiinfo import getConfig
warnings.filterwarnings(action='ignore', module='.*paramiko.*')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

###########################################################################################
#
# EXCEPTION
#
###########################################################################################


class HTTPSException(Exception):
    '''Custom exception to catch Error 404'''

###########################################################################################
#
# GETTERS
#
###########################################################################################


def getARecords(urlBase, credHeaders):
    '''Given SOLIDserver base URL and credentials, fetch all A records'''
    preamble = 'dns_rr_list?WHERE=rr_type%20like%20'
    quote = '%27'
    query = 'A'

    loc = urlBase + preamble + quote + query + quote

    r = requests.get(loc, headers=credHeaders)
    if r.encoding is None:
        r.encoding = 'utf-8'

    try:
        j = r.json()
    except json.decoder.JSONDecodeError:
        return None
    except Exception:
        return None
    return j


def getMXRecords(urlBase, credHeaders):
    '''Given SOLIDserver base URL and credentials, fetch all MX records'''
    preamble = 'dns_rr_list?WHERE=rr_type%20like%20'
    quote = '%27'
    query = 'MX'
    loc = urlBase + preamble + quote + query + quote

    print(loc)

    r = requests.get(loc, headers=credHeaders)
    if r.encoding is None:
        r.encoding = 'utf-8'

    try:
        j = r.json()
    except json.decoder.JSONDecodeError:
        return None
    except Exception:
        return None
    return j


def getCNAMERecords(urlBase, credHeaders):
    '''Given SOLIDserver base URL and credentials, fetch all CNAME records'''
    preamble = 'dns_rr_list?WHERE=rr_type%20like%20'
    quote = '%27'
    query = 'CNAME'
    loc = urlBase + preamble + quote + query + quote

    print(loc)

    r = requests.get(loc, headers=credHeaders)
    if r.encoding is None:
        r.encoding = 'utf-8'

    try:
        j = r.json()
    except json.decoder.JSONDecodeError:
        return None
    except Exception:
        return None
    return j


def getIPAddress(domains):
    '''Given domain, call dig to find IP Address
    On failure, look for TXT records.
    On further failure, set as dangling'''
    ips = []
    failed = []
    txt = {}
    for domain in domains:
        try:
            ip = str(resolver.resolve(domain[1], 'A').rrset).split()[-1]
            ips.append((domain[0], domain[1], ip))
        except Exception:
            try:
                ip = str(resolver.resolve(domain[1], 'TXT').rrset)
                txt[domain[0]] = (domain[1], ip)
            except Exception:
                failed.append(('rdata does not resolve', domain[0], domain[1]))
    return ips, failed

###########################################################################################
#
# FILTERS/MAPS
#
###########################################################################################


def filterIPAddress(ip):
    '''Filtered Penn affliated IP Addresses'''
                # PennNet globally routable IPv4
    return not (ip.startswith('128.91.') or ip.startswith('130.91.') or ip.startswith('158.130.') or
                ip.startswith('165.123.') or ip.startswith('192.5.44.') or
                ip.startswith('192.84.2.') or
                # Non-globally routable IPv4 (RFC 1918)
                ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.10') or
                ip.startswith('172.11') or ip.startswith('172.12') or ip.startswith('172.13') or
                ip.startswith('172.14') or ip.startswith('172.15') or ip.startswith('172.16') or
                ip.startswith('172.2') or ip.startswith('172.30') or ip.startswith('172.31') or
                # Wharton SF / MAGPI (stable)
                ip.startswith('137.164.') or ip.startswith('216.27.96.0') or
                # Loopback
                ip.startswith('127.0.0.1') or
                # DNS
                ip.startswith('9.9.9.9') or ip.startswith('8.8.8.8') or ip.startswith('8.8.4.4') or
                ip.startswith('76.76.2.0') or ip.startswith('76.76.10.0') or
                ip.startswith('149.112.112.112') or ip.startswith('1.0.0.1') or
                ip.startswith('1.1.1.1') or ip.startswith('208.67.222.222') or
                ip.startswith('208.67.220.220') or ip.startswith('76.76.19.19') or
                ip.startswith('76.223.122.150')
                )


def filterUPennA(info):
    '''Given cname records, check for valid, non-Penn affliated domains'''
    ip = info['value1']
    domain = socket.getnameinfo((ip, 0), 0)
    return 'upenn.edu' not in domain


def filterUPennMX(info):
    '''Given cname records, check for valid, non-Penn affliated domains'''
    domain = info['value2']
    return 'upenn.edu' not in domain and domain != '.'


def filterUPennCNAME(info):
    '''Given cname records, check for valid, non-Penn affliated domains'''
    domain = info['value1']
    return 'upenn.edu' not in domain and 'in-addr.arpa' not in domain


def multiprocessA(record):
    '''Given a (rr_full_name, ip_address) pair, fetch the https page.
    On connection/read error or 404 response, fetch the http page.
    On further error, set up for attachment to dangling list'''
    session = requests.Session()
    rr_full_name = record[0]
    value1 = record[1]
    try:
        r = session.get(f'https://{rr_full_name}', headers={
                        'User-Agent': 'Mozilla/5.0'}, verify=False, timeout=(3.05, 10))
        if r.status_code == 404:
            raise HTTPSException('try http')
        soup = BeautifulSoup(r.text, 'html.parser')
        return ('HTTPS success', rr_full_name, value1, soup.get_text(), '', r.status_code, '')
    except (requests.exceptions.SSLError, requests.ReadTimeout, requests.ConnectionError,
            requests.ConnectTimeout, HTTPSException):
        try:
            r2 = session.get(f'http://{rr_full_name}', headers={
                             'User-Agent': 'Mozilla/5.0'}, verify=False, timeout=(3.05, 10))
            soup2 = BeautifulSoup(r2.text, 'html.parser')
            return ('HTTP success', rr_full_name, value1, '', soup2.get_text(), '', r2.status_code)
        except Exception as e:
            return (type(e).__name__, rr_full_name, value1)
    except Exception as e:
        return (type(e).__name__, rr_full_name, value1)


def multiprocessCNAME(record):
    '''Given a (rr_full_name, c_name, ip_address) tuple, fetch the https page.
    On connection/read error or 404 response, fetch the http page.
    On further error, set up for attachment to dangling list'''
    session = requests.Session()
    rr_full_name = record[0]
    value1 = record[1]
    ip = record[2]
    try:
        r = session.get(f'https://{rr_full_name}', headers={
                        'User-Agent': 'Mozilla/5.0'}, verify=False, timeout=(3.05, 10))
        if r.status_code == 404:
            raise HTTPSException('try http')
        soup = BeautifulSoup(r.text, 'html.parser')
        return ('HTTPS success', rr_full_name, ip, value1, soup.get_text(), '', r.status_code, '')
    except (requests.exceptions.SSLError, requests.ReadTimeout, requests.ConnectionError,
            requests.ConnectTimeout, HTTPSException):
        try:
            r2 = session.get(f'http://{rr_full_name}', headers={
                             'User-Agent': 'Mozilla/5.0'}, verify=False, timeout=(3.05, 10))
            soup2 = BeautifulSoup(r2.text, 'html.parser')
            return ('HTTP success', rr_full_name, ip, value1, '', soup2.get_text(), '',
                    r2.status_code)
        except Exception as e:
            return (type(e).__name__, rr_full_name, ip)
    except Exception as e:
        return (type(e).__name__, rr_full_name, ip)


def multiprocessCheckA(x):
    '''Given a (url, ip_address) tuple, find false positives'''
    url = x[1]
    ip_address = x[2]
    # Runs a 'dig -x' on the ip address to determine if
    # it is the same as as the url or if it is connected to
    # a Penn affliated domain
    try:
        domain = socket.gethostbyaddr(ip_address)[0]
        if url == domain or 'upenn.edu' in domain:
            return x
    except Exception:
        pass
    # Runs telnet on port 25 to check for email service
    try:
        if ('mx' in url or 'smtp' in url):
            tn = Telnet(url, port=25, timeout=5)
            tn.close()
            return x
    except Exception:
        pass
    # Runs Telnet on port 3268/389 to check for gc._msdcs
    try:
        if 'gc._msdcs' in url:
            tn = Telnet(url, port=3268, timeout=5)
            tn.close()
            return x
    except Exception:
        pass
    try:
        if 'gc._msdcs' in url:
            tn = Telnet(url, port=389, timeout=5)
            tn.close()
            return x
    except Exception:
        pass
    return None


def multiprocessCheckCNAME(x):
    '''Given a (error, url, ip_address) tuple, find false positives'''
    error = x[0]
    url = x[1]
    ip_address = x[2]
    if error != 'rdata does not resolve':
        # Runs a 'dig -x' on the ip address to determine if
        # it is the same as as the url or if it is connected to
        # a Penn affliated domain
        try:
            domain = socket.gethostbyaddr(ip_address)[0]
            if url == domain or 'upenn.edu' in domain:
                return x
        except Exception:
            pass
        # Tries to make a sftp/scp/ssh connection
        try:
            if 'sftp' in url or 'scp' in url or 'ssh' in url:
                host = url
                port = 22
                transport = paramiko.Transport((host, port))
                transport.connect()
                return x
        except Exception:
            pass
        # Runs telnet on port 25 to check for email service
        try:
            if 'mx' in url or 'smtp' in url:
                tn = Telnet(url, port=25, timeout=5)
                tn.close()
                return x
        except Exception:
            pass
        # Runs telnet on port 5060 to check for sip service
        try:
            if 'sip' in url:
                tn = Telnet(url, port=5060, timeout=5)
                tn.close()
                return x
        except Exception:
            pass
    return None


def parse(string):
    '''Categorize the type of error'''
    if string in ('ConnectionError', 'ConnectTimeout', 'RemoteDisconnect', 'ReadTimeout'):
        return 'Timeout and similar'
    if string in ('TooManyRedirects', 'SSLError') or 'Response Code' in string:
        return 'HTTP/S'
    if string in ('rdata does not resolve', 'LocationParseError'):
        return 'DNS-related'
    print(f'check this {string}')
    return None

#################################################################################
#
# CHECK EXPIRED
#
#################################################################################


def checkARecords(urlBase, credHeaders):
    '''Iterate through A records to check for dangling domains'''
    a_records = getARecords(urlBase, credHeaders)

    ip_addresses = [(x['rr_full_name'], x['value1']) for x in a_records]
    filtered_ip_addresses = [x for x in ip_addresses if filterIPAddress(x[1])]

    orgNames = {}
    dangling = []
    with Pool(processes=4) as pool:
        for result in pool.map(multiprocessA, filtered_ip_addresses):
            if result[0] == 'HTTPS success' or result[0] == 'HTTP success':
                orgNames[result[1]] = result[2:]
            else:
                dangling.append(result)

    with open('A_content.json', 'w', encoding='utf-8') as f:
        json.dump(orgNames, f, ensure_ascii=False, indent=4)

    for key, value in orgNames.items():
        ip_address = value[0]
        https_status_code = value[3]
        http_status_code = value[4]
        if not (https_status_code == 200 or http_status_code == 200 or
                https_status_code == 401 or http_status_code == 401 or
                https_status_code == 403 or http_status_code == 403):
            if https_status_code != '':
                dangling.append(
                    (f'Response Code {https_status_code} on port 443', key, ip_address))
            elif http_status_code != '':
                dangling.append(
                    (f'Response Code {http_status_code} on port 80', key, ip_address))
    return dangling


def checkMXRecords(urlBase, credHeaders):
    '''Iterate through MX records to check for dangling domains'''
    mx_records = getMXRecords(urlBase, credHeaders)
    filtered_mx_records = list(filter(filterUPennMX, mx_records))
    filtered_domains = [(x['rr_full_name'], x['value2'])
                        for x in filtered_mx_records]
    _, failed_ip_addresses = getIPAddress(filtered_domains)
    return failed_ip_addresses


def checkCNAMERecords(urlBase, credHeaders):
    '''Iterate through CNAME records to check for dangling domains'''
    cname_records = getCNAMERecords(urlBase, credHeaders)
    filtered_cname_records = list(filter(filterUPennCNAME, cname_records))
    filtered_domains = [(x['rr_full_name'], x['value1'])
                        for x in filtered_cname_records]

    filtered_ip_addresses, failed_ip_addresses = getIPAddress(filtered_domains)
    filtered_ip_addresses = [
        x for x in filtered_ip_addresses if filterIPAddress(x[2])]

    orgNames = {}
    with Pool(processes=4) as pool:
        for result in pool.map(multiprocessCNAME, filtered_ip_addresses):
            if result[0] == 'HTTPS success' or result[0] == 'HTTP success':
                orgNames[result[1]] = result[2:]
            else:
                failed_ip_addresses.append(result)

    with open('CNAME_content.json', 'w', encoding='utf-8') as f:
        json.dump(orgNames, f, ensure_ascii=False, indent=4)

    dangling = []
    for key, value in orgNames.items():
        cname_pointer = value[0]
        https_status_code = value[4]
        http_status_code = value[5]
        if not (https_status_code == 200 or http_status_code == 200 or
                https_status_code == 401 or http_status_code == 401 or
                https_status_code == 403 or http_status_code == 403):
            dangling.append((key, cname_pointer))
            if value[4] != '':
                failed_ip_addresses.append(
                    (f'Response Code {https_status_code} on port 443', key, cname_pointer))
            elif value[5] != '':
                failed_ip_addresses.append(
                    (f'Response Code {http_status_code} on port 80', key, cname_pointer))
    return failed_ip_addresses


def main():
    '''Check for dangling domains
    Delete false positives
    Fetch School/Center list
    Format report'''
    urlBase, credHeaders = getConfig()

    dangling = {}

    # Initial Dangling List
    dangling['A'] = checkARecords(urlBase, credHeaders)
    dangling['MX'] = checkMXRecords(urlBase, credHeaders)
    dangling['CNAME'] = checkCNAMERecords(urlBase, credHeaders)

    # Delete False Positives
    with Pool(processes=4) as pool:
        for result in pool.map(multiprocessCheckA, dangling['A']):
            if result is not None:
                dangling['A'].remove(result)

    deletion_MX = []
    for x in dangling['MX']:
        mx = x[2]
        try:
            tn = Telnet(mx, port=25, timeout=5)
            tn.close()
            deletion_MX.append(x)
        except Exception:
            pass

    with Pool(processes=4) as pool:
        for result in pool.map(multiprocessCheckCNAME, dangling['CNAME']):
            if result is not None:
                dangling['CNAME'].remove(result)

    for x in deletion_MX:
        dangling['MX'].remove(x)

    # Fetch School/Center list
    session = requests.Session()
    df = None
    try:
        r = session.get('https://lab.net.isc.upenn.edu/domainnames/',
                        headers={'User-Agent': 'Mozilla/5.0'}, verify=False, timeout=(3.05, 10))
        df_list = pd.read_html(r.content)
        df = df_list[-1]
        df = df.set_index('Name')
        df.loc['private.upenn.edu'] = [
            'Filler', 'Information Systems & Computing (ISC)', 'Filler']
    except Exception as e:
        print(f'Error with fetching school/center names: {type(e).__name__}')

    # Exclusion List
    with open('exclusion_list.txt') as exclusion:
        data = exclusion.read()
        exclusion_list = data.split("\n")

    # Format
    report = {}
    for x in dangling['A']+dangling['MX']+dangling['CNAME']:
        if x[1] in exclusion_list:
            continue
        third_level_domain = '.'.join(str(x[1]).split('.')[-3:])
        try:
            school_center = df.loc[third_level_domain]['Registrant']
        except Exception as e:
            if 'magpi' in third_level_domain:
                school_center = 'Magpi'
            else:
                school_center = 'Unknown School/Center'
        report.setdefault(school_center, {}).setdefault(
            parse(x[0]), []).append(x)

    with open('report.txt', 'w', encoding='utf-8') as f:
        f.write(
            'School/Organization\tType of Error\tAffected domain name\tSpecific Error\trdata\n')
        for x in report.items():
            for y in x[1].items():
                for z in y[1]:
                    f.write(f'{x[0]}')
                    f.write(f'\t{y[0]}')
                    f.write(f'\t{z[1]}\t{z[0]}\t{z[2]}\n')
                f.write('\n')
            f.write('\n')


if __name__ == '__main__':
    main()
