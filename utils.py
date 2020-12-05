import requests
import time
import subprocess
import os
import json
import sys
import argparse
import socket
import ipaddress

VERSION = "1.0.0"
COPYRIGHT_YEAR=2020
AUTHOR="Victor Huang <i@qwq.ren>"

API_URL = None
API_SUFFIX = ":801/eportal/"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.42 Safari/537.36 Edg/86.0.622.19",
    "Referer": API_URL
}
SOCKET_BIND = False
IP_TO_BIND = ""

def parseArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", type=str,
                        help="specify a config file")
    parser.add_argument("-u", "--logout", action="store_true",
                        help="run and logout then exit")
    return parser.parse_args()

def getLogTime():
    return "[" + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) + "] "

def logger(info: str):
    for x in info.split('\n'):
        print(getLogTime() + x)

def parseConfig(configFilePath: str):
    global API_URL, HEADERS, SOCKET_BIND
    with open(configFilePath, "r") as f:
        config = json.load(f)
        f.close()
        API_URL = "http://" + config["authserver"] + API_SUFFIX
        HEADERS["Referer"] = API_URL
        if "socketBind" in config and config["socketBind"]:
            SOCKET_BIND = True;
        if "ip" in config and config["ip"]:
            try:
                ipaddress.ip_address(config["ip"])
            except:
                config["ip"] = None
        if "eth" not in config and config["ip"] is None:
            config["ip"] = getLocalIP4(authserver=config["authserver"])
        elif "eth" in config and config["ip"] is None:
            config["ip"] = getLocalIP4(config["eth"], authserver=config["authserver"])
        return config

SOCK_CREATE_CONNECTION = socket.create_connection
def setSrcAddr(*args):
    address, timeout = args[0], args[1]
    srcAddr = (IP_TO_BIND, 0)
    return SOCK_CREATE_CONNECTION(address, timeout, srcAddr)

def bindSocket(ip: str):
    global IP_TO_BIND
    try:
        ipaddress.ip_address(ip)
        IP_TO_BIND = ip
        socket.create_connection = setSrcAddr
        return True
    except:
        socket.create_connection = SOCK_CREATE_CONNECTION
        return False

def getLoginPayload(carrier: str, account: str, password: str, ip: str):
    return {
        "c": "Portal",
        "a": "login",
        "callback": "", # dr1003
        "login_method": 1,
        "user_account": ",0," + account + "@" + carrier,
        "user_password": password,
        "wlan_user_ip": ip,
        "wlan_user_ipv6": "",
        "wlan_user_mac": "000000000000",
        "wlan_ac_ip": "",
        "wlan_ac_name": "",
        "jsVersion": "3.3.3",
        "v": 3069
    }

def getLogoutPayload(carrier: str, account: str, ip: str):
    return {
        "c": "Portal",
        "a": "unbind_mac",
        "callback": "", # dr1002
        "user_account": account + "@" + carrier,
        "wlan_user_ip": ip,
        "wlan_user_ipv6": "",
        "wlan_user_mac": "000000000000",
        "jsVersion": "3.3.3",
        "v": 7455
    }

def handleException(origin, e):
    for i in e.args:
        logger("ERROR! [%s] Exception with information '%s'" % (origin, i))

def sendRequest(payload: dict = None, headers: dict = None, url: dict = None):
    if url is None:
        url = API_URL
    return requests.get(url, params=payload, headers=headers)

def stripBrackets(jsonp: str):
    return jsonp[jsonp.find('(') + 1:][:-1]

def getLocalIP4(eth: str = None, authserver: str = None, port: int = 80):
    ip = ""
    if eth is None:
        if authserver is None:
            raise Exception("No valid authserver found")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((authserver, port))
        ip = s.getsockname()[0]
        s.close()
    else:
        try:
            s = subprocess.run("ip -4 addr show dev %s | grep inet" % (eth), shell=True, stdout=subprocess.PIPE)
            ipwithcidr = s.stdout.decode().strip().split(" ")[1]
            ip = ipwithcidr.split("/")[0]
        except Exception as e:
            handleException("getLocalIP4", e)
    return ip