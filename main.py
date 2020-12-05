#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from utils import *

def checkIfHaveLoggedIn(authserver: str):
    try:
        r = sendRequest(url="http://" + authserver)
        return not r.text.find("注销页") == -1
    except:
        return False

def doLogin(config):
    if not checkIfHaveLoggedIn(config["authserver"]):
        try:
            if "initShellCommands" in config and config["initShellCommands"] is not None:
                os.system(config["initShellCommands"])
            stat = json.loads(stripBrackets(sendRequest(getLoginPayload(config["carrier"], config["account"], config["password"], config["ip"]), headers=HEADERS).text))
            logger("Logged in\nInfo: %s" % json.dumps(stat, ensure_ascii=False))
        except Exception as e:
            handleException("doLogin", e)

def doLogout(config):
    if checkIfHaveLoggedIn(config["authserver"]):
        try:
            stat = json.loads(stripBrackets(sendRequest(getLogoutPayload(config["carrier"], config["account"], config["ip"]), headers=HEADERS)))
            logger("Logged out\nInfo: %s" % json.dumps(stat, ensure_ascii=False))
        except Exception as e:
            handleException("doLogout", e)

def loginDaemonLoop(config):
    logger("Script started, working hard to connect to Internet.")
    while True:
        doLogin(config)
        time.sleep(3)

def main(argv: list):
    args = parseArgs()
    try:
        configFilePath = args.config
        assert configFilePath
    except:
        configFilePath = "config.json"
    print("CQUPT Internet AutoLogin ver %s" % VERSION)
    print("%d (c) %s\n" % (COPYRIGHT_YEAR, AUTHOR))
    config = parseConfig(configFilePath)
    if SOCKET_BIND:
        if not bindSocket(config["ip"]):
            logger("Warning! IP invalid.\n")
    if args.logout:
        doLogout(config)
        exit()
    loginDaemonLoop(config)

if __name__ == "__main__":
    main(sys.argv)