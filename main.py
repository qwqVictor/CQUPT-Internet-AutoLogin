#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
from utils import *

def check_if_have_logged_in(authserver: str):
    try:
        r = send_request(url="http://" + authserver)
        return not r.text.find("注销页") == -1
    except:
        return False

def do_login(config):
    if not check_if_have_logged_in(config["authserver"]):
        try:
            if "initShellCommands" in config and config["initShellCommands"] is not None:
                os.system(config["initShellCommands"])
            stat = json.loads(strip_brackets(send_request(get_login_payload(config["carrier"], config["account"], config["password"], config["ip"]), headers=HEADERS).text))
            logger("Logged in\nInfo: %s" % json.dumps(stat, ensure_ascii=False))
        except Exception as e:
            handle_exception("doLogin", e)

def do_logout(config):
    if check_if_have_logged_in(config["authserver"]):
        try:
            stat = json.loads(strip_brackets(send_request(get_logout_payload(config["carrier"], config["account"], config["ip"]), headers=HEADERS)))
            logger("Logged out\nInfo: %s" % json.dumps(stat, ensure_ascii=False))
        except Exception as e:
            handle_exception("doLogout", e)

def login_daemon_loop(config):
    logger("Script started, working hard to connect to Internet.")
    while True:
        do_login(config)
        time.sleep(20)

def main(argv: list):
    args = parse_args()
    try:
        config_file_path = args.config
        assert config_file_path
    except:
        config_file_path = "config.json"
    print("CQUPT Internet AutoLogin ver %s" % VERSION)
    print("%d (c) %s\n" % (COPYRIGHT_YEAR, AUTHOR))
    config = parse_config(config_file_path)
    if SOCKET_BIND:
        if not bind_socket(config["ip"]):
            logger("Warning! IP invalid.\n")
    if args.logout:
        do_logout(config)
        exit()
    login_daemon_loop(config)

if __name__ == "__main__":
    main(sys.argv)