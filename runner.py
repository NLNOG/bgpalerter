# BGPalerter
# Copyright (C) 2019  Massimo Candela <https://massimocandela.com>
#
# Licensed under BSD 3-Clause License. See LICENSE for more details.

import yaml
from bgpalerter import BGPalerter
import os

config = yaml.safe_load(open("config.yml", "r").read())


to_be_monitored = {}

for file_name in config.get("monitored-prefixes-files"):
    print("Loading prefixes from " + file_name)
    pointer = open(file_name, "r")
    input_list = yaml.safe_load(pointer.read())
    for item in input_list.keys():
        to_be_monitored[item] = input_list[item]


def send_to_slack(message):
    print(message)
    command = "curl -X POST -H 'Content-type: application/json' --data '{\"text\": \"" + message + "\"}' " + \
              config.get("slack-web-hook")
    os.system(command)


alerter = BGPalerter(config)

alerter.on("hijack", send_to_slack)
alerter.on("low-visibility", send_to_slack)
alerter.on("difference", send_to_slack)
# alerter.on("heartbeat", send_to_slack)
alerter.monitor(to_be_monitored)
