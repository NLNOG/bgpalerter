# BGPalerter
# Copyright (C) 2019  Massimo Candela <https://massimocandela.com>
#
# Licensed under BSD 3-Clause License. See LICENSE for more details.

import yaml
import smtplib
from bgpalerter import BGPalerter
import os
from email.mime.text import MIMEText

config = yaml.safe_load(open("config.yml", "r").read())


to_be_monitored = {}

for file_name in config.get("monitored-prefixes-files"):
    print("Loading prefixes from " + file_name)
    pointer = open(file_name, "r")
    input_list = yaml.safe_load(pointer.read())
    for item in input_list.keys():
        to_be_monitored[item] = input_list[item]


def send_to_slack(message):
    command = "curl -X POST -H 'Content-type: application/json' --data '{\"text\": \"" + message + "\"}' " + \
              config.get("slack-web-hook")
    os.system(command)


def send_email(message):
    email_from = config.get("sender-notifications-email")
    email_to = config.get("notified-emails")

    msg = MIMEText(message)
    msg['Subject'] = 'BGP alert'
    msg['From'] = email_from
    msg['To'] = ", ".join(email_to)

    server = smtplib.SMTP('localhost')
    server.sendmail(email_from, email_to, msg.as_string())
    server.quit()


send_to_slack("Starting to monitor...")
# send_email("Starting to monitor...")

# change the way you want to be notified below
alerter = BGPalerter(config)

alerter.on("hijack", send_to_slack)
alerter.on("low-visibility", send_to_slack)
alerter.on("difference", send_to_slack)
# alerter.on("heartbeat", send_to_slack)

alerter.monitor(to_be_monitored)
