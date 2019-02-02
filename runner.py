# BGPalerter
# Copyright (C) 2019  Massimo Candela <https://massimocandela.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from ris_listener import RisListener
import os
import yaml
from threading import Timer

to_be_monitored = {}
stats = {}
config = yaml.safe_load(open("config.yml", "r").read())
reset_called = False

def tranform(item):
    return {
        "origin": item["base_asn"],
        "description": item.get("description"),
        "monitor_more_specific": not item.get("ignore_morespec", False),
    }


def read_input_file(file_name):
    pointer = open(file_name, "r")
    input_list = yaml.safe_load(pointer.read())
    for item in input_list.keys():
        to_be_monitored[item] = tranform(input_list[item])


for file_name in config.get("monitored-prefixes-files"):
    print("Loading prefixes from " + file_name)
    read_input_file(file_name)


def collect_stats(data):
    global stats
    key = data["expected"]["prefix"] + "-" + data["altered"]["prefix"] + \
          "-" + str(data["expected"]["originAs"]) + "-" + str(data["altered"]["originAs"])

    if key in stats:
        if not data["peer"] in stats[key]["peers"]:
            stats[key]["peers"].append(data["peer"])
    else:
        stats[key] = {
            "expected": data["expected"],
            "altered": data["altered"],
            "peers": [data["peer"]],
            "description": data["description"]
        }


def reset():
    global stats
    stats = {}


def check_stats():
    global reset_called
    global stats
    Timer(config.get("repeat-alert-after-seconds", 10), check_stats).start()
    for key, value in stats.items():
        print(value)
        if len(value["peers"]) > config.get("number-peers-before-alert", 0):
            send_to_slack(alert_message(value))
            if not reset_called:
                Timer(config.get("reset-after-seconds", 600), reset).start()
                reset_called = True


def alert_message(data):
    print("hijack detected")
    message = "Possible Hijack, it should be " + data["expected"]["prefix"] + " AS" + str(data["expected"]["originAs"])
    if "description" in data:
        message += " (" + str(data["description"]) + ") "
    message += " now announced " + data["altered"]["prefix"] + " AS" + str(data["altered"]["originAs"])
    message += " seen by " + str(len(data["peers"])) + " peers"
    return message


def send_to_slack(message):
    command = "curl -X POST -H 'Content-type: application/json' --data '{\"text\": \"" + message + "\"}' " + \
              config.get("slack-web-hook")
    os.system(command)


def heartbeat():
    heartbeat_time = config.get("repeat-status-heartbeat-after-seconds", 0)
    if heartbeat_time > 0:
        Timer(heartbeat_time, heartbeat).start()
    send_to_slack("Still monitoring...")


def run_service(url):
    ris = RisListener(url)
    ris.on("hijack", collect_stats)
    ris.subscribe(to_be_monitored)


check_stats()
heartbeat()


for url in config.get("websocket-data-services"):
    run_service(url)





