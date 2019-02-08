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
from threading import Timer


class BGPalerter:

    def __init__(self, config, monitored_prefixes):
        self.monitored_prefixes = monitored_prefixes
        self.config = config
        self.stats = {
            "hijack": {},
            "low-visibility": {}
        }
        self.reset_called = False
        self._check_stats()
        self._heartbeat()

    def _collect_stats_hijack(self, data):
        key = data["expected"]["prefix"] + "-" + data["altered"]["prefix"] + \
              "-" + str(data["expected"]["originAs"]) + "-" + str(data["altered"]["originAs"])

        if key in self.stats["hijack"]:
            if not data["peer"] in self.stats["hijack"][key]["peers"]:
                self.stats["hijack"][key]["peers"].append(data["peer"])
        else:
            self.stats["hijack"][key] = {
                "expected": data["expected"],
                "altered": data["altered"],
                "peers": [data["peer"]],
                "description": data["description"]
            }

    def _collect_stats_low_visibility(self, data):
        prefix = data["prefix"]
        peer = data["peer"]

        if not self.stats["low-visibility"][prefix]:
            self.stats["low-visibility"][prefix] = {}

            self.stats["low-visibility"][prefix][peer] = True


    def reset(self):
        self.stats = {
            "hijack": {},
            "low-visibility": {}
        }

    def _check_stats(self):
        Timer(self.config.get("repeat-alert-after-seconds", 10), self._check_stats).start()
        triggered = False
        for key, value in self.stats["hijack"].items():
            if len(value["peers"]) > self.config.get("number-peers-before-hijack-alert", 0):
                self.send_to_slack(self._get_hijack_alert_message(value))
                triggered = True

        for prefix, value in self.stats["low-visibility"].items():
            number_peers = len(value.items())
            if number_peers > self.config.get("number-peers-before-low-visibility-alert", 0):
                self.send_to_slack(self._get_low_visibility_alert_message(prefix, number_peers))
                triggered = True

        if not self.reset_called and triggered:
            Timer(self.config.get("reset-after-seconds", 600), self.reset).start()
            self.reset_called = True

    def _get_hijack_alert_message(self, data):
        message = "Possible Hijack, it should be " + data["expected"]["prefix"] + \
                  " AS" + str(data["expected"]["originAs"])

        if "description" in data:
            message += " (" + str(data["description"]) + ") "
        message += " now announced " + data["altered"]["prefix"] + " AS" + str(data["altered"]["originAs"])
        message += " seen by " + str(len(data["peers"])) + " peers"
        return message

    def _get_low_visibility_alert_message(self, prefix, number_peers):
        message = "The prefix " + prefix + " is not visible anymore from " + number_peers + " peers"
        self._send_to_slack(message)

    def _send_to_slack(self, message):
        command = "curl -X POST -H 'Content-type: application/json' --data '{\"text\": \"" + message + "\"}' " + \
                  self.config.get("slack-web-hook")
        os.system(command)

    def _heartbeat(self):
        heartbeat_time = self.config.get("repeat-status-heartbeat-after-seconds", 0)
        if heartbeat_time > 0:
            Timer(heartbeat_time, self.heartbeat).start()
        self._send_to_slack("Still monitoring...")

    def run_service(self, url):
        ris = RisListener(url)
        ris.on("hijack", self._collect_stats_hijack)
        ris.on("low-visibility", self._collect_stats_low_visibility)
        ris.subscribe(self.monitored_prefixes)

