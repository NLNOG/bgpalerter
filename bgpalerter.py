# BGPalerter
# Copyright (C) 2019  Massimo Candela <https://massimocandela.com>
#
# Licensed under BSD 3-Clause License. See LICENSE for more details.

from ris_listener import RisListener
from threading import Timer


class BGPalerter:

    def __init__(self, config):
        self.monitored_prefixes = {}
        self.config = config

        self.stats = {
            "hijack": {},
            "low-visibility": {}
        }
        self.callbacks = {
            "hijack": [],
            "low-visibility": [],
            "difference": [],
            "heartbeat": []
        }
        self.reset_called = False
        self._check_stats()
        self._heartbeat()

        self._ris = RisListener(self.config.get("websocket-data-service"))
        self._ris.on("hijack", self._collect_stats_hijack)
        self._ris.on("difference", self._collect_stats_difference)
        self._ris.on("withdrawal", lambda data: self._collect_stats_low_visibility(data, False))
        self._ris.on("announcement", lambda data: self._collect_stats_low_visibility(data, True))

    def _collect_stats_difference(self, data):
        prefix = data["expected"]["prefix"]
        more_specific = data["altered"]["prefix"]
        self._publish("difference", "The prefix {} it is not configured to be announced with the more specific {}"
                      .format(prefix, more_specific))

    def monitor(self, prefixes):

        def tranform(item):
            return {
                "origin": item["base_asn"],
                "description": item.get("description"),
                "monitor_more_specific": not item.get("ignore_morespec", False),
            }

        for item in prefixes.keys():
            self.monitored_prefixes[item] = tranform(prefixes[item])

        self._ris.subscribe(self.monitored_prefixes)

    def on(self, event_name, callback):
        if event_name in self.callbacks:
            self.callbacks[event_name].append(callback)
        else:
            raise Exception('This is not a valid event: ' + event_name)

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

    def _collect_stats_low_visibility(self, data, add):
        prefix = data["prefix"]
        peer = data["peer"]

        if prefix not in self.stats["low-visibility"]:
            self.stats["low-visibility"][prefix] = {}

        self.stats["low-visibility"][prefix][peer] = not add

    def reset(self):
        self.stats = {
            "hijack": {},
            "low-visibility": {}
        }

    def _check_stats(self):
        Timer(self.config.get("repeat-alert-after-seconds", 10), self._check_stats).start()
        triggered = False
        for key, value in self.stats["hijack"].items():
            if len(value["peers"]) >= self.config.get("number-peers-before-hijack-alert", 0):
                self._publish("hijack", self._get_hijack_alert_message(value))
                triggered = True

        for prefix, value in self.stats["low-visibility"].items():
            number_peers = len(value.items())
            if number_peers >= self.config.get("number-peers-before-low-visibility-alert", 0):
                self._publish("low-visibility", self._get_low_visibility_alert_message(prefix, number_peers))
                triggered = True

        if not self.reset_called and triggered:
            Timer(self.config.get("reset-after-seconds", 600), self.reset).start()
            self.reset_called = True

    def _get_hijack_alert_message(self, data):
        message = "Possible Hijack, it should be " + data["expected"]["prefix"] + \
                  " AS" + str(data["expected"]["originAs"])

        if "description" in data:
            message += " (" + str(data["description"]) + ") "
        message += "now announced " + data["altered"]["prefix"] + " AS" + str(data["altered"]["originAs"])
        message += " seen by " + str(len(data["peers"])) + " peers"
        return message

    def _get_low_visibility_alert_message(self, prefix, number_peers):
        return "The prefix " + prefix + " is not visible anymore from " + str(number_peers) + " peers"

    def _publish(self, event_name, message):
        for call in self.callbacks[event_name]:
            call(message)

    def _heartbeat(self):
        heartbeat_time = self.config.get("repeat-status-heartbeat-after-seconds", 0)
        if heartbeat_time > 0:
            Timer(heartbeat_time, self._heartbeat).start()
        self._publish("heartbeat", "Still monitoring...")

