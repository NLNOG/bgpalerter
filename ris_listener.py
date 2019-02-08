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

import json
import websocket
import ipaddress
from threading import Timer


class RisListener:

    def __init__(self, url):
        self.prefixes = {}
        self.url = url
        self.prefixes_index = {
            "4": [],
            "6": [],
        }
        self.hijacks = {}
        self.callbacks = {
            "hijack": [],
            "withdrawal": [],
        }

        ws = websocket.WebSocket()
        self.ws = ws
        self._connect()

        # t = Timer(5, self._fake)
        # t.start()

        def ping():
            ws.send('2')
            Timer(5, ping).start()

        ping()

    def _connect(self):
        self.ws.connect(self.url)

    def _fake(self):
        data = {
            "data": {
                "prefix": "84.205.65.0/25",
                "peer": "192.168.1.1",
                "path": [123, 125, 3334],
            }
        }

        self._filter_hijack(data)

    def on(self, event, callback):
        if event not in self.callbacks:
            raise Exception('This is not a valid event: ' + event)
        else:
            self.callbacks[event].append(callback)

    def _detect_hijack(self, original_prefix, original_as, hijacked_prefix, hijacking_as, peer, description):
        if hijacking_as and hijacking_as != original_as:
            for call in self.callbacks["hijack"]:
                call({
                    "expected": {
                        "originAs": original_as,
                        "prefix": original_prefix
                    },
                    "altered": {
                        "originAs": hijacking_as,
                        "prefix": hijacked_prefix
                    },
                    "description": description,
                    "peer": peer
                })
        return

    def _filter_visibility(self, data):
        item = data["data"]
        str_prefix = item["prefix"]
        peer = item["peer"]

        for call in self.callbacks["withdrawal"]:
            call({
                "prefix": str_prefix,
                "peer": peer
            })

    def _filter_hijack(self, data):
        item = data["data"]
        str_prefix = item["prefix"]
        prefix = ipaddress.ip_network(str_prefix)

        same_version_prefix_index = self.prefixes_index[str(prefix.version)]
        peer = item["peer"]
        path = item["path"]

        if len(path) > 0:
            origin_as = path[-1]

            if prefix in same_version_prefix_index:
                return self._detect_hijack(str_prefix, self.prefixes[str_prefix]["origin"], str_prefix, origin_as,
                                           peer, self.prefixes[str_prefix]["description"])
            else:
                for supernet in same_version_prefix_index:
                    if prefix.subnet_of(supernet):
                        return self._detect_hijack(str(supernet), self.prefixes[str(supernet)]["origin"], str_prefix,
                                                   origin_as, peer, self.prefixes[str(supernet)]["description"])

        return  # nothing strange

    def subscribe(self, prefixes):
        self.prefixes = prefixes
        ip_list = list(map(ipaddress.ip_network, self.prefixes.keys()))

        self.prefixes_index = {
            "4": list(filter(lambda ip: ip.version == 4, ip_list)),
            "6": list(filter(lambda ip: ip.version == 6, ip_list)),
        }

        for prefix in prefixes:
            print("Subscribing to " + prefix)
            self.ws.send(json.dumps({
                "type": "ris_subscribe",
                "data": {
                    "prefix": prefix,
                    "moreSpecific": True,
                    "type": "UPDATE",
                    # "require": "announcements",
                    "socketOptions": {
                        "includeRaw": False,
                        "explodePrefixes": True,
                    }
                }
            }))

        for data in self.ws:
            parsed = json.loads(data)
            if parsed["type"] == "ris_message":
                if parsed["source"] == "announcements":
                    self._filter_hijack(parsed)
                elif parsed["source"] == "withdrawals":
                    self._filter_visibility(parsed)
