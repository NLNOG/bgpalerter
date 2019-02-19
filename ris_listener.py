# BGPalerter
# Copyright (C) 2019  Massimo Candela <https://massimocandela.com>
#
# Licensed under BSD 3-Clause License. See LICENSE for more details.

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
            "difference": []
        }

        ws = websocket.WebSocket()
        self.ws = ws
        self._connect()

        def ping():
            ws.send('2')
            Timer(5, ping).start()

        ping()

    def _connect(self):
        self.ws.connect(self.url)

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
        else:
            for call in self.callbacks["difference"]:
                call({
                    "expected": {
                        "prefix": original_prefix
                    },
                    "altered": {
                        "prefix": hijacked_prefix
                    },
                    "originAs": original_as,
                    "description": description,
                    "peer": peer
                })

    def _filter_visibility(self, item):
        str_prefix = item["prefix"]
        peer = item["peer"]
        prefix = ipaddress.ip_network(str_prefix)
        same_version_prefix_index = self.prefixes_index[str(prefix.version)]

        if prefix in same_version_prefix_index:
            for call in self.callbacks["withdrawal"]:
                call({
                    "prefix": str_prefix,
                    "peer": peer
                })

    def _filter_hijack(self, item):
        str_prefix = ""
        try:
            str_prefix = item["prefix"]
        except:
            print(item)
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

    def unpack(self, json_data):
        data = json_data["data"]
        unpacked = []

        if "announcements" in data:
            for announcement in data["announcements"]:
                next_hop = announcement["next_hop"]
                if "prefixes" in announcement:
                    for prefix in announcement["prefixes"]:
                        unpacked.append({
                            "type": "announcement",
                            "prefix": prefix,
                            "peer": data["peer"],
                            "path": data["path"],
                            "next_hop": next_hop
                        })

        if "withdrawals" in data:
            for prefix in data["withdrawals"]:
                unpacked.append({
                    "type": "withdrawal",
                    "prefix": prefix,
                    "peer": data["peer"]

                })

        return unpacked

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
                    "socketOptions": {
                        "includeRaw": False
                    }
                }
            }))

        for data in self.ws:
            try:
                json_data = json.loads(data)
                if "type" in json_data and json_data["type"] == "ris_message":
                    for parsed in self.unpack(json_data):
                        if parsed["type"] is "announcement":
                            self._filter_hijack(parsed)
                        elif parsed["type"] is "withdrawal":
                            self._filter_visibility(parsed)
            except:
                print("Error while reading the JSON from WS")
