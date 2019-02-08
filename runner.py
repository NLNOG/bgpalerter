import yaml
from bgpalerter import BGPalerter

config = yaml.safe_load(open("config.yml", "r").read())


def tranform(item):
    return {
        "origin": item["base_asn"],
        "description": item.get("description"),
        "monitor_more_specific": not item.get("ignore_morespec", False),
    }

to_be_monitored = {}

for file_name in config.get("monitored-prefixes-files"):
    print("Loading prefixes from " + file_name)
    pointer = open(file_name, "r")
    input_list = yaml.safe_load(pointer.read())
    for item in input_list.keys():
        to_be_monitored[item] = tranform(input_list[item])

BGPalerter(config, to_be_monitored)
