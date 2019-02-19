# BGPalerter
BGPalerter is a script to monitor in real time if a list of <prefix, AS> pairs are announced consistently.

It uses the [real-time RIPE RIS](https://ris-live.ripe.net/) streaming service to obtain BGP messages with a delay in the order of seconds.

For now BGPalerter triggers an alert if:
1) a prefix (or a more specific) is announced by a different AS of what it should be
2) a prefix is loosing visibility
3) a more specific is announced instead of the prefix initially configured (but it was not supposed to happen)

### Installation

Steps:
- clone the repo:
``git clone git@github.com:NLNOG/bgpalerter.git``
or download the zip file
```https://github.com/NLNOG/bgpalerter/archive/master.zip```

- rename ```monitored_prefixes.base.yml``` to ```monitored_prefixes.yml```

- edit the ```monitored_prefixes.yml``` file to contain your prefixes.
```
27.114.0.0/17: <- The prefix you want to monitor
    description: A description <-- A human readable description that will appear in the notification
    base_asn: 2914 <-- The origin ASN of the prefix
    ignore_morespec: False <-- Monitor also for more specific prefix and trigger an alert if they appear (I would leave it to False!)
```

- rename ```config.base.yml``` to ```config.yml```

- edit the ```config.yml``` file.

- You need python 3.7, after install the other requirements with ```pip install -r requirements.txt```

- to run the monitoring do ```python runner.py```

### Notifications
In runner.py you can subscribe to the following event names:
- hijack (type 1)
- low-visibility (type 2)
- difference (type 3)
- heartbeat (status of the monitor)

As an example the script sends the notifications to a slack channel or to a list of email addresses (both configurable in config.yml) but you can subscribe to the event whatever callback you want.




