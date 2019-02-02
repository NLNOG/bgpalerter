This is a basic script to monitor if a list of <prefix, AS> pairs are announced consistently.

It uses the RIPE RIS data to monitor in real-time the pairs.
If a prefis (or a more specific of it) is announced from an AS different from the one sprecified in the list, it triggers an alert.

For now the alert is a message in Slack.
