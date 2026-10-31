A detection that stops working looks exactly like a detection with nothing to detect.

I kept coming back to that while building PTAF Sentinel, an open-source agent that runs on Windows, macOS, Linux and VMs, fires harmless imitations of attacker behavior, and checks that your detection rules actually fire.

The first real run found a bug in my own example rule: a doubled backslash meant it could never match a Windows path. It had passed validation for weeks.

What it does today: safe canaries, your Sigma rules run against real telemetry, drift alerts when something that used to work stops, and a plain-English dashboard you can hand to a client.

What it doesn't do yet is in the README, in plain words.

If you do detection engineering or run a SOC: what's the last detection you *proved* still works?

Repo in the comments.

#cybersecurity #detectionengineering #purpleteam #opensource
