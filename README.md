# Wazuh containers for Docker

## Current release 

containers are currently **tested** on Wazuh

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](https://goo.gl/forms/M2AoZC4b2R9A9Zy12)
* wazuh: It runs the Wazuh manager, Wazuh API and Filebeat (for integration with Elastic Stack)

### More Infomation
Here is an example of a `/wazuh-config-mount` folder used to mount some common custom configuration files:
```
root@wazuh-manager:/# tree /wazuh-config-mount/
/wazuh-config-mount/
└── etc
    ├── ossec.conf
    ├── rules
    │   └── local_rules.xml
    └── shared
        └── default
            └── agent.conf

4 directories, 3 files
```
