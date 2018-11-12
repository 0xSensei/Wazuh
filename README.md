# Wazuh containers for Docker

## Current release 

containers are currently **tested** on Wazuh

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
