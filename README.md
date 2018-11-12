# Kosyas Wazuh containers for Docker

## Current release 

* Kosyas Wazuh containers are currently on Wazuh.
* Kosyas Wazuh systems collect logs from those who contact your system. And then analyze collected logs, make your visualize statistics by Kibana. Kosyas Rule's Agents will alert, if they find danerous detection. These system make safe your system. 

### Docker-hub notes

These are Docker-Hub URL:
1. wazuh
[![Documentation](https://img.shields.io/badge/web-view-green.svg)](https://hub.docker.com/r/kng20170406/wazuh/)
2. logstash
[![Documentation](https://img.shields.io/badge/web-view-green.svg)](https://hub.docker.com/r/kng20170406/wazuh-logstash/)
3. elasticsearch
[![Documentation](https://img.shields.io/badge/web-view-green.svg)](https://hub.docker.com/r/kng20170406/elasticsearch/)
4. kibana
[![Documentation](https://img.shields.io/badge/web-view-green.svg)](https://hub.docker.com/r/kng20170406/wazuh-kibana/)
5. nginx
[![Documentation](https://img.shields.io/badge/web-view-green.svg)](https://hub.docker.com/r/kng20170406/wazuh-nginx/)


### How to use **docker-compose.yml**

If you want to use docker-compose.yml, using this file make you to configurate Kosyas wazuh containers (Docker images will be downloaded automatically.) 

```
root@wazuh-manager:docker-compose up -d

Creating network "wazuh_docker_elk" with driver "bridge"
Creating wazuh_elasticsearch_1
Creating wazuh_wazuh_1
Creating wazuh_kibana_1
Creating wazuh_nginx_1
Creating wazuh_logstash_1

```
So you can find your docker-containters status by using 'docker ps' commander.

```
root@wazuh-manager:docker ps

CONTAINER ID        IMAGE                                                 COMMAND                  CREATED              STATUS                  PORTS                                                                                                                                                  NAMES
f438464e2cc9        kng20170406/wazuh-logstash                            "/usr/local/bin/dock…"   About a minute ago   Up 9 seconds            0.0.0.0:5000->5000/tcp, 0.0.0.0:6514->6514/udp, 0.0.0.0:7514->7514/udp, 5044/tcp, 0.0.0.0:5045-5046->5045-5046/tcp, 9600/tcp, 0.0.0.0:7516->7516/udp   wazuh_logstash_1
9998ad254da7        kng20170406/wazuh-nginx                               "/run.sh"                About a minute ago   Up About a minute       0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp                                                                                                               wazuh_nginx_1
d29a2f55770e        kng20170406/wazuh-kibana                              "/wait-for-it.sh ela…"   About a minute ago   Up About a minute       0.0.0.0:5601->5601/tcp                                                                                                                                 wazuh_kibana_1
3952ecb3e224        kng20170406/wazuh                                     "/tmp/run.sh"            2 minutes ago        Up About a minute       0.0.0.0:514->514/udp, 0.0.0.0:1515->1515/tcp, 0.0.0.0:1514->1514/udp, 0.0.0.0:55000->55000/tcp, 1516/tcp                                               wazuh_wazuh_1
1db2d763097a        docker.elastic.co/elasticsearch/elasticsearch:6.2.3   "/usr/local/bin/dock…"   2 minutes ago        Up Less than a second   0.0.0.0:9200->9200/tcp, 9300/tcp   

```

Finally, you can check your own Kosyas Wazuh containers.

### More Information

You need to increase max_map_count on your Docker ho

sysctl -w vm.max_map_count=262144



To set this value permanently, update the vm.max_map_count setting in /etc/sysctl.conf. To verify after rebooting, run “sysctl vm.max_map_count”.

### More documentation

* [Wazuh full documentation](http://documentation.wazuh.com)
* [Wazuh documentation for Docker](https://documentation.wazuh.com/current/docker/index.html)
* [Docker hub](https://hub.docker.com/u/wazuh)

### License and copyright

Wazuh App Copyright (C) 2018 Wazuh Inc. 

### Wazuh official website

[Wazuh website](http://wazuh.com)
