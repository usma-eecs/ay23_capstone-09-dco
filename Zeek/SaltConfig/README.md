# Files to configure:

```global.sls``` -> the contents of this file should be pasted at the end of your global.sls file which is located at ```/opt/so/saltstack/local/pillar```. Once pasted you will need to restart the zeek docker with ```sudo so-zeek-restart```. We can test if the restart was successful with ```sudo docker logs so-zeek```

```zeek.OS``` -> this file allows you to ingest the custom OS log that we have created into elastic. To verify if the OS.log is being created look for it in ```/nsm/zeek/logs/current```, if it isn't there then there is a problem with zeek, if it is, then this file will allow it to be ingested so it is viewable in elastic and all related services (securityonion frontend, kibana, etc)
This file should be placed, as is, in ```/opt/so/saltstack/local/salt/elasticsearch/files/ingest```, after placing, you should restart are elastic dockers with the command ```sudo so-[name of docker]-restart```. You can ensure it worked with ```sudo docker logs [name of docker]```

Focus on the ```global.sls``` first, without this the zeek log will not even be created and hence ```zeek.OS``` has no log file to even ingest. Once you verify you are creating the log file properly, you can move on to ```zeek.OS```
