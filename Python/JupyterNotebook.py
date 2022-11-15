#!/usr/bin/env python
# coding: utf-8

from elasticsearch import Elasticsearch
import elasticsearch.helpers
from elasticsearch_dsl import Search
import pandas as pd
import urllib3
import json
import time
import sys
import os
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#Redirect stderr output
fd = os.open('/dev/null',os.O_WRONLY)
os.dup2(fd,2)

#Handling user input
#Dictionary of valid queries we allow
validQueries = {"alert" : "event.dataset: alert",
		"syslog" : "event.dataset : syslog",
		"zeek" : "event.module : zeek",
		"suricata" : "event.module : suricata",
		"elasticsearch" : "event.module : elasticsearch",
		"kratos" : "event.module : kratos",
		"kibana" : "event.module : kibana",
		"windows_eventlog" : "event.module : windows_eventlog"
}
userQuery = None
#Handles Command Line Argument for UserQuery
if len(sys.argv) == 1:
	print("Error: Expected Argument <query>")
	quit()
userQuery = sys.argv[1]
if len(sys.argv) > 2:	
	if sys.argv[2] == "&":
		print("Running in Background...")
	else:
		print("Error: Too Many Arguments :: Expected 1")
		quit()
if not validQueries.__contains__(userQuery):
	print("Error: Invalid Query :: Try: ")
	for key in validQueries:
		print(key)
	quit()


#Count for file names, can hold x amount of logs in the folder at any point
count = 0

while(True):
	if(count >= 10):
		count = 0
	count += 1
	
	es = Elasticsearch(['https://10.19.89.215:9200'],
	ca_certs=False,verify_certs=False, http_auth=('jupyter','B3@+Navy!!'))
	searchContext = Search(using=es, index='*:so-*', doc_type='doc')
	#Establish connection to the security onion servers


	s = searchContext.query('query_string', query=validQueries[userQuery])
	#Establishes the module/event that is being queried




	response = s.execute()
	if response.success():
	  df = pd.DataFrame((d.to_dict() for d in s.scan()))
	#Converts query into a dataframe


	os.makedirs('./dfCSVs', exist_ok=True)  
	df.to_csv(f'./dfCSVs/out{count}.csv')
	#Sends dataframe to a csv in another folder
	
	#time.sleep(3600)

