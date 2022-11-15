from elasticsearch import Elasticsearch
from elasticsearch import helpers
from elasticsearch_dsl import Search
import pandas as pd
import urllib3
import os
import numpy as np
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  
#redirect stderr to devnull
fd = os.open('/dev/null',os.O_WRONLY)
os.dup2(fd,2)

#Establishes connection to where we are querying from
es = Elasticsearch(['https://10.19.89.215:9200'],
ca_certs=False,verify_certs=False, http_auth=('jupyter','B3@+Navy!!'))
searchContext = Search(using=es, index='*:so-*', doc_type='doc')

print("Connection Established")

#Defines search context
s = searchContext.query('query_string',query='event.module: kratos')
print("Search Context Defined")
#Creates Dataframe
response = s.execute()
if response.success():
	df = pd.DataFrame((d.to_dict() for d in s.scan()))

print("DataFrame Established")

def safe_value(field_val):
	return field_val if not pd.isna(field_val) else "Other"

df = df.dropna()
print("DataFrame Cleaned")

use_these_keys = ['metadata','log','destination','source','network']

def filterKeys(document):
	return {key: document[key] for key in use_these_keys}

#Creates a generator type. This is the accepted type by the ES database
def doc_generator(df):
	df_iter = df.iterrows()
	for index, document in df_iter:
		yield {
			"_index":'*:so-*',
			"_type":"_doc",
			"_id": f"{document['id'] + index}",
			"_source":filterKeys(document),
		}
	#raise StopIteration

#sends dataframe to elasticsearch database
helpers.bulk(es, doc_generator(df))

print("Sent to ES")
