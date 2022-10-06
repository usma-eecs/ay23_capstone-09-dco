from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
import pandas as pd
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#sets up the environment we are querying from, in this case security onion
es = Elasticsearch(['https://192.168.6.100:9200'],
ca_certs=False,verify_certs=False, http_auth=('jupyter','B3@+Navy!!'))
searchContext = Search(using=es, index='*:so-*', doc_type='doc')

#This tells our search context what to query, in this example we are doing a query on alerts which are of type event.dataset
s = searchContext.query('query_string', query='event.dataset:alert')

#This creates the dataframe of our query
response = s.execute()
if response.success():
    df = pd.DataFrame((d.to_dict() for d in s.scan()))
df

#The below script will get the unique destination IPs from the dataset and print the count
df['destination'].value_counts().rename_axis('unique values').to_frame('counts')
#Similarly this one does it for Source IPs
df['source'].value_counts().rename_axis('unique values').to_frame('counts')
