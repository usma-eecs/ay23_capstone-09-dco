from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
import pandas as pd
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

es = Elasticsearch(['https://10.19.89.215:9200'],
ca_certs=False,verify_certs=False, http_auth=('jupyter','B3@+Navy!!'))
searchContext = Search(using=es, index='*:so-*', doc_type='doc')

s = searchContext.query('query_string', query='event.module:kibana')

def query():
    response = s.execute()
    if response.success():
    df = pd.DataFrame((d.to_dict() for d in s.scan()))
    df

def queryWithFiltering():
    response = s.execute()
    if response.success():
        df = pd.DataFrame(([d['metadata'],d['log'],d['type'],d['event'], d['fileset'],d['message']] for d in s))
    df.columns=['MetaData','Log','Type','Event','FileSet','Message']
    df