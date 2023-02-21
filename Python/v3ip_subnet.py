from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
import pandas as pd
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import ipaddress
import csv

"""
This initial block of code connects the script to the elasticsearch api, using our credentials to log into our elasticsearch server.
    Once the connection has been established a search context is defined, specifically looking at our security onion logs (*:so-*).
    A query is then inputted, specifically requesting our custom made dataset called 'software' which maps an IP to a user agent (software) which helps define what OS is in use.
    
    Then, the fields of the query are picked with s.source. We focused on the IP and software version.
    A dataframe, using pandas, is then created for ease of parsing.
"""
es = Elasticsearch(['https://10.19.89.215:9200'],
    ca_certs=False,verify_certs=False, http_auth=('jupyter','B3@+Navy!!'))

searchContext = Search(using=es, index='*:so-*', doc_type='doc')

s = searchContext.query('query_string', query='event.dataset: software')

s = s.source(['source.ip','software.version.unparsed'])

response = s.execute()
if response.success():
    df = pd.DataFrame((d.to_dict() for d in s))

"""
The two commented lines below is to gain an understanding of how the dataframe formats our logs. It is key to working with the dataframe.
"""
# softwares = df['software'].tolist() #a dictionary of dictionaries, primary key 'version' secondary key 'unparsed'
# uniqueSourceIPs = df['source'].tolist()


"""
Using the dataframe, we take the software and IPs from the dataframe and collect it into a single list of tuples formatted as (ip, software)
"""
uniqueIP = []

df['new_col'] = list(zip(df.source,df.software))
dataLog = df['new_col'].tolist()

sourceSoftware = []
for item in dataLog:
    sof = item[1].get('version').get('unparsed')
    ip = item[0].get('ip')
    sourceSoftware.append((ip,sof))

for i, (ip,sof) in enumerate(sourceSoftware):
    if ip not in uniqueIP and not dict:
        uniqueIP.append(ip)
    elif ip not in uniqueIP and dict:
        uniqueIP.append(ip)

"""
An excel sheet of all the subnets on the EECSnet was given to us and we utilized it to map subnets and their ranges to a clearly defined name such as 'EECSnet users'
"""

df_excel = pd.read_excel('Network Configuration.xlsx')

net_names=[]
subnets = []

for column, row in df_excel.iterrows():
    network = row[0]
    sub = row[1]
    if isinstance(sub,str) and not sub[0].isdigit():
        continue
    else:
        net_names.append(network)
        subnets.append(sub)

"""
Once we transform the networks into a more easily used data type we then take our initial list of tuples with the IP and software and add an additional index that combines all aspects of our analysis. (ip, software, subnet)
"""

ip_obj = []
for (ip,sof) in sourceSoftware:
    try: 
        ip_obj.append((ipaddress.IPv4Address(ip),sof))
    except ipaddress.AddressValueError:
        ip_obj.append((ipaddress.IPv6Address(ip),sof))

ipSofNet = []
for i in range(0, len(net_names)): #Links ip to subnets
    try:
        network = ipaddress.IPv4Network(subnets[i]) #puts the subnet into ipv4network object
        for (ip,sof) in ip_obj:
            if ip in network:
                ipSofNet.append((str(ip),sof,net_names[i])) #Assigns a network to our IP in combination with our software
    except ipaddress.AddressValueError:
        continue

# for net in ipSofNet: #Prints in user-friendly format in Console
#     if isinstance(net,float):
#         continue
#     if isinstance(net,str) and net == '':
#         continue
#     elif not net[1:]:
#         continue
#     print(f"{net[0]} : {net[1]} : {net[2]}\n")

"""
Once the data has been completely transformed it is then inputted into a csv for a more digestible product.
"""

fields = ['IP', 'Software', 'Subnet']

with open('output.csv', 'w+') as csvfile:                #https://www.geeksforgeeks.org/writing-csv-files-in-python/
    csvwriter = csv.writer(csvfile)
    csvwriter.writerow(fields)
    csvwriter.writerows(ipSofNet)
    
