# Capstone: Passive Network Discovery

## Overview
A Network defenders’ visibility of their network is crucial to their success as defenders because responding to threats is highly dependent on their ability to detect these threats in the first place. Security Information and Event (SIEM) tools — like Security Onion, Microsoft Azure Sentinel, Splunk Enterprise Security, or IBM Security QRadar — serve as the ultimate collection source/location for any logs generated by a network. These applications create and process rule-based alerts, and they allow for defenders to organize their network’s log data into meaningful representations. At the United States Military Academy, the EECSNet network is running an instance of Security Onion that is collecting EECSNet logs of any traffic on the network — to include internet traffic, DNS queries and/or DHCP requests. For Security Onion, supports an alerts interface, a hunt interface to focus in on specific threats, a case feature to assign case numbers to alerts, and a PCAP interface that allows a defender to view a full packet capture of any packet collected by Security Onion. This project will deliver a prototype software product the provides passive network analysis capabilities to a defender. This product will integrate with Security Onion in order to increase acceptability into already defined network solutions. The Passive Network Analysis Tool will provide OS fingerprinting capabilities and provide a summary of the services a device tends to use based on historical traffic log data — to include DNS, HTTP/HTTPs, DHCP, and other log data. 

## Members of the team:
Cadet Claire Dworsky   
Cadet Michael Grimm   
Cadet Nicholas Liebers   
Cadet Kevin Ruthemeyer   
Cadet Alicia Torres   

## Instructors
LTC Christopher Morrell   

## Advisors
MAJ John Fernandes   

## Product Owners
Dr. Suzanne Matthews 

## Important Links
https://securityonionsolutions.com/   
https://docs.securityonion.net/en/2.3/introduction.html

# Sprint 2 Accomplishments   

## Elastic Search   
We have succeeded in dynamically querying ElasticSearch for post processing and then we can return post process data to ElasticSearch. The presets to query this data are: metadata, log, destination, source, and network.    

## Zeek   
We have a successful theoretical configure file to be pushed up to Zeek (see the local.zeek file). This Zeek file can start ingesting software data.    

# Sprint 3 Accomplishments   

## Meeting with Security Onion Contact (Mr. Di Giorgio) 
We met with Mr. Di Giorgio via Teams to ask his professional guidance on how to edit Zeek via the Salt stack. 
