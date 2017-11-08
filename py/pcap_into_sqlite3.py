import sqlite3
from scapy.all import rdpcap
from datetime import datetime
from pprint import pprint


db = '../db/firewall.db'

conn = sqlite3.connect(db) 
c = conn.cursor()

capin = "../tftp/in"
capout = "../tftp/out"

inside = 'inside_int'
outside = 'outside_int'

def initialize_db():
	create_table(inside)
	create_table(outside)

	pcap_into_lists_inside = pcap_into_list(capin)
	insert_table(pcap_into_lists_inside, inside)

	pcap_into_lists_outside = pcap_into_list(capin)
	insert_table(pcap_into_lists_outside, outside)


def create_table(tbl_name):
	sql = 'create table if not exists ' + tbl_name + '(sDate datetime, srcIP varchar(15), srcPort varchar(10), dstIP varchar(15), dstPort varchar(10), pktSize int, protocol varchar(10) );'
	c.execute(sql)
	conn.commit()

def pcap_into_list(file_name):
	pkts = rdpcap(file_name)
	row = []
	tuples = ()

	for pkt in pkts:
	    timestamp = datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S')
	    srcIP,srcPort = pkt.sprintf("%IP.src%"), pkt.sprintf("%TCP.sport%")
	    dstIP,dstPort = pkt.sprintf("%IP.dst%"), pkt.sprintf("%TCP.dport%")
	    pktSize, protocol = int( pkt.sprintf("%IP.len%") ), pkt.sprintf("%IP.proto%")

	    tuples = (timestamp, srcIP, srcPort, dstIP, dstPort, pktSize, protocol)
	    row.append(tuples)
	
	return row

def insert_table(pLists, tbl_name):
	    sql = 'insert into ' + tbl_name + ' values (?, ?, ?, ?, ?, ?, ?)'
	    c.executemany(sql, pLists)
	    conn.commit()

	    
initialize_db()

c.close()
conn.close()
