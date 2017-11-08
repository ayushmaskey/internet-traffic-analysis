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




def create_table(tbl_name):
	sql = 'create table if not exists ' + tbl_name + '(sDate datetime, srcIP varchar(15), srcPort varchar(10), dstIP varchar(15), dstPort varchar(10), pktSize int, protocol varchar(10), flag varchar(5) );'
	c.execute(sql)
	conn.commit()

def pcap_into_list_of_tuples(file_name):
	pkts = rdpcap(file_name)
	row = []
	tuples = ()

	for pkt in pkts:
	    timestamp = datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S')
	    srcIP,srcPort = pkt.sprintf("%IP.src%"), pkt.sprintf("%TCP.sport%")
	    dstIP,dstPort = pkt.sprintf("%IP.dst%"), pkt.sprintf("%TCP.dport%")
	    pktSize, protocol = int( pkt.sprintf("%IP.len%") ), pkt.sprintf("%IP.proto%")
	    flags = pkt.sprintf("%TCP.flags%S")
	    tuples = (timestamp, srcIP, srcPort, dstIP, dstPort, pktSize, protocol, flags)
	    row.append(tuples)
	
	return row

def insert_table(pLists, tbl_name):
	    sql = 'insert into ' + tbl_name + ' values (?, ?, ?, ?, ?, ?, ?, ?)'
	    c.executemany(sql, pLists)
	    conn.commit()

def pcap_into_db(file_name, tbl_name):
	pcap_into_lists = pcap_into_list_of_tuples(file_name)
	insert_table(pcap_into_lists, tbl_name)


def main():
	create_table(inside)
	create_table(outside)

	pcap_into_db(capin, inside)
	pcap_into_db(capout, outside)

def drop_table(tbl_name):
	sql = 'drop table ' + tbl_name
	c.execute(sql)


def test():
	drop_table(inside)
	drop_table(outside)

#test()

main()


"""
S: SYN - 3 way handshake
A: ACK -success
F: FIN - finish
R: RESET - denied
P: PUSH - similar to urgent
U: URGENT - process this packet before any other
E: ECE - ECN capable
C: CWR - recieved packet with ECE flag
.: ACK
"""


c.close()
conn.close()
