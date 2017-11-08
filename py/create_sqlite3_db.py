import sqlite3
from scapy.all import rdpcap
from datetime import datetime


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
	insert_table(capin, inside)
	insert_table(capout, outside)


def create_table(tbl_name):
	sql = 'create table if not exists ' + tbl_name + '(sDate datetime, srcIP char(15), srcPort char(7), dstIP char(15), dstPort char(7), pktSize char(10), protocol char(7) );'
	print(sql)
	c.execute(sql)
	conn.commit()


def insert_table(file_name, tbl_name):
	pkts = rdpcap(file_name)

	for pkt in pkts:
	    timestamp = datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S')
	    srcIP,srcPort = pkt.sprintf("%IP.src%"), pkt.sprintf("%TCP.sport%")
	    dstIP,dstPort = pkt.sprintf("%IP.dst%"), pkt.sprintf("%TCP.dport%")
	    pktSize, protocol = pkt.sprintf("%IP.len%"),pkt.sprintf("%IP.proto%")
	    
	    sql = 'insert into ' + tbl_name + '(sDate, srcIP, srcPort, dstIP, dstPort, pktSize, protocol) values (%s, %s, %s, %s, %s, %s, %s )' % (timestamp, srcIP, srcPort, dstIP, dstPort, pktSize, protocol)
	    print(sql)
	    c.execute(sql)
	    c.commit()

initialize_db()

c.close()
conn.close()