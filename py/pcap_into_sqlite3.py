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
	sql = 'create table if not exists ' + tbl_name + \
		'(sDate datetime, eth_dst varchar(17), eth_src varchar(17), eth_type varchar(4), \
		ip_ver smallint, ip_ihl smallint, ip_tos varchar(5), ip_len int, ip_id int, ip_flags varchar(3), \
		ip_frag smallint, ip_ttl int, ip_proto varchar(5), ip_chksum varchar(6), ip_src varchar(15), ip_dst varchar(15), \
		tcp_sPort varchar(5), tcp_dPort varchar(5), tcp_seq int, tcp_ack int, tcp_dataofs int, tcp_reserved int, tcp_flags varchar(3), \
		tcp_window int, tcp_chksum varchar(6), tcp_urgptr int)'
	c.execute(sql)
	conn.commit()

def pcap_into_list_of_tuples(file_name):
	pkts = rdpcap(file_name)
	row = []
	tuples = ()

	for pkt in pkts:
	    timestamp = datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S')
	   
	    eth_dst = pkt.sprintf("%Ether.dst%")
	    eth_src = pkt.sprintf("%Ether.src%")
	    eth_type = pkt.sprintf("%Ether.type%")
	    
	    ip_ver = pkt.sprintf("%IP.version%")
	    ip_ihl = pkt.sprintf("%IP.ihl%")
	    ip_tos = pkt.sprintf("%IP.tos%")
	    ip_len = pkt.sprintf("%IP.len%")
	    ip_id = pkt.sprintf("%IP.id%")
	    ip_flags = pkt.sprintf("%IP.flags%")
	    ip_frag = pkt.sprintf("%IP.frag%")
	    ip_ttl = pkt.sprintf("%IP.ttl%")
	    ip_proto = pkt.sprintf("%IP.proto%")
	    ip_chksum = pkt.sprintf("%IP.chksum%")
	    ip_src = pkt.sprintf("%IP.src%")
	    ip_dst = pkt.sprintf("%IP.dst%")

	    tcp_sPort = pkt.sprintf("%TCP.sport%")
	    tcp_dPort = pkt.sprintf("%TCP.dport%")
	    tcp_seq = pkt.sprintf("%TCP.seq%")
	    tcp_ack = pkt.sprintf("%TCP.ack%")
	    tcp_dataofs = pkt.sprintf("%TCP.dataofs%")
	    tcp_reserved = pkt.sprintf("%TCP.reserved%")
	    tcp_flags = pkt.sprintf("%TCP.flags%")
	    tcp_window =  pkt.sprintf("%TCP.window%")
	    tcp_chksum = pkt.sprintf("%TCP.chksum%")
	    tcp_urgptr = pkt.sprintf("%TCP.urgptr%")

	    tuples = (timestamp, eth_dst, eth_src, eth_type, ip_ver, ip_ihl, ip_tos, ip_len, ip_id, ip_flags, ip_frag, ip_ttl, ip_proto, ip_chksum, ip_src, ip_dst, tcp_sPort, tcp_dPort, tcp_seq, tcp_ack, tcp_dataofs, tcp_reserved, tcp_flags, tcp_window, tcp_chksum, tcp_urgptr)
	    row.append(tuples)
		print(pkt.id)
	return row

def insert_table(pLists, tbl_name):
	    sql = 'insert into ' + tbl_name + ' values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
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


def drop_all_table():
	drop_table(inside)
	drop_table(outside)

def only_pcap():
	x = pcap_into_list_of_tuples(capin)
	print(x[105])

# drop_all_table()
 only_pcap()

#main()


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
