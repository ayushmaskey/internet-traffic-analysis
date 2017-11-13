import sqlite3

db = '../db/firewall.db'

conn = sqlite3.connect(db) 
c = conn.cursor()

rows = []

def col_agg_groupBy(tbl_name ,col_name, agg_name):
	sql = 'select ' + col_name +', ' + agg_name + ', count(*) as tot \
		from ' + tbl_name \
		+ '  group by ' + col_name \
		+ ' order by tot desc' \
		+ ' limit 10 '
	rows =  c.execute(sql)
	print( col_name + ' with ' + agg_name + ' and count!!')
	print_rows(rows)


def col_groupBy(tbl_name, col_name):
	sql = 'select ' + col_name + ', count(*) tot \
			from ' + tbl_name \
			+ ' group by ' + col_name \
			+ ' order by tot desc' \
			+ ' limit 10'
	rows =  c.execute(sql)
	print('top 10 ' + col_name +  ' by count!!')
	print_rows(rows)

def distinct_count(tbl_name, col_name):
	sql = 'select count(distinct(' + col_name + ')) \
			from ' + tbl_name 
	rows =  c.execute(sql)
	print('distinct ' + col_name + ' count!!')
	print_rows(rows)

def print_rows(rows):
	for row in rows:
		print(row)

def table_to_query(tbl_name):
	print('focus on ' + tbl_name + '!!')
	col_agg_groupBy(tbl_name, 'ip_proto', 'avg(ip_len)')
	print()
	col_groupBy(tbl_name, 'ip_dst')
	print()
	col_groupBy(tbl_name, 'ip_src')
	print()
	distinct_count(tbl_name, 'ip_dst')
	print()
	distinct_count(tbl_name, 'ip_src')
	print()
	col_groupBy(tbl_name, 'tcp_dport')
	print()
	col_groupBy(tbl_name, 'ip_src, tcp_sport, ip_dst, tcp_dport, ip_proto, ip_flags')
	print()


def main():
	# table_to_query('inside_int')
	# table_to_query('outside_int')
	table_to_query('inside_ip_warehouse')
	table_to_query('outside_ip_warehouse')


main()

c.close()
conn.close()
