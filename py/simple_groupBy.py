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

# build and return sql statement
def sql_statement(tbl_name, col_name, group_by='', order_by='', limit_int=''):
	group_by_str = ' group by ' + group_by 
	order_by_str = ' order by ' + order_by
	limit_int_str = ' limit ' + limit_int

	sql = 'select ' + col_name \
			+ ' from ' + tbl_name \
			+ (group_by_str if group_by != '' else '') \
			+ (order_by_str if order_by != '' else '') \
			+ (limit_int_str if limit_int != '' else '')
			
	sql_execute(sql)

def sql_execute(sql):
	rows = []
	rows = c.execute(sql)
	print_rows(rows)

def print_rows(rows):
	for row in rows:
		# dns_lookup(row[0])
		print(row)

def sql_parameters():
	sql = sql_statement('inside_ip_warehouse', 'ip_dst, count(*) tot', 'ip_dst', '', '10')
	

def main():
	# table_to_query('inside_int')
	# table_to_query('outside_int')
	# table_to_query('inside_ip_warehouse')
	# table_to_query('outside_ip_warehouse')
	sql_parameters()


main()

c.close()
conn.close()
