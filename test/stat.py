#!/usr/bin/python
# -*- coding: utf-8 -*-

import os,time,sys,threading

stat_file = '/sys/kernel/nap/stat'
cache_file = '/sys/kernel/nap/cache_stat'
recursion_file = '/sys/kernel/nap/recursion_stat'


def read_stat():
	try:
		with open(stat_file,'r') as f:
			print(f.read())
	except Exception as e:
		print(e)


def read_stat():
	try:
		with open(stat_file,'r') as f:
			print(f.read())
		with open(recursion_file,'r') as f:
			print(f.read())
		with open(cache_file,'r') as f:
			print(f.read())
		print('------device stats-----------------')
		os.system('uptime')
		print('------mem stats--------------------')
		os.system('free')
	except Exception as e:
		print(e)


def print_stat(is_ipv4):
	try:
		with open(stat_file,'r') as f:
			for s in f:
				if s.find('netlink_conf') > 0:
					break
				l = list(set(s.split('  ')))
				if '' in l:
					l.remove('')
				if '\n' in l:
					l.remove('\n')
				if len(l) == 1 and '-' in l[0]:
					print(l[0]),
					continue
				elif len(l) > 1:
					for i in range(len(l)):
						if 'v6' in l[i] or 'V6' in l[i]:
							if is_ipv4 == False:
								if l[i][0] == ' ':
									print l[i][1:]
								else:
									print l[i]
						else:
							if is_ipv4:
								print l[i]
	except Exception as e:
		print(e)


def stat_ipv4_ipv6():
	while True:
		num = input()
		if num == 4:
			print_stat(True)
		elif num == 6:
			print_stat(False)
		


if __name__ == '__main__':
	interval = 2
	try:
		if len(sys.argv) > 1:
			interval = int(sys.argv[1])
	except Exception as e:
		print(e)
		sys.exit(1)

	threading._start_new_thread(stat_ipv4_ipv6,())
	while True:
		time.sleep(interval)
		read_stat()
