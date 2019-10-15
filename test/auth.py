#!/usr/bin/python
# -*- coding: utf-8 -*-

#import subprocess,os,sys
import os,sys

auth_file = '/var/named/auth/auth.zone'
conf_file = '/etc/named.conf'
rndc = '/usr/sbin/rndc'


def include_file(fname):
	f_str = 'include ' + '"' + fname + '";\n'
	try:
		with open(conf_file,'r') as f:
			for s in f:
				if s == f_str:
					return True
		with open(conf_file,'a') as f:
			f.write('\n')
			f.write(f_str)
		return True
	except Exception as e:
		print('include file to named conf error: {}'+str(e))
	return False
	

def include_zone(data,fname,zone_str,zone_file):
	try:
		with open(fname,'w') as f:
			f.write(data)
		if os.path.exists(zone_file) == False:
			with open(zone_file,'w') as f:
				f.write(zone_str)
			return True
		with open(zone_file,'r+') as f:
			for s in f:
				if zone_str == s:
					return True
			f.write(zone_str)
		return True
	except Exception as e:
		print('include zone file to named conf error: {}'+str(e))
	return False
		


def reload_bind_conf():
	try:
		#subprocess.check_call([rndc, 'reload'], cwd = '/etc')
		os.system('rndc reload')
		os.system('rndc flush')
	except Exception as e:
		logger.error('do rndc reload error: {}'+str(e))
		return False
	return True


def ns_cname_force(domain,is_cname):
	if include_file(auth_file) == False:
		return False
	
	data = 'zone "' + domain + '" IN {\n    type master;\n    file "/var/named/auth/' + domain + '.zone";\n};'
	fname = '/var/named/auth/' + domain + '.auth'
	auth_str = 'include ' + '"' + fname  + '";\n'
	
	if include_zone(data,fname,auth_str,auth_file) == False:
		return False
	
	zone_file = '/var/named/auth/' + domain + '.zone'
	#soa =  '$TTL 600\n@    IN    SOA    ns.{} admin.{} (\n    20190924\n    2H\n    4M\n    1W\n    2D\n    )\n'.format(domain,domain)
	#ns = '    IN    NS    ns\nns    IN    A    127.0.0.1\nns    IN    AAAA    ::1\n'.format(domain,domain,domain)
	#soa =  '$TTL 600\n@ IN SOA ns.{} admin.{} (20190924 2H 4M 1W 2D)\n'.format(domain,domain)
	soa =  '$TTL 600\n@ IN SOA ns.%s admin.%s (20190924 2H 4M 1W 2D)\n'%(domain,domain)
	ns = ' IN NS ns\nns IN A 127.0.0.1\nns IN AAAA ::1\n'
	zone_data = soa + ns
	if is_cname:
		zone_data += 'www IN CNAME cname.shifen.com.\n'
	with open(zone_file,'w') as f:
		f.write(zone_data)
	return True


def ns_cname_force_500(is_cname):
	for i in range(1,501):
		domain = str(i) + '.com'
		ns_cname_force(domain,is_cname)


def del_zone(domain):
	fname = '/var/named/auth/' + domain + '.auth'
	zname = '/var/named/auth/' + domain + '.zone'
	f_str = 'include ' + '"' + fname  + '";\n'
	try:
		if os.path.exists(auth_file) == False:
			return False
		l = []
		with open(auth_file,'r') as f:
			l = f.readlines()
		with open(auth_file,'w') as f:
			for s in l:
				if f_str == s:
					continue
				f.write(s)
		if os.path.exists(fname):
			os.remove(fname)
		if os.path.exists(zname):
			os.remove(zname)
		return True
	except Exception as e:
		print('del forward zone from forward file error: '+str(e))
	return False


def del_zone_500():
	for i in range(1,501):
		domain = str(i) + '.com'
		del_zone(domain)


def conf_zone_forward(domain):
	if include_file(auth_file) == False:
		return False

	d1 = 'zone "%s" IN '%(domain) + '{\n    type forward;\n'
	d2 = '    forward first;\n    forwarders { 114.114.114.114; };\n};'
	data = d1 + d2
	
	fname = '/var/named/auth/' + domain + '.auth'
	forward_str = 'include ' + '"' + fname  + '";\n'
	if include_zone(data,fname,forward_str,auth_file) == False:
		return False

	return True


def zone_forward_500():
	for i in range(1,501):
		domain = str(i) + '.com'
		conf_zone_forward(domain)


def conf_zone_stub(domain):
	if include_file(auth_file) == False:
		return False

	d1 = 'zone "%s" IN '%(domain) + '{\n    type static-stub;\n'
	d2 = '    server-addresses { 114.114.114.114; };\n};'
	data = d1 + d2
	
	fname = '/var/named/auth/' + domain + '.auth'
	forward_str = 'include ' + '"' + fname  + '";\n'
	if include_zone(data,fname,forward_str,auth_file) == False:
		return False

	return True


def zone_stub_500():
	for i in range(1,501):
		domain = str(i) + '.com'
		conf_zone_stub(domain)


use = \
'''
plaese using for example:\n
python auth.py add ns auth baidu.com
python auth.py add ns fwd baidu.com
python auth.py add ns stub baidu.com
python auth.py del ns baidu.com\n
python auth.py add ns auth 500
python auth.py add ns fwd 500
python auth.py del ns 500\n
python auth.py add cname baidu.com
python auth.py del cname baidu.com\n
python auth.py add cname 500
python auth.py del cname 500
'''

if __name__ == '__main__':
	if len(sys.argv) < 4:
		print(use)
		sys.exit(1)
	if os.path.exists('/var/named/auth') == False:
		os.mkdir('/var/named/auth')

	if sys.argv[1] == 'add':
		if sys.argv[2] == 'ns':
			if sys.argv[3] == 'auth':
				if sys.argv[4] == '500':
					ns_cname_force_500(False)
				else:
					ns_cname_force(sys.argv[4],False)
			elif sys.argv[3] == 'fwd':
				if sys.argv[4] == '500':
					zone_forward_500()
				else:
					conf_zone_forward(sys.argv[4])
			elif sys.argv[3] == 'stub':
				if sys.argv[4] == '500':
					zone_stub_500()
				else:
					conf_zone_stub(sys.argv[4])
			else:
				print(use)
				sys.exit(1)
		elif sys.argv[2] == 'cname':
			if sys.argv[3] == '500':
				ns_cname_force_500(True)
			else:
				ns_cname_force(sys.argv[3],True)
		else:
			print(use)
			sys.exit(1)
	elif sys.argv[1] == 'del' and len(sys.argv) == 4:
		if sys.argv[2] == 'ns' or sys.argv[2] == 'cname':
			if sys.argv[3] == '500':
				del_zone_500()
			else:
				del_zone(sys.argv[3])
		else:
			print(use)
			sys.exit(1)
	else:
		print(use)
		sys.exit(1)
	reload_bind_conf()


