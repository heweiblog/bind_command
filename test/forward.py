
import subprocess,os

forward_file = '/var/drms_toggle_data/forward.zone'
conf_file = '/etc/named.conf'
rndc = '/usr/sbin/rndc'

def include_forward_file():
	forward_str = 'include ' + '"' + forward_file + '";\n'
	try:
		with open(conf_file,'r') as f:
			for s in f:
				if s == forward_str:
					print('alread add:',forward_str)
					return True
		with open(conf_file,'a') as f:
			f.write('\n')
			f.write(forward_str)
			print('first add:',forward_str)
		return True
	except Exception as e:
		print('include forward file to named conf error: {}'.format(e))
	return False
	

def include_foward_zone(data,fname,forward_str):
	try:
		with open(fname,'w') as f:
			f.write(data)
		if os.path.exists(forward_file) == False:
			with open(forward_file,'w') as f:
				print('first write:',forward_str)
				f.write(forward_str)
			return True
		with open(forward_file,'r+') as f:
			for s in f:
				if forward_str == s:
					print('already have:',forward_str)
					return True
			print('first write -> :',forward_str)
			f.write(forward_str)
		return True
	except Exception as e:
		print('include forward file to named conf error: {}'.format(e))
	return False
		

def reload_bind_conf():
	try:
		subprocess.check_call([rndc, 'reload'], cwd = '/etc')
	except Exception as e:
		logger.error('do rndc reload error: {}'.format(e))
		return False
	return True


def conf_zone_forward(domain, mode, ipv4_list, ipv6_list):
	if include_forward_file() == False:
		return False

	d1 = 'zone "{}" IN '.format(domain) + '{\n    type forward;\n'
	forward_mode = 'first' if mode == '1' else 'only'
	iplist = '{ '
	for ip in ipv4_list:
		iplist += ip + ';'
	for ip in ipv6_list:
		iplist += ip + ';'
	iplist += ' }'
	d2 = '    forward {};\n    forwarders {};\n'.format(forward_mode,iplist)+ '};'
	data = d1 + d2
	print(data)
	
	fname = '/var/drms_toggle_data/' + domain + '.forward'
	forward_str = 'include ' + '"' + fname  + '";\n'
	if include_foward_zone(data,fname,forward_str) == False:
		return False

	return reload_bind_conf()


def del_zone_forward(domain):
	fname = '/var/drms_toggle_data/' + domain + '.forward'
	forward_str = 'include ' + '"' + fname  + '";\n'
	try:
		if os.path.exists(forward_file) == False:
			return False
		l = []
		with open(forward_file,'r') as f:
			l = f.readlines()
		with open(forward_file,'w') as f:
			for s in l:
				if forward_str == s:
					continue
				f.write(s)
		print('successful del foreard zone:',domain)
		return reload_bind_conf()
	except Exception as e:
		print('del forward zone from forward file error: {}'.format(e))
	return False

conf_zone_forward('hww.com','1',['192.168.16.109'],[])
conf_zone_forward('yamu.com','1',['1.1.8.8'],[])

#del_zone_forward('hww.com')


