import json,subprocess,os,pwd
from iscpy.iscpy_dns.named_importer_lib import *

conf_file = '/etc/named.conf'
rndc = '/usr/sbin/rndc'

def test():
	try:
		with open(conf, 'r') as f:
			data = f.read()
			print(data)
			named_data = MakeNamedDict(data)
			print(named_data)
	except Exception as e:
		print(e)

#test()

'''
f = open("/etc/named.conf",'r')
data = f.read() 
f.close()
#print('named.conf----->',type(data),'\n',data,'\n')
print('named.conf----->',type(data),'\n')

named_data = MakeNamedDict(data)

options =  named_data['options']['options']

if 'dnssec-enable' in options:
	print('dnssec-enable = ',options['dnssec-enable'])
if 'dnssec-validation' in options:
	print('dnssec-validation = ',options['dnssec-validation'])
if 'dnssec-lookaside' in options:
	print('dnssec-lookaside = ',options['dnssec-lookaside'])



for k in named_data:
	print('key=',k,'val=',named_data[k],'\n')
	for i in named_data[k]:
		print('key=',i,'val=',named_data[k][i],'\n')
'''

def get_dnssec_status():
	try:
		dnssec = {}
		with open(conf_file,'r') as f:
			_data = f.read() 
		named_data = MakeNamedDict(_data)
		options =  named_data['options']['options']
		dnssec['dnssec-enable'] = options['dnssec-enable']
		dnssec['dnssec-validation'] = options['dnssec-validation']
		dnssec['dnssec-lookaside'] = options['dnssec-lookaside']
		return dnssec 
	except Exception as e:
		print('get dnssec conf error: {}'.format(e))
	return {'dnssec-enable':'no','dnssec-validation':'no','dnssec-lookaside':'auto'}


def reload_bind_conf():
	try:
		subprocess.check_call([rndc, 'reload'], cwd = '/etc')
		subprocess.check_call([rndc, 'flush'], cwd = '/etc')
	except Exception as e:
		print('do rndc reload error: {}'.format(e))
		return False
	return True


def dnssec_on_off(on):
	try:
		conf_str = ''
		with open(conf_file,'r') as f:
			for l in f:
				if 'dnssec-enable' in l:
					if on:
						l = '    dnssec-enable yes;\n'
					else:
						l = '    dnssec-enable no;\n'
				elif 'dnssec-validation' in l:
					if on:
						l = '    dnssec-validation yes;\n'
					else:
						l = '    dnssec-validation no;\n'
				elif 'dnssec-lookaside' in l:
					l = '    dnssec-lookaside auto;\n'
				conf_str += l
		with open(conf_file,'w') as f:
			f.write(conf_str)
		os.chown(conf_file,pwd.getpwnam('root').pw_gid,pwd.getpwnam('named').pw_gid)
	except Exception as e:
		print('reconf named.conf error: {}'.format(e))
	return reload_bind_conf()


def cancel_dnssec(dnssec):
	try:
		conf_str = ''
		with open(conf_file,'r') as f:
			for l in f:
				if 'dnssec-enable' in l:
					l = '    dnssec-enable %s;\n'%dnssec['dnssec-enable']
				elif 'dnssec-validation' in l:
					l = '    dnssec-validation %s;\n'%dnssec['dnssec-validation']
				elif 'dnssec-lookaside' in l:
					l = '    dnssec-lookaside %s;\n'%dnssec['dnssec-lookaside']
				conf_str += l
		with open(conf_file,'w') as f:
			f.write(conf_str)
		os.chown(conf_file,pwd.getpwnam('root').pw_gid,pwd.getpwnam('named').pw_gid)
	except Exception as e:
		print('reconf named.conf error: {}'.format(e))
	return reload_bind_conf()
	

status = get_dnssec_status()
print(status)
print(dnssec_on_off(True))
print(get_dnssec_status())
print(cancel_dnssec(status))
print(get_dnssec_status())


