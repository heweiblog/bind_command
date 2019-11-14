#!/usr/bin/python
# -*- coding: utf-8 -*-

#备份配置文件 并添加新加的配置

import os,time,shutil,ConfigParser

crm_file = '/etc/crm.ini'
nap_file = '/etc/nap.ini'
xf_file = '/etc/xf_conf'
sql_file = '/var/lib/crm.sqlite'

def back_conf():
	try:
		t_now = time.strftime('%Y%m%dT%H%M%S')

		new_file = ''.join([crm_file,'.',t_now])
		shutil.copyfile(crm_file,new_file)

		new_file = ''.join([nap_file,'.',t_now])
		shutil.copyfile(nap_file,new_file)

		new_file = ''.join([xf_file,'.',t_now])
		shutil.copyfile(xf_file,new_file)

		new_file = ''.join([sql_file,'.',t_now])
		shutil.copyfile(sql_file,new_file)

		shutil.copyfile('/var/lib/crm.sqlite.new','/var/lib/crm.sqlite')

		return True

	except Exception as e:
		print(e)

	return False


def cmp_conf(old_file,new_file):
	try:
		old = ConfigParser.ConfigParser()
		new = ConfigParser.ConfigParser()

		old.read(old_file)
		new.read(new_file)

		new_sections = new.sections()
		old_sections = old.sections()

		for s in new_sections:
			if s in old_sections:
				new_ops = new.options(s)
				old_ops = old.options(s)
				if new_ops != old_ops:
					for i in new_ops:
						if i not in old_ops:
							old.set(s,i,new.get(s,i))
			else:
				old.add_section(s)
				for i in new.options(s):
					old.set(s,i,new.get(s,i))

		with open(old_file,'w') as f:
			old.write(f)

		return True

	except Exception as e:
		print(e)

	return False


if __name__ == '__main__':
	if back_conf():
		print('back crm sql nap conf success!!!')
	if cmp_conf(crm_file,crm_file+'.new'):
		print('cmp crm conf success!!!')
	if cmp_conf(nap_file,nap_file+'.new'):
		print('cmp nap conf success!!!')
	if cmp_conf(xf_file,xf_file+'.new'):
		print('cmp xf conf success!!!')

