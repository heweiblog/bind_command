#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os, sys, re, time, datetime, logging, random, string, logging.handlers, gzip, paramiko
import multiprocessing, subprocess, requests, urllib3, uuid
from threading import Timer
from configparser import ConfigParser
from Crypto.Cipher import AES

from iscpy.iscpy_dns.named_importer_lib import *
import base64, hashlib, zlib, json, lxml.etree, pexpect, dns, dns.resolver

from time import sleep
import threading, binascii, xml.dom.minidom, shutil

from daemon import Daemon
from waj import *

def get_transfer_ip_and_delay(soa):
	target = 'serial ' + str(soa)
	try:
		with open(run_file) as f:
			l = f.readlines()
			for i in range(len(l)):
				if l[i].find(target) > 0:
					for v in l[i:]:
						if v.find('Transfer completed') > 0:
							res = v
							return int(1000*float(res.split(', ')[-1].split(' ')[0])) , res.split('#')[0].split(' ')[-1]

	except Exception as e:
		logger.warning('get transfer ip and delay error:'+str(e))
	return 0,'0.0.0.0'
		

def get_server_from_file():
	try:
		server = ''
		with open(standard_source, 'r') as f:
			data = f.read()
			named_data = MakeNamedDict(data)
			servers = named_data['orphan_zones']['.']['options']['masters']
			for ip in servers:
				server += ip + ','
		with open(exigency_source, 'r') as f:
			data = f.read()
			named_data = MakeNamedDict(data)
			servers = named_data['orphan_zones']['.']['options']['masters']
			for ip in servers:
				server += ip + ','
		return server[:-1]

	except Exception as e:
		logger.warning('get server from root source file error:'+str(e))

	return ''


def get_transfer_ip_and_delay_from_file(soa):
	try:
		with open(root_source, 'r') as f:
			data = f.read()
			named_data = MakeNamedDict(data)
			servers = named_data['orphan_zones']['.']['options']['masters']
			dns_query = dns.message.make_query('.', 'SOA')
			for ip in servers:
				begin = datetime.datetime.now()
				res = dns.query.udp(dns_query, ip, port = 53,timeout = 2)
				end = datetime.datetime.now()
				for i in res.answer:
					for j in i.items:
						if j.serial == soa:
							return (end - begin).microseconds//1000,ip
	except Exception as e:
		logger.warning('get transfer ip and delay from swotch_root.zone error:'+str(e))
	return 0,'0.0.0.0'


def get_root_file_size():
	try:
		with open(root_source, 'r') as f:
			data = f.read()
			named_data = MakeNamedDict(data)
			return os.path.getsize(named_data['orphan_zones']['.']['file'])
	except Exception as e:
		logger.warning('get root_copy file size error:'+str(e))
	return 0


def upload_root_run_data(soa):
	result = 'get source or size error'
	delay,ip = get_transfer_ip_and_delay(soa)
	if delay == 0 and ip == '0.0.0.0': 
		delay,ip = get_transfer_ip_and_delay_from_file(soa)
	size = get_root_file_size()
	if delay != 0 and ip != '0.0.0.0' and size != 0:
		result = 'success'
	
	server = get_server_from_file()

	timestamp = time.strftime('%Y-%m-%d %H:%M:%S')

	root_soa_str_data = dns_id + '|' + root_copy_room_id + '|' + server_id + '|' + server + '|' + ip\
	+ '|' + timestamp + '|' + result + '|' + str(size) + '|' + str(soa) + '|' + str(delay)

	file_name = 'zoneOperation_full_' + dns_id + '_0_' + time.strftime('%Y%m%d%H%M%S') + '.gz'

	logger.info(root_soa_str_data)
	try:
		cache_dir = '/var/drms_toggle_data/'
		with gzip.open(cache_dir + file_name, "wb") as f:
			f.write(bytes(root_soa_str_data, 'utf-8'))
		upload_to_ftp(cache_dir,file_name,'15')
	except Exception as e:
		logger.error('upload root resove data error:'+str(e))


def get_root_copy_soa():
	try:
		dns_query = dns.message.make_query('.', 'SOA')
		res = dns.query.udp(dns_query, '127.0.0.1', port = 53,timeout = 2)
		for i in res.answer:
			for j in i.items:
				return j.serial
	except Exception as e:
		logger.warning('Server exception get soa error:'+str(e))
	return 0


def check_soa_and_upload():
	global loop_count
	now_soa,root_soa = 0,0
	while True:
		if server_type == 'root_copy' and loop_count % 60 == 0:
			now_soa = get_root_copy_soa()
			if now_soa > 0:
				if root_soa != now_soa:
					root_soa = now_soa
					upload_root_run_data(now_soa)
				if loop_count  >= 900 and int(share_delay.value) == 900:
					upload_root_run_data(now_soa)
			else:
				logger.warning('dns server can not work please check')
		if loop_count >= 900:
			loop_count = 0
		sleep(1)
		loop_count += 1



class DrmsToggle(Daemon):
	def run(self):
		logger.info('main process start at: %s' % time.ctime())

		threading._start_new_thread(xgj_main_task,())
		threading._start_new_thread(waj_main_task,())
		check_soa_and_upload()

		logger.info('main process end at: %s' % time.ctime())
 

if __name__ == '__main__':
	drms_toggle = DrmsToggle('/var/drms_toggle_data/drms_toggle.pid')
	drms_toggle.start()
