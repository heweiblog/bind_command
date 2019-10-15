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


try:
	config = ConfigParser()
	config.read('/etc/drms_toggle.ini')
	listen_port = config.getint('network', 'port')
	ackhost = config.get('network', 'ackhost')
	ackport = config.getint('network', 'ackport')

	gPwd = config.get('security', 'secret')
	dataPwd = config.get('security', 'data_pwd')
	gAESKey = config.get('security', 'aes_key')
	gAESIV = config.get('security', 'aes_iv')

	soft = config.get('dns', 'soft')

	work_dir = config.get('bind', 'dir')
	conf_file = config.get('bind', 'conf_file')
	forward_file = '/var/drms_toggle_data/forward.force'
	ns_file = '/var/drms_toggle_data/ns.force'
	cname_file = '/var/drms_toggle_data/cname.force'
	rndc = config.get('bind', 'rndc')
	switch = config.get('bind', 'switch')
	std = config.get('bind', 'std')
	local = config.get('bind', 'local')

	yrdns_switch = config.get('yrdns', 'switch')
	yrdns_std = config.get('yrdns', 'std')
	yrdns_local = config.get('yrdns', 'local')

	run_file = config.get('root-copy', 'run_file')
	root_source = config.get('root-copy', 'root_source')
	standard_source = config.get('root-copy', 'standard_source')
	exigency_source = config.get('root-copy', 'exigency_source')
	root_copy_room_id = config.get('root-copy', 'room_id')

	ftp_ip = config.get('ftp', 'ip')
	ftp_port = config.getint('ftp', 'port')
	ftp_user = config.get('ftp', 'user')
	ftp_pwd = config.get('ftp', 'pwd')
	ftp_dir = config.get('ftp', 'dir')

	server_type = config.get('server', 'server_type')
	zone_room_id = config.get('server', 'zone_room_id')
	node_name = config.get('server', 'node_name')
	server_id = config.get('server', 'server_id')
	dns_id = config.get('server', 'dns_id')

	loop_count = 0
	share_delay = multiprocessing.Value('d', 86400)

	waj_command_cache = {}
	waj_conf = {}
	network = {}
	network['ip'] = config.get('local-net', 'ip')
	network['port'] = config.getint('local-net', 'port')
	network['crt'] = config.get('local-net', 'crt')
	network['key'] = config.get('local-net', 'key')
	waj_conf['net'] = network
	
	upload = {}
	upload['url'] = config.get('upload', 'url')
	upload['data_tag'] = config.get('upload', 'data_tag')
	waj_conf['upload'] = upload

	security = {}
	security['user_pwd'] = config.get('waj-security', 'user_pwd')
	security['data_pwd'] = config.get('waj-security', 'data_pwd')
	security['aes_key'] = config.get('waj-security', 'aes_key')
	security['aes_iv'] = config.get('waj-security', 'aes_iv')
	security['hash_mode'] = config.get('waj-security', 'hash_mode')
	security['encrypt_mode'] = config.get('waj-security', 'encrypt_mode')
	security['compress_mode'] = config.get('waj-security', 'compress_mode')
	waj_conf['security'] = security

	logger = logging.getLogger('drms_toggle')
	logger.setLevel(level = logging.INFO)
	handler = logging.FileHandler("/var/log/drms_toggle.log")
	handler.setLevel(logging.INFO)
	formatter = logging.Formatter('%(asctime)s|%(lineno)d|%(levelname)s|%(message)s')
	handler.setFormatter(formatter)
	logger.addHandler(handler)

except Exception as e:
	print('load conf or create log error:'+str(e))
	sys.exit(1)


class AESCipher:
	def __init__(self, key, iv):
		self.key = key 
		self.iv = iv 
	def __pad(self, text):
		text_length = len(text)
		amount_to_pad = AES.block_size - (text_length % AES.block_size)
		if amount_to_pad == 0:
			amount_to_pad = AES.block_size
		pad = chr(amount_to_pad)
		return text + (pad * amount_to_pad).encode('utf-8')
	def __unpad(self, text):
		pad = text[-1] #ord(text[-1])
		return text[:-pad]
	def encrypt(self, raw):
		raw = self.__pad(raw)
		cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
		return cipher.encrypt(raw)
	def decrypt(self, enc):
		cipher = AES.new(self.key, AES.MODE_CBC, self.iv )
		return self.__unpad(cipher.decrypt(enc))#.decode("utf-8"))


def aesDecode(raw):
	aes = AESCipher(gAESKey, gAESIV)
	return aes.decrypt(raw)


def upload_to_ftp(dir_name,file_name,data_type):
	dir_list = []
	if ftp_dir.find('/') >= 0:
		dir_list = ftp_dir.split('/')
		del(dir_list[0])
	else:
		dir_list = [ftp_dir]
	try:
		transport = paramiko.Transport((ftp_ip, ftp_port))
		transport.connect(username = ftp_user, password = ftp_pwd)
		transport.banner_timeout = 30
		sftp = paramiko.SFTPClient.from_transport(transport)
		listdir = sftp.listdir('/')
		for i in dir_list:
			if i not in listdir:
				sftp.mkdir(i)
				logger.warning('ftp upload dir not exit and create -> '+i)
			sftp.chdir(i)
			listdir = sftp.listdir('.')
		if data_type not in listdir:
			sftp.mkdir(data_type)
			logger.warning('ftp upload dir not exit and create -> '+data_type)
		sftp.chdir(data_type)
		listdir = sftp.listdir('.')
		data_dir = time.strftime('%Y-%m-%d')
		if data_dir not in listdir:
			sftp.mkdir(data_dir)
			logger.warning('ftp upload dir not exit and create -> '+data_dir)
		sftp.chdir(data_dir)
		sftp.put(dir_name+file_name,file_name)
		sftp.close()
		transport.close()
	
	except Exception as e:
		logger.error('upload to sftp error:'+str(e))
		return False

	logger.info('upload file %s success' % file_name)
	return True


def switch_named_file(target,source,clear):
	if os.path.exists(target) == False:
		logger.error('[%d] file[%s] not exist error!' % os.getpid(),target)
		return False

	if source == root_source:
		try:
			with open(target, 'r') as f:
				data = f.read()
				named_data = MakeNamedDict(data)
				slave_file = named_data['orphan_zones']['.']['file']
			if os.path.exists(slave_file):
				os.remove(slave_file)
		except Exception as e:
			logger.warning('del root copy slave file catch exption {}'.format(e))

	try:
		subprocess.check_call(['ln', '-f', '-s', target, source], cwd = '/etc')
	except subprocess.CalledProcessError:
		logger.error('create link path error!')
		return False
	
	if soft == 'bind':
		try:
			subprocess.check_call([rndc, 'reconfig'], cwd = '/etc')
		except subprocess.CalledProcessError:
			logger.error('rndc reconfig error!')
			return False
		if clear == '1':
			try:
				subprocess.check_call([rndc, 'flush'], cwd = '/etc')
				logger.info('swutch and clear cache')
			except subprocess.CalledProcessError:
				logger.error('rndc flush error!')
				return False
	elif soft == 'yrdns':
		try:
			subprocess.check_call(['service', 'yrdnsd', 'restart'], cwd = '/etc')
		except subprocess.CalledProcessError:
			logger.error('yrdns restart error!')
			return False
	
	logger.info('root switch to {}'.format(target))
	return True


def check_root_copy_data_source(is_exigency):
	d1,d2='',''
	with open(root_source,'r') as f:
		d1 = f.read()
	if is_exigency:
		with open(exigency_source,'r') as f:
			d2 = f.read()
	else:
		with open(standard_source,'r') as f:
			d2 = f.read()
	if d1 == d2:
		return True
	return False


def getXmlValue(dom, root, xpath):
	ml = dom.getElementsByTagName(root)[0]
	node = ml.getElementsByTagName(xpath)[0]
	for n in node.childNodes:
		nodeValue = n.nodeValue
		return nodeValue
	return None


def xmlget(root, xpath):
	lst = root.xpath(xpath)
	if lst and lst[0].text:
		return lst[0].text
	return None



