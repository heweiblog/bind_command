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
import threading, binascii, xml.dom.minidom, shutil, xmltodict

from spyne import ServiceBase
from spyne.protocol.soap import Soap11
from spyne.decorator import rpc
from spyne.model.primitive import Integer, Int, Long, Unicode
from spyne.model.complex import Iterable
from spyne.application import Application
from spyne.util.wsgi_wrapper import WsgiMounter
from spyne.util.etreeconv import root_etree_to_dict
from wsgiref.simple_server import make_server

import osa

from pub import *

def gen_commandack_result(dnsId, cmdId, cmdType, resultCode):
	xml = u'''\
<?xml version="1.0" encoding="UTF-8"?>
<dnsCommandAck>
    <dnsId>%s</dnsId>
    <commandAck>
        <commandId>%s</commandId>
        <type>%d</type>
        <resultCode>%d</resultCode>
        <appealContent></appealContent>
        <msgInfo></msgInfo>
    </commandAck>
    <timeStamp>%s</timeStamp>
</dnsCommandAck>
''' % (dnsId, cmdId, cmdType, resultCode, time.strftime('%Y-%m-%d %H:%M:%S'))
    
	return xml


def dnsCommandAck(commandType, commandSequence, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm, resultCode):

	sleep(1) 
	result = bytes(gen_commandack_result(dnsId, commandSequence, commandType, 0 if resultCode==0 else 2), encoding = 'utf-8')
	randVal = bytes(''.join(random.sample(string.ascii_letters, 20)), 'utf-8')
	lPwd = bytes(gPwd,'utf-8')
	lData = bytes(dataPwd,'utf-8')

	if hashAlgorithm == 0: 
		_hashed_pwd = lPwd + randVal
		pwdHash = base64.b64encode(_hashed_pwd)
	elif hashAlgorithm == 1: 
		_hashed_pwd = hashlib.md5(lPwd + randVal).digest()
		pwdHash = base64.b64encode(binascii.b2a_hex(_hashed_pwd))
	elif hashAlgorithm == 2: 
		_hashed_pwd = hashlib.sha1(lPwd + randVal).digest()
		pwdHash = base64.b64encode(binascii.b2a_hex(_hashed_pwd))

	if compressionFormat == 0: _compressed_result = result
	elif compressionFormat == 1: _compressed_result = zlib.compress(result)

	e = AESCipher(gAESKey, gAESIV)
	if (gAESKey is not None) and (encryptAlgorithm == 1): 
		_encrypted_result = e.encrypt(_compressed_result)
	else: _encrypted_result = _compressed_result
    
	result = base64.b64encode(_encrypted_result)

	if hashAlgorithm == 0: 
		_hashed_result = _compressed_result + lData
		resultHash = base64.b64encode(_hashed_result)
	elif hashAlgorithm == 1: 
		_hashed_result = hashlib.md5(_compressed_result + lData).digest()
		resultHash = base64.b64encode(binascii.b2a_hex(_hashed_result))
	elif hashAlgorithm == 2: 
		_hashed_result = hashlib.sha1(_compressed_result + lData).digest()
		resultHash = base64.b64encode(binascii.b2a_hex(_hashed_result))

	commandVersion = 'v0.1'

	cl = osa.Client('http://%s:%d/DNSWebService/dnsCommandAck?wsdl' % (ackhost, ackport))
    
	try:
		r = cl.service.dns_commandack(dnsId, str(randVal, encoding='utf-8'), 
		str(pwdHash,encoding='utf-8'), str(result,encoding = 'utf-8'),
		str(resultHash,encoding='utf-8'), encryptAlgorithm, hashAlgorithm,compressionFormat, commandVersion)

		dom = xml.dom.minidom.parseString(r)
		res = int(getXmlValue(dom, "return", "resultCode"))
		logger.info('return to drms dnsCommandAck result_code {}'.format(res))

		if res == 0:
			logger.info('return to drms dnsCommandAck success')
		else:
			logger.error('return to drms dnsCommandAck failed')

	except Exception as e:
		logger.warning('dnsCommandAck exception:'+str(e))
		l = str(e).split('/')
		if 'tmp' in l:
			d = '/tmp/' + l[-2]
			if os.path.exists(d) == False:
				os.mkdir(d)
				logger.info('mkdir '+d+' and copy /var/drms_toggle_data/base_library.zip')
				shutil.copyfile('/var/drms_toggle_data/base_library.zip',d+'/base_library.zip')

			r = cl.service.dns_commandack(dnsId, str(randVal, encoding='utf-8'), 
			str(pwdHash,encoding='utf-8'), str(result,encoding = 'utf-8'),
			str(resultHash,encoding='utf-8'), encryptAlgorithm, hashAlgorithm,compressionFormat, commandVersion)

			dom = xml.dom.minidom.parseString(r)
			res = int(getXmlValue(dom, "return", "resultCode"))

			if res == 0:
				logger.info('return to drms dnsCommandAck success')
			else:
				logger.error('return to drms dnsCommandAck failed')
		else:
			logger.warning('dnsCommandAck exception:'+str(e))
			return -1


def genResult(rcode, commandType, commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm):
	lookaside = {
		0 : 'Done',
		1 : 'De-cryption error',
		2 : 'Certification error',
		3 : 'De-compression error',
		4 : 'Invalid type',
		5 : 'Malformed content',
		900 : 'Other error, try again'                                                        
	}
    
	xml = u'''<?xml version="1.0" encoding="UTF-8"?>
	<return>
		<resultCode>%d</resultCode>
		<msg>%s</msg>
	</return>''' % (rcode, lookaside[rcode])
    
	if commandId:    
		threading._start_new_thread(dnsCommandAck, (commandType, commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm, rcode))

	return xml


def certificate(pwdHash, randVal, hashAlgorithm):                                             
	if hashAlgorithm == 0: 
		raw = gPwd + randVal 
		return pwdHash == base64.b64encode(raw.encode('utf-8')).decode('utf-8')
	elif hashAlgorithm == 1: raw = hashlib.md5((gPwd + randVal).encode()).digest()
	elif hashAlgorithm == 2: raw = hashlib.sha1((gPwd + randVal).encode()).digest()
	else: return False
	return pwdHash == base64.b64encode(binascii.b2a_hex(raw)).decode()



def deCMDPre(command, compressionFormat, commandHash, hashAlgorithm, encryptAlgorithm):
	raw = base64.b64decode(command.encode('utf-8'))
	if (gAESKey is not None) and (encryptAlgorithm == 1):
		data = aesDecode(raw)
	else: data = raw
	if hashAlgorithm == 0: hashed = data + dataPwd.encode('utf-8')
	elif hashAlgorithm == 1: hashed = hashlib.md5((data + dataPwd.encode('utf-8'))).digest()
	elif hashAlgorithm == 2: hashed = hashlib.sha1((data + dataPwd.encode('utf-8'))).digest()
	else: return None
	if hashAlgorithm == 0:
		if base64.b64encode(hashed).decode('utf-8') != commandHash:
			return None
	else:
		if base64.b64encode(binascii.b2a_hex(hashed)).decode('utf-8') != commandHash:
			return None
	if compressionFormat == 0: cmd = data
	elif compressionFormat == 1: cmd = zlib.decompress(data)
	return cmd


def xmlget(root, xpath):
	lst = root.xpath(xpath)
	if lst and lst[0].text:
		return lst[0].text
	return None


def upload_switch_result(target, dnsId, commandId):
	switch_data = dns_id + '|' + commandId + '|' + zone_room_id + '|' + node_name

	if target == std or target == yrdns_std:
		switch_data += '|1|' + time.strftime('%Y-%m-%d %H:%M:%S') + '||' + time.strftime('%Y-%m-%d %H:%M:%S')
	elif target == local or target == yrdns_local:
		switch_data += '|2|' + time.strftime('%Y-%m-%d %H:%M:%S') + '|' + time.strftime('%Y-%m-%d %H:%M:%S') + '|'
	elif target == standard_source:
		switch_data += '|1|' + time.strftime('%Y-%m-%d %H:%M:%S') + '||' 
	elif target == exigency_source:
		switch_data += '|2|' + time.strftime('%Y-%m-%d %H:%M:%S') + '||' 

	file_name = 'zoneSwitch_diff_' + dns_id + '_' + commandId + '_' + time.strftime('%Y%m%d%H%M%S') + '.gz'
	logger.info(switch_data)
	
	try:
		with gzip.open('/var/drms_toggle_data/' + file_name, "wb") as f:
			f.write(bytes(switch_data, 'utf-8'))
		upload_to_ftp('/var/drms_toggle_data/',file_name,'17')
	except Exception as e:
		logger.error('upload root switch data error:'+str(e))


def switch_rootca(target, switch_file, clear, dnsId, commandType, commandId, hashAlgorithm, compressionFormat, encryptAlgorithm):
	if switch_named_file(target,switch_file,clear):
		upload_switch_result(target, dnsId, commandId)
		return genResult(0, commandType, commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)
	return genResult(900, commandType, commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)



def switch_root_source(is_exigency, dnsId, commandType, commandId, hashAlgorithm, compressionFormat, encryptAlgorithm):
	target = exigency_source if is_exigency else standard_source
	if check_root_copy_data_source(is_exigency):
		logger.info('root copy data source already at {}'.format(target))
		upload_switch_result(target, dnsId, commandId)
		return genResult(0, commandType, commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)
	if switch_named_file(target,root_source,'0'):
		upload_switch_result(target, dnsId, commandId)
		return genResult(0, commandType, commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)
	return genResult(900, commandType, commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)


def switch_root_direction(cmd, commandType, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm):
	ele = lxml.etree.fromstring(cmd)
	_commandId = xmlget(ele, 'commandId')
	_type = xmlget(ele, 'type')
	_urgency = xmlget(ele, 'urgency')
	_datasources = xmlget(ele, 'datasources')
	_clearcache = xmlget(ele, 'clearCache')

	if _type != None and server_type == 'recursion':
		if soft == 'bind':
			target = local if _type == '1' else std
			return switch_rootca(target, switch, _clearcache, dnsId, 8, _commandId, hashAlgorithm, compressionFormat, encryptAlgorithm)
		elif soft == 'yrdns':
			target = yrdns_local if _type == '1' else yrdns_std
			return switch_rootca(target, yrdns_switch, '0', dnsId, 8, _commandId, hashAlgorithm, compressionFormat, encryptAlgorithm)

	if _datasources != None and server_type == 'root_copy':
		is_exigency = True if _datasources != '1' else False
		return switch_root_source(is_exigency, dnsId, 8 , _commandId, hashAlgorithm, compressionFormat, encryptAlgorithm)

	logger.warning('The server can not receive this switch command')
	return genResult(900, commandType, _commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)


def switch_exigency_status(cmd, commandType, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm):
	ele = lxml.etree.fromstring(cmd)
	_commandId = xmlget(ele, 'commandId')
	_type = xmlget(ele, 'type')
	global loop_count

	if _type == '1':
		share_delay.value = 900
		loop_count = 0
		logger.info('sys switch to exigency status upload_delay {}'.format(int(share_delay.value)))
	if _type == '2':
		share_delay.value = 86400
		logger.info('sys switch to standard status upload_delay {}'.format(int(share_delay.value)))

	return genResult(0, 8, _commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)


class DRMSService(ServiceBase):
	@rpc(Unicode, Unicode, Unicode, Unicode, Unicode,Int, Long, Int, Int, 
		Int,Unicode, _out_variable_name = 'return', _returns = Unicode)

	def dns_command(ctx, dnsId, randVal, pwdHash, command, commandHash, commandType, 
	commandSequence, encryptAlgorithm, hashAlgorithm, compressionFormat, commandVersion):
		try:
			if not certificate(pwdHash, randVal, hashAlgorithm):
				logger.error('command certificate error')
				return genResult(2, commandType, None, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm) 
			cmd = deCMDPre(command, compressionFormat, commandHash,hashAlgorithm, encryptAlgorithm)
			if not cmd:
				logger.error('webService Malformed content do deCMDPre error')
				return genResult(5, commandType, None, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)
			command_func = {18:switch_root_direction,19:switch_exigency_status}
			if commandType in command_func:
				return command_func[commandType](cmd, commandType, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)
		except Exception as e: 
			logger.error('command error:{}'.format(e))
			return genResult(900, commandType, None, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)
        


def xgj_main_task():
	application = Application([DRMSService],'http://webservice.ack.dns.act.com/', 
			in_protocol = Soap11(validator = 'lxml'), 
			out_protocol = Soap11())

	wsgi_app = WsgiMounter({'DNSWebService' : application})
	server = make_server('0.0.0.0', listen_port, wsgi_app)
	server.serve_forever()


