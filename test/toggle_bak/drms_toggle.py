#!/usr/bin/python3
# -*- coding: utf-8 -*-

from __future__ import print_function

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

from flask import Flask
from flask import request

import osa, daemon

waj_conf = {}
white_domain = {}
app = Flask(__name__)

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

	conf_file = config.get('bind', 'conf_file')
	forward_file = '/var/drms_toggle_data/forward.zone'
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

	network = {}
	network['ip'] = config.get('local-net', 'ip')
	network['port'] = config.getint('local-net', 'port')
	network['crt'] = config.get('local-net', 'crt')
	network['key'] = config.get('local-net', 'key')
	waj_conf['net'] = network
	
	upload = {}
	upload['url'] = config.get('upload', 'url')
	upload['org_id'] = config.get('upload', 'org_id')
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


def getXmlValue(dom, root, xpath):
	ml = dom.getElementsByTagName(root)[0]
	node = ml.getElementsByTagName(xpath)[0]
	for n in node.childNodes:
		nodeValue = n.nodeValue
		return nodeValue
	return None


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


def aesDecode(raw):
	aes = AESCipher(gAESKey, gAESIV)
	return aes.decrypt(raw)


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


#waj返回给drms的ack
def waj_dnsCommandAck(uuid, orgId, subsysId, hashMode, compressMode, encryptMode):
	sleep(1)
	try:
		url                 = waj_conf['upload']['url']+'41/'+waj_conf['upload']['org_id']
		randVal             = bytes(''.join(random.sample(string.ascii_letters, 20)), 'utf-8')
		lPwd                = bytes(waj_conf['security']['user_pwd'], 'utf-8')
		lMsgAuthKey         = bytes(waj_conf['security']['data_pwd'], 'utf-8')
		commandVersion      = 'v0.1'
		_uuid               = uuid
        
		jsonData = {
			'cmdUuid'       : str(_uuid),
			'processStatus' : '5',
			'remark'        : '指令处置完毕',
			'workCompRate'  : 0.99,
			'timeStamp'		:datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
		}
        
		data                = bytes(json.dumps(jsonData),'utf-8')   
        
		if hashMode == '0':  
			_hashed_pwd = (lPwd + randVal)
			pwdHash = base64.b64encode(_hashed_pwd)
		elif hashMode == '1':  
			_hashed_pwd = hashlib.md5(lPwd + randVal).hexdigest()
			pwdHash = base64.b64encode(_hashed_pwd.encode('utf-8'))
		elif hashMode == '2':  
			_hashed_pwd = hashlib.sha1(lPwd + randVal).hexdigest()
			pwdHash = base64.b64encode(_hashed_pwd.encode('utf-8'))
		elif hashMode == '3':  
			_hashed_pwd = hashlib.sha256(lPwd + randVal).hexdigest()
			pwdHash = base64.b64encode(_hashed_pwd.encode('utf-8'))
		elif hashMode == '11': pass
		else :  
			_hashed_pwd = lPwd + randVal
			pwdHash = base64.b64encode(_hashed_pwd)

		if compressMode == '0': _compressed_data = data
		elif compressMode == '1': _compressed_data = zlib.compress(data)

		if encryptMode == '0':
			_encrypted_data = _compressed_data
		elif encryptMode == '1':
			e = AESCipher(waj_conf['security']['aes_key'].encode('utf-8'), waj_conf['security']['aes_iv'].encode('utf-8'))
			_encrypted_data = e.encrypt(_compressed_data)
		elif encryptMode == '2'   : pass
		elif encryptMode == '11'  : pass
		elif encryptMode == '12'  : pass
		elif encryptMode == '13'  : pass
		elif encryptMode == '14'  : pass
		else: _encrypted_data = _compressed_data
                   
		data = base64.b64encode(_encrypted_data)

		if hashMode == '0':  
			_hashed_data = _compressed_data + lMsgAuthKey
			dataHash = base64.b64encode(_hashed_data)
		elif hashMode == '1':  
			_hashed_data = hashlib.md5(_compressed_data + lMsgAuthKey).hexdigest()
			dataHash = base64.b64encode(_hashed_data.encode('utf-8'))
		elif hashMode == '2':  
			_hashed_data = hashlib.sha1(_compressed_data + lMsgAuthKey).hexdigest()
			dataHash = base64.b64encode(_hashed_data.encode('utf-8'))
		elif hashMode == '3':  
			_hashed_data = hashlib.sha256(_compressed_data + lMsgAuthKey).hexdigest()
			dataHash = base64.b64encode(_hashed_data.encode('utf-8'))
		elif hashMode == '11': pass
		else :  
			_hashed_data = _compressed_data + lMsgAuthKey
			dataHash = base64.b64encode(_hashed_data)

		requestData = {
			'uuid'          : str(_uuid),
			'orgId'         : orgId,
			'subsysId'      : subsysId,
			'intfId'        : '41',
			'intfVer'       : commandVersion,
			'timeStamp'		: datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
			'randVal'       : randVal.decode(),
			'pwdHash'       : pwdHash.decode(),
			'encryptMode'   : encryptMode,
			'hashMode'      : hashMode,
			'compressMode'  : compressMode,
			'dataTag'       : waj_conf['upload']['data_tag'],
			'data'          : data.decode(),
			'dataHash'      : dataHash.decode()
		}
        
		headers = {
			"Accept-Charset": "utf-8",
			"Content-Type": "application/json"
		}   

		ret =requests.post(url, json.dumps(requestData), headers = headers)
		retData = json.loads(ret.text)
        
		if retData.get('errorCode') == '0':
			logger.info('send to {} waj_dnsCommandAck success'.format(url))
		else:
			logger.info('send to {} waj_dnsCommandAck error'.format(url))

	except Exception as e:
		logger.error('send to {} waj_dnsCommandAck failed:{}'.format(url,e))


#waj获取返回错误的信息
def gen_waj_Result(rcode, uuid = ' ', orgId ='4', subsysId = '20', hashMode='3', compressMode='1', encryptMode='0'):
	lookaside = {    
		'0' : '',    
		'1' : 'Failure for unknown reason',    
		'2' : 'Certification error',    
		'3' : 'Check failure',    
		'4' : 'De-compression error',    
		'5' : 'Format error',    
	}   
	result = {
		"errorCode"         : rcode,
		"errorMsg"          : lookaside[rcode],
		'timeStamp'			:datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
	}
	if rcode == '0':
		threading._start_new_thread(waj_dnsCommandAck, (uuid, orgId, subsysId, hashMode, compressMode, encryptMode))
	return result


def waj_certificate(pwdHash, randVal, hashMode):
	pwd = waj_conf['security']['user_pwd']
	if hashMode   == '0'     : raw = (pwd + randVal).encode('utf-8')
	elif hashMode == '1'     : raw = hashlib.md5((pwd + randVal).encode()).hexdigest().encode('utf-8')
	elif hashMode == '2'     : raw = hashlib.sha1((pwd + randVal).encode()).hexdigest().encode('utf-8')
	elif hashMode == '3'     : raw = hashlib.sha256((pwd + randVal).encode()).hexdigest().encode('utf-8')
	elif hashMode == '11'    : pass 
	else: return False
    
	return pwdHash == base64.b64encode(raw).decode('utf-8')


def waj_deCMDPre(data, compressMode, dataHash,hashMode, encryptMode):
	gAESKey, gMsgAuthKey = waj_conf['security']['aes_key'],waj_conf['security']['data_pwd']
	raw = base64.b64decode(data.encode('utf-8'))

	if encryptMode == '0'     : aesData = raw
	elif (gAESKey is not None) and (encryptMode == '1'): aesData = aesDecode(raw)
	elif encryptMode == '2'   : pass
	elif encryptMode == '11'  : pass
	elif encryptMode == '12'  : pass
	elif encryptMode == '13'  : pass
	elif encryptMode == '14'  : pass
	else: return None
    
	if hashMode == '0'      : hashed = aesData + gMsgAuthKey.encode('utf-8')
	elif hashMode == '1'    : hashed = hashlib.md5((aesData + gMsgAuthKey.encode('utf-8'))).hexdigest().encode('utf-8')
	elif hashMode == '2'    : hashed = hashlib.sha1((aesData + gMsgAuthKey.encode('utf-8'))).hexdigest().encode('utf-8')
	elif hashMode == '3'    : hashed = hashlib.sha256((aesData + gMsgAuthKey.encode('utf-8'))).hexdigest().encode('utf-8')
	elif hashMode == '11'   : pass 
	else: return None
  
	if base64.b64encode(hashed).decode('utf-8') != dataHash:
		return None
    
	if compressMode == '0'      : requestData = aesData
	elif compressMode == '1'    : requestData = zlib.decompress(aesData)
    
	return requestData


def clear_zone_cache(domain,domainType):
	try:
		if domainType == '1':
			subprocess.check_call([rndc, 'flushname', domain], cwd = '/etc')
			logger.info('clear domain {} cache'.format(domain))
		elif domainType == '0' or domainType == '2':
			subprocess.check_call([rndc, 'flushtree', domain], cwd = '/etc')
			logger.info('clear zone {} all cache'.format(domain))
		return True
	except subprocess.CalledProcessError:
		logger.error('rndc flush {} error!'.format(domain))
	return False
	

def waj_clear_cache(intfId, requestData, orgId, subsysId, uuid, encryptMode, hashMode, compressMode):
	try:
		jsonData        = json.loads(requestData.decode("utf-8"))
		domain          = jsonData.get('domain')
		domainType      = jsonData.get('domainType')
		if clear_zone_cache(domain,domainType):
			return json.dumps(gen_waj_Result('0',uuid, orgId, subsysId, hashMode, compressMode, encryptMode))
	except Exception as e:
		logger.error('clear cache error: {}'.format(e))
	return json.dumps(gen_waj_Result('1'))



def waj_root_switch(intfId, requestData, orgId, subsysId, uuid, encryptMode, hashMode, compressMode):
	target,switch_file = '',''

	if intfId == '15' or intfId == '18':
		if soft == 'bind':
			target = local
			switch_file = switch
		elif soft == 'yrdns':
			target = yrdns_local
			switch_file = yrdns_switch
	elif intfId == '16' or intfId == '17':
		if soft == 'bind':
			target = std
			switch_file = switch
		elif soft == 'yrdns':
			target = yrdns_std
			switch_file = yrdns_switch
	elif intfId == '34':
		target = exigency_source
		switch_file = root_source
	elif intfId == '35':
		target = standard_source
		switch_file = root_source

	if server_type == 'root_copy':
		is_exigency = True if exigency_source == target else False
		if check_root_copy_data_source(is_exigency):
			logger.info('root copy data source already at {}'.format(target))
			return json.dumps(gen_waj_Result('0',uuid, orgId, subsysId, hashMode, compressMode, encryptMode))
	if switch_named_file(target,switch_file,'0'):
		return json.dumps(gen_waj_Result('0',uuid, orgId, subsysId, hashMode, compressMode, encryptMode))
	return json.dumps(gen_waj_Result('1'))


def include_forward_file():
	forward_str = 'include ' + '"' + forward_file + '";\n'
	try:
		with open(conf_file,'r') as f:
			for s in f:
				if s == forward_str:
					return True
		with open(conf_file,'a') as f:
			f.write('\n')
			f.write(forward_str)
		return True
	except Exception as e:
		logger.error('include forward file to named conf error: {}'.format(e))
	return False
	

def include_foward_zone(data,fname,forward_str):
	try:
		with open(fname,'w') as f:
			f.write(data)
		if os.path.exists(forward_file) == False:
			with open(forward_file,'w') as f:
				f.write(forward_str)
			return True
		with open(forward_file,'r+') as f:
			for s in f:
				if forward_str == s:
					return True
			f.write(forward_str)
		return True
	except Exception as e:
		logger.error('include forward file to named conf error: {}'.format(e))
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
		return reload_bind_conf()
	except Exception as e:
		logger.error('del forward zone from forward file error: {}'.format(e))
	return False


def waj_zone_forward(intfId, requestData, orgId, subsysId, uuid, encryptMode, hashMode, compressMode):
	try:
		jsonData        = json.loads(requestData.decode("utf-8"))
		domain          = jsonData.get('domain')
		domainType      = jsonData.get('domainType')
		ipv4List      	= jsonData.get('ipv4List')
		ipv6List      	= jsonData.get('ipv6List')
		forwardMode		= jsonData.get('forwardMode')

		if intfId == '25' and conf_zone_forward(domain,forwardMode, ipv4List, ipv6List):
			return json.dumps(gen_waj_Result('0',uuid, orgId, subsysId, hashMode, compressMode, encryptMode))
		elif intfId == '26' and del_zone_forward(domain):
			return json.dumps(gen_waj_Result('0',uuid, orgId, subsysId, hashMode, compressMode, encryptMode))

	except Exception as e:
		logger.error('zone forward error: {}'.format(e))
	return json.dumps(gen_waj_Result('1'))


#flask 处理https的入口函数
@app.route('/<int:intfId>/<int:orgId>', methods=['POST'])
def handerHttpsRequest(intfId, orgId):
	try:
		if request.method == 'POST':
			jsonData = json.loads(request.get_data().decode('utf-8'))			
			logger.info('local 0.0.0.0:18899 HttpsRequest recv {}'.format(jsonData))            
            #获取请求参数里面的对应值            
			uuid            = jsonData.get('uuid')            
			orgId           = jsonData.get('orgId')            
			subsysId        = jsonData.get('subsysId')            
			intfId          = jsonData.get('intfId')            
			intfVer         = jsonData.get('intfVer')            
			timeStamp       = jsonData.get('timeStamp')            
			randVal         = jsonData.get('randVal')            
			pwdHash         = jsonData.get('pwdHash')            
			encryptMode     = jsonData.get('encryptMode')            
			hashMode        = jsonData.get('hashMode')            
			compressMode    = jsonData.get('compressMode')            
			dataTag         = jsonData.get('dataTag')            
			data            = jsonData.get('data')            
			dataHash        = jsonData.get('dataHash')                        
			#进行hash的验证            
			if not waj_certificate(pwdHash, randVal, hashMode):                
				logger.error('waj Certification error')                
				return json.dumps(gen_waj_Result('2'))            
			#数据的提取和校验            
			requestData = waj_deCMDPre(data, compressMode, dataHash,hashMode, encryptMode)            
			if not requestData:                
				logger.error('waj Check data failure')                
				return json.dumps(gen_waj_Result('3'))

			command_func = {
				'29' : waj_clear_cache,
				'15' : waj_root_switch,'16' : waj_root_switch,'17' : waj_root_switch,'18' : waj_root_switch,
				'34' : waj_root_switch,'35' : waj_root_switch,
				'25' : waj_zone_forward,'26' : waj_zone_forward
			}

			if intfId in command_func:
				return command_func[intfId](intfId, requestData, orgId, subsysId, uuid, encryptMode, hashMode, compressMode)            
			#不支持的inftid            
			else:                
				logger.warning('unsupported intfId : {} \nrequestData : {}'.format(intfId,requestData))        
		return json.dumps(gen_waj_Result('5'))    
	except Exception as e:        
		logger.warning('waj ack catch exception : {}'.format(e))        
		return json.dumps(gen_waj_Result('1'))


def waj_main_task():
	app.run(host=waj_conf['net']['ip'], port=waj_conf['net']['port'], debug=False, ssl_context=(waj_conf['net']['crt'], waj_conf['net']['key']))


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
		if loop_count >= 900:
			loop_count = 0
		sleep(1)
		loop_count += 1


#if __name__ == '__main__':
with daemon.DaemonContext():
	logger = logging.getLogger('drms_toggle')
	logger.setLevel(level = logging.INFO)
	handler = logging.FileHandler("/var/log/drms_toggle.log")
	handler.setLevel(logging.INFO)
	formatter = logging.Formatter('%(asctime)s|%(lineno)d|%(levelname)s|%(message)s')
	handler.setFormatter(formatter)
	logger.addHandler(handler)

	logger.info('main process start at: %s' % time.ctime())

	threading._start_new_thread(xgj_main_task,())
	threading._start_new_thread(waj_main_task,())
	check_soa_and_upload()

	logger.info('main process end at: %s' % time.ctime())
 

