#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os, pwd, sys, re, time, datetime, logging, random, string, logging.handlers, gzip, paramiko
import multiprocessing, subprocess, requests, urllib3, uuid
from threading import Timer
from configparser import ConfigParser
from Crypto.Cipher import AES

from iscpy.iscpy_dns.named_importer_lib import *
import base64, hashlib, zlib, json, lxml.etree, pexpect, dns, dns.resolver

from time import sleep
import threading, binascii, xml.dom.minidom, shutil, filecmp

from flask import Flask
from flask import request

from xgj import *

app = Flask(__name__)

#waj返回给drms的ack
def waj_dnsCommandAck(uuid, orgId, subsysId, hashMode, compressMode, encryptMode):
	sleep(1)
	try:
		url                 = waj_conf['upload']['url']+'41/' + orgId
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
	
	try:
		jsonData        = json.loads(requestData.decode("utf-8"))

		if intfId == '15':
			if soft == 'bind':
				target = local
				switch_file = switch
				waj_command_cache[uuid] = std if filecmp.cmp(std,switch) else local
			elif soft == 'yrdns':
				target = yrdns_local
				switch_file = yrdns_switch
				waj_command_cache[uuid] = yrdns_std if filecmp.cmp(yrdns_std,yrdns_switch) else yrdns_local
		elif intfId == '16':
			cancelCmdUuid = jsonData.get('cancelCmdUuid')
			if soft == 'bind':
				target = waj_command_cache[cancelCmdUuid] if cancelCmdUuid in waj_command_cache else std
				switch_file = switch
			elif soft == 'yrdns':
				target = waj_command_cache[cancelCmdUuid] if cancelCmdUuid in waj_command_cache else yrdns_std
				switch_file = yrdns_switch
			del waj_command_cache[cancelCmdUuid]
		elif intfId == '17':
			if soft == 'bind':
				target = std
				switch_file = switch
				waj_command_cache[uuid] = std if filecmp.cmp(std,switch) else local
			elif soft == 'yrdns':
				target = yrdns_std
				switch_file = yrdns_switch
				waj_command_cache[uuid] = yrdns_std if filecmp.cmp(yrdns_std,yrdns_switch) else yrdns_local
		elif intfId == '18':
			cancelCmdUuid = jsonData.get('cancelCmdUuid')
			if soft == 'bind':
				target = waj_command_cache[cancelCmdUuid] if cancelCmdUuid in waj_command_cache else local
				switch_file = switch
			elif soft == 'yrdns':
				target = waj_command_cache[cancelCmdUuid] if cancelCmdUuid in waj_command_cache else yrdns_local
				switch_file = yrdns_switch
			del waj_command_cache[cancelCmdUuid]
		elif intfId == '34':
			switch_file = root_source
			waj_command_cache[uuid] = standard_source if filecmp.cmp(standard_source,root_source) else exigency_source
			source = jsonData.get('dataSource')
			if source == '1':
				target = standard_source
			elif source == '2':
				target = exigency_source
		elif intfId == '35':
			cancelCmdUuid = jsonData.get('cancelCmdUuid')
			target = waj_command_cache[cancelCmdUuid] if cancelCmdUuid in waj_command_cache else standard_source
			switch_file = root_source
			del waj_command_cache[cancelCmdUuid]

		if server_type == 'root_copy':
			is_exigency = True if exigency_source == target else False
			if check_root_copy_data_source(is_exigency):
				logger.info('root copy data source already at {}'.format(target))
				return json.dumps(gen_waj_Result('0',uuid, orgId, subsysId, hashMode, compressMode, encryptMode))
		if switch_named_file(target,switch_file,'0'):
			return json.dumps(gen_waj_Result('0',uuid, orgId, subsysId, hashMode, compressMode, encryptMode))
	
	except Exception as e:
		logger.error('root switch error : {}'.format(e))

	#return json.dumps(gen_waj_Result('1'))
	return json.dumps(gen_waj_Result('0',uuid, orgId, subsysId, hashMode, compressMode, encryptMode))


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
		logger.error('include file to named conf error: {}'.format(e))
	return False
	

def include_zone(data,fname,zone_str,zone_file):
	try:
		with open(fname,'w') as f:
			f.write(data)
		os.chown(fname,pwd.getpwnam('named').pw_gid,pwd.getpwnam('named').pw_gid)
		if os.path.exists(zone_file) == False:
			with open(zone_file,'w') as f:
				f.write(zone_str)
			os.chown(zone_file,pwd.getpwnam('named').pw_gid,pwd.getpwnam('named').pw_gid)
			return True
		with open(zone_file,'r+') as f:
			for s in f:
				if zone_str == s:
					return True
			f.write(zone_str)
		return True
	except Exception as e:
		logger.error('include zone file to named conf error: {}'.format(e))
	return False
		

def reload_bind_conf():
	try:
		subprocess.check_call([rndc, 'reload'], cwd = '/etc')
		subprocess.check_call([rndc, 'flush'], cwd = '/etc')
	except Exception as e:
		logger.error('do rndc reload error: {}'.format(e))
		return False
	return True


def del_force_zone(include_file,include_str):
	try:
		if os.path.exists(include_file) == False:
			return False
		l = []
		with open(include_file,'r') as f:
			l = f.readlines()
		with open(include_file,'w') as f:
			for s in l:
				if include_str == s:
					continue
				f.write(s)
		os.chown(include_file,pwd.getpwnam('named').pw_gid,pwd.getpwnam('named').pw_gid)
		return reload_bind_conf()
	except Exception as e:
		logger.warning('del ns force file error: '+str(e))
	return False


def conf_zone_forward(domain, mode, ipv4_list, ipv6_list):
	if include_file(forward_file) == False:
		return False

	d1 = 'zone "{}" IN '.format(domain) + '{\n    type forward;\n'
	forward_mode = 'first' if mode == '1' else 'only'
	iplist = '{ '
	for ip in ipv4_list:
		if ip != '':
			iplist += ip + ';'
	for ip in ipv6_list:
		if ip != '':
			iplist += ip + ';'
	iplist += ' }'
	d2 = '    forward {};\n    forwarders {};\n'.format(forward_mode,iplist)+ '};'
	data = d1 + d2
	
	fname = '/var/drms_toggle_data/' + domain + 'forward'
	forward_str = 'include ' + '"' + fname  + '";\n'
	if include_zone(data,fname,forward_str,forward_file) == False:
		return False

	return reload_bind_conf()


def del_zone_forward(domain):
	fname = '/var/drms_toggle_data/' + domain + 'forward'
	forward_str = 'include ' + '"' + fname  + '";\n'
	if os.path.exists(fname):
		os.remove(fname)
	return del_force_zone(forward_file,forward_str)


def get_ns_str(nslist):
	ns_str = ''
	try:
		for d in nslist:
			for i in d['ipv4List']:
				if i != '':
					ns_str += i + ';'
			for i in d['ipv6List']:
				if i != '':
					ns_str += i + ';'
		return ns_str
	except Exception as e:
		logger.error('get ns list str error: {}'.format(e))
	return ''


def ns_force_resolve(domain,domainType,nslist):
	if include_file(ns_file) == False:
		return False

	ns_str = get_ns_str(nslist)

	d1 = 'zone "%s" IN '%(domain) + '{\n    type forward;\n'
	d2 = '    forward first;\n    forwarders { %s };\n};'%(ns_str)
	data = d1 + d2
	
	fname = '/var/drms_toggle_data/' + domain + 'ns'
	forward_str = 'include ' + '"' + fname  + '";\n'
	if include_zone(data,fname,forward_str,ns_file) == False:
		return False

	return reload_bind_conf()


def cancel_ns_force_resolve(domain):
	fname = '/var/drms_toggle_data/' + domain + 'ns'
	f_str = 'include ' + '"' + fname  + '";\n'
	if os.path.exists(fname):
		os.remove(fname)
	return del_force_zone(ns_file,f_str)


def cname_force_resolve(domain,domainType,cname):
	if include_file(cname_file) == False:
		return False
	
	dname = ''
	if domain[-1:] == '.':
		dname = domain
	else:
		dname = domain + '.'
	domain = domain.split('.',1)[1]

	if cname[-1:] != '.':
		cname = cname + '.'

	data = 'zone "' + domain + '" IN {\n    type master;\n    file "/var/drms_toggle_data/' + domain + 'cname.zone";\n};'
	fname = '/var/drms_toggle_data/' + domain + 'cname'
	cname_str = 'include ' + '"' + fname  + '";\n'
	
	if include_zone(data,fname,cname_str,cname_file) == False:
		return False

	zone_file = '/var/drms_toggle_data/' + domain + 'cname.zone'
	soa =  '$TTL 600\n@ IN SOA ns.%s admin.%s (%s 2H 4M 1W 2D)\n'%(domain,domain,time.strftime('%Y%m%d%H'))
	ns = ' IN NS ns\nns IN A 114.114.114.114\n'
	zone_data = soa + ns + dname + ' IN CNAME ' + cname + '\n'

	with open(zone_file,'w') as f:
		f.write(zone_data)
	os.chown(zone_file,pwd.getpwnam('named').pw_gid,pwd.getpwnam('named').pw_gid)

	return reload_bind_conf()


def cancel_cname_force_resolve(domain):
	domain = domain.split('.',1)[1]
	fname = '/var/drms_toggle_data/' + domain + 'cname'
	f_str = 'include ' + '"' + fname  + '";\n'
	if os.path.exists(fname):
		os.remove(fname)
	zname = '/var/drms_toggle_data/' + domain + 'cname.zone'
	if os.path.exists(zname):
		os.remove(zname)
	return del_force_zone(cname_file,f_str)


def waj_force_resolve(intfId, requestData, orgId, subsysId, uuid, encryptMode, hashMode, compressMode):
	try:
		jsonData        = json.loads(requestData.decode("utf-8"))

		if intfId == '21':
			domain = jsonData.get('domain')
			domainType = jsonData.get('domainType')
			nslist = jsonData.get('paraList')
			if ns_force_resolve(domain,domainType,nslist):
				waj_command_cache[uuid] = domain
				return json.dumps(gen_waj_Result('0',uuid, orgId, subsysId, hashMode, compressMode, encryptMode))
		elif intfId == '22':
			cancelCmdUuid = jsonData.get('cancelCmdUuid')
			if cancelCmdUuid in waj_command_cache and cancel_ns_force_resolve(waj_command_cache[cancelCmdUuid]):
				del waj_command_cache[cancelCmdUuid]
				return json.dumps(gen_waj_Result('0',uuid, orgId, subsysId, hashMode, compressMode, encryptMode))
		elif intfId == '23':
			domain = jsonData.get('domain')
			domainType = jsonData.get('domainType')
			cname = jsonData.get('cname')
			if cname_force_resolve(domain,domainType,cname):
				waj_command_cache[uuid] = domain
				return json.dumps(gen_waj_Result('0',uuid, orgId, subsysId, hashMode, compressMode, encryptMode))
		elif intfId == '24':
			cancelCmdUuid = jsonData.get('cancelCmdUuid')
			if cancelCmdUuid in waj_command_cache and cancel_cname_force_resolve(waj_command_cache[cancelCmdUuid]):
				del waj_command_cache[cancelCmdUuid]
				return json.dumps(gen_waj_Result('0',uuid, orgId, subsysId, hashMode, compressMode, encryptMode))
		elif intfId == '25':
			domain          = jsonData.get('domain')
			domainType      = jsonData.get('domainType')
			ipv4List      	= jsonData.get('ipv4List')
			ipv6List      	= jsonData.get('ipv6List')
			forwardMode		= jsonData.get('forwardMode')
			if conf_zone_forward(domain,forwardMode, ipv4List, ipv6List):
				waj_command_cache[uuid] = domain
				return json.dumps(gen_waj_Result('0',uuid, orgId, subsysId, hashMode, compressMode, encryptMode))
		elif intfId == '26':
			cancelCmdUuid = jsonData.get('cancelCmdUuid')
			if cancelCmdUuid in waj_command_cache and del_zone_forward(waj_command_cache[cancelCmdUuid]):
				del waj_command_cache[cancelCmdUuid]
				return json.dumps(gen_waj_Result('0',uuid, orgId, subsysId, hashMode, compressMode, encryptMode))
	except Exception as e:
		logger.error('force resolve error: {}'.format(e))
	#return json.dumps(gen_waj_Result('1'))
	return json.dumps(gen_waj_Result('0',uuid, orgId, subsysId, hashMode, compressMode, encryptMode))


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
		logger.error('get dnssec conf error: {}'.format(e))
	return {'dnssec-enable':'no','dnssec-validation':'no','dnssec-lookaside':'auto'}


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
		return reload_bind_conf()
	except Exception as e:
		logger.error('reconf named.conf error: {}'.format(e))
	return False


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
		logger.error('reconf named.conf error: {}'.format(e))
	return reload_bind_conf()
	

def control_dnssec(intfId, requestData, orgId, subsysId, uuid, encryptMode, hashMode, compressMode):
	try:
		jsonData        = json.loads(requestData.decode("utf-8"))

		if intfId == '30':
			waj_command_cache[uuid] = get_dnssec_status()
			if dnssec_on_off(True):
				return json.dumps(gen_waj_Result('0',uuid, orgId, subsysId, hashMode, compressMode, encryptMode))
		elif intfId == '31' or intfId == '33':
			cancelCmdUuid = jsonData.get('cancelCmdUuid')
			if cancelCmdUuid in waj_command_cache and cancel_dnssec(waj_command_cache[cancelCmdUuid]):
				del waj_command_cache[cancelCmdUuid]
				return json.dumps(gen_waj_Result('0',uuid, orgId, subsysId, hashMode, compressMode, encryptMode))
		elif intfId == '32':
			waj_command_cache[uuid] = get_dnssec_status()
			if dnssec_on_off(False):
				return json.dumps(gen_waj_Result('0',uuid, orgId, subsysId, hashMode, compressMode, encryptMode))
	except Exception as e:
		logger.error('contronl dnssec error: {}'.format(e))
	#return json.dumps(gen_waj_Result('1'))
	return json.dumps(gen_waj_Result('0',uuid, orgId, subsysId, hashMode, compressMode, encryptMode))


#flask 处理https的入口函数
@app.route('/<int:intfId>/<int:orgId>', methods=['POST'])
def handerHttpsRequest(intfId, orgId):
	try:
		if request.method == 'POST':
			jsonData = json.loads(request.get_data().decode('utf-8'))			
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

			logger.info('recv waj cmd {}'.format(requestData))
			command_func = {
				'29' : waj_clear_cache,
				'15' : waj_root_switch, '16' : waj_root_switch,
				'17' : waj_root_switch, '18' : waj_root_switch,
				'34' : waj_root_switch, '35' : waj_root_switch,
				'21' : waj_force_resolve, '22' : waj_force_resolve,
				'23' : waj_force_resolve, '24' : waj_force_resolve,
				'25' : waj_force_resolve, '26' : waj_force_resolve,
				'30' : control_dnssec,'31' : control_dnssec,
				'32' : control_dnssec,'33' : control_dnssec
			}

			if intfId in command_func:
				return command_func[intfId](intfId, requestData, orgId, subsysId, uuid, encryptMode, hashMode, compressMode)            
			#不支持的inftid            
			else:                
				logger.warning('unsupported intfId : {} \nrequestData : {}'.format(intfId,requestData))        
		return json.dumps(gen_waj_Result('5'))    
	except Exception as e:        
		logger.warning('waj handerHttpsRequest catch exception : {}'.format(e))        
		return json.dumps(gen_waj_Result('1'))


def waj_main_task():
	app.run(host=waj_conf['net']['ip'], port=waj_conf['net']['port'], debug=False, ssl_context=(waj_conf['net']['crt'], waj_conf['net']['key']))

