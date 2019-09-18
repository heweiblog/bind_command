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

from flask import Flask
from flask import request

from xgj import *

app = Flask(__name__)

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

