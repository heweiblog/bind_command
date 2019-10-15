import time

ns = [{'nsName':'ns1.qq.com','ipv4List':['1.1.1.1','2.2.2.2'],'ipv6List':['12::34::ea::12']},
	{'nsName':'ns2.qq.com','ipv4List':['1.1.3.5','4.2.2.2'],'ipv6List':[]},
	{'nsName':'ns3.qq.com','ipv4List':[],'ipv6List':['11::34::ea::11']}]


def get_ns_str(domain,nslist):
	ns_str = ''
	try:
		for d in nslist:
			ns_str += domain + ' IN NS ' + d['nsName'] + '\n'
			for i in d['ipv4List']:
				ns_str += d['nsName'] + ' IN A ' + i + '\n'
			for i in d['ipv6List']:
				ns_str += d['nsName'] + ' IN AAAA ' + i + '\n'
		return ns_str
	except Exception as e:
		print('get ns list str error: {}'.format(e))
	return ''


def get_ns_str2(domain,nslist):
	ns_str = ''
	try:
		for d in nslist:
			for i in d['ipv4List']:
				ns_str += i + '; '
			for i in d['ipv6List']:
				ns_str += i + '; '
		return ns_str
	except Exception as e:
		print('get ns list str error: {}'.format(e))
	return ''



domain = 'qq.com'
soa =  '$TTL 86400\n@ IN SOA ns.%s admin.%s (%s 2H 4M 1W 2D)\n'%(domain,domain,time.strftime('%Y%m%d%H'))
ns = get_ns_str2('qq.com',ns)
zone = soa+ns
print(zone)
