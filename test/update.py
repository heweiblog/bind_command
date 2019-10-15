from dns import *
import dns
keyring = dns.tsigkeyring.from_text({
		                'rndc-key': "zG7TdwvsnD2dYoyqG2IEtg=="        #用到了刚刚key的sec
						            })


try:
	update = dns.update.Update('not.com', keyring=keyring)        #需要更新的域,以及认证所用的key

	#update.add('www', 86400, 'A', '1.1.1.1')              #这个是直接更新覆盖,改为这个记录.如果没有则添加记录
	update.delete('www')                            ##删除主机头为xxx的记录

	response = dns.query.tcp(update,'127.0.0.1', timeout=3)      #更新
	print('-----response-----\n',response)
	return_code=response.rcode()        ##这个是返回代码,0才是成功
	print('-----return_code-----\n',return_code)
	Result_Text=dns.rcode._by_value[return_code]        ##代码转换为对应结果
	print('-----Result_Text-----\n',Result_Text)
except Exception as e:
	print(e)


#update.replace('yw.hww.com', 6000, 'A', '1.1.1.1')               #这个是追加记录
#update.replace('a.cname.net', 86400, 'A', '192.168.6.11')               #这个是追加记录
#update.replace('news', 86400, 'A', '192.168.6.22')               #这个是追加记录
#update.replace('www', 86400, 'CNAME', 'a.cname.net')              #这个是直接更新覆盖,改为这个记录.如果没有则添加记录
#update._add(True,None,'www', 86400, 'CNAME', 'a.cname.net')              #这个是直接更新覆盖,改为这个记录.如果没有则添加记录
#update.add('a.cname.net', 86400, 'A', '192.168.6.11')          
#update.add('', 86400, 'NS', 'ns1')              #这个是直接更新覆盖,改为这个记录.如果没有则添加记录
#update.add('ns1', 86400, 'A', '1.1.1.1')              #这个是直接更新覆盖,改为这个记录.如果没有则添加记录
#update.delete('www')                            ##删除主机头为xxx的记录
#update.delete('yw')                            ##删除主机头为xxx的记录
#update.delete('a.cname.net')                            ##删除主机头为xxx的记录

