#概述
xssfork是新一代xss漏洞探测工具，其开发的目的是帮助安全从业者高效率的检测xss安全漏洞，关于xss的更多详情可以移步[Cross-site Scripting (XSS)](https://www.owasp.org/index.php/Cross-site_Scripting_(XSS))。不管什么语言，传统的xss探测工具，一般都是采用第三方库向服务器发送一个注入恶意代码的请求，其工作原理是采用payload in response的方式，即通过检测响应包中payload的完整性来判断，这种方式缺陷，很多。
例如
1.不能检测dom类xss(无法从源代码中检查)
2.不能模拟真正的浏览器
3.网页js无法交互,第三方库不认识网页中的js的代码。
与传统的工具相比，xssfork使用的是 webkit内核的浏览器phantomjs，其可以很好的模拟浏览器。工具分为两个部分，xssfork和xssforkapi，其中xssfork在对网站fuzz xss的时候会调用比较多的payload。
#两者结合
可以使用xssforkapi来做批量xss检测工具,xssfork做深度fuzz工具。xssforkapi这种webservice方式十分适合分布式部署。
#创建任务
关于key,为了保证外部不能非法调用服务，xssforkapi采用的是http协议验证key的方式。
##key的获取方式
在每次启动xssforkapi的时候，会将key写入到根目录authentication.key中，你也可以在每次启动服务的时候看到key。
![](http://pic.findbugs.top/17-7-28/74466819.jpg)
key默认是每次启动服务不更新的，你也可以在下一次启动服务的时候强制更新，只需要启动的时候指定--refresh True即可。值得注意的时候，refresh指定为true之后，原有的保存在data目录下xssfork.db将会清除，这意味着你将清除你之前所有的检测纪录。
![](http://pic.findbugs.top/17-7-28/52701244.jpg)
##新建扫描任务
需要向服务传递两个参数,1.key(主要用于验证身份)；2.检测参数
### get协议检测
###创建任务
1.get反射型类型
```
req = requests.post('http://127.0.0.1:2333/xssfork/create_task/7T2o22NcQSLGk75',data=json.dumps({'url':'http://10.211.55.13/xss/example1.php?name=hacker', ), headers={'Content-Type':'application/json'})
return req.content
```
2.post反射类型
```
req = requests.post('http://127.0.0.1:2333/xssfork/create_task/7T2o22NcQSLGk75',data=json.dumps({'url':'http://10.211.55.13/xss/post_xss.php', 'data':'name=233'), headers={'Content-Type':'application/json'})
return req.content
```
3.get反射型类型，需要验证cookie
```
req = requests.post('http://127.0.0.1:2333/xssfork/create_task/7T2o22NcQSLGk75',data=json.dumps({'url':'http://10.211.55.13/xss/example1.php?name=hacker', 'cookie':'usid=admin'), headers={'Content-Type':'application/json'})
return req.content
```
4.post反射型类型，需要验证cookie
```
req = requests.post('http://127.0.0.1:2333/xssfork/create_task/7T2o22NcQSLGk75',data=json.dumps({'url':'http://10.211.55.13/xss/post_xss.php', 'data':'name=2333', 'cookie': 'usid=admin'), headers={'Content-Type':'application/json'})
return req.content
```
5.get储存型，需要验证cookie
```
req = requests.post('http://127.0.0.1:2333/xssfork/create_task/7T2o22NcQSLGk75',data=json.dumps({'url':'http://10.211.55.13/xss/example1.php?name=hacker', 'cookie':'usid=admin', 'destination': 'http://10.211.55.13/output.php'), headers={'Content-Type':'application/json'})
return req.content
```
4.post储存型，需要验证cookie
```
req = requests.post('http://127.0.0.1:2333/xssfork/create_task/7T2o22NcQSLGk75',data=json.dumps({'url':'http://10.211.55.13/xss/example1.php?name=hacker', 'data':'name=2333', 'cookie':'usid=admin', 'destination': 'http://10.211.55.13/output.php'), headers={'Content-Type':'application/json'})
return req.content
```
返回码

```
{"status": "success", "task_id": "1"}
```
调用者可以获取到任务id，以便于启动检测。
#启动任务
```
import requests
req = requests.get('http://127.0.0.1:2333/xssfork/start_task/tM0Xnl0qD6nsHku/%s' % (task_id))
print req.content
```
返回码

```
{"status": "success", "msg": "task will start"}
```
#查看状态
```
import requests
req = requests.get('http://127.0.0.1:2333/xssfork/task_status/tM0Xnl0qD6nsHku/%s' % (task_id))
print req.content
```
返回码分为4种，分别如下:  
1.任务不存在
```
{"status": -1, "msg": "task isn’t existed"}
```  
2.任务创建了，但是未启动
```
{"status": 0, "msg": "task isn't started"}
```  
3.任务正在作业中，未完成
```
{"status": 1, "msg": "task is working"}
```  
4.任务作业完成
```
{"status":2, "msg": "task has been done"}
```
#获取结果
```
req = requests.get('http://127.0.0.1:2333/xssfork/task_result/7T2o22NcQSLGk75/%s' % (task_id))
	print req.content
```
返回分为两种  
1.检测到漏洞，并且返回payload
```
{"payload": "{'url': "http://10.211.55.13/xss/example1.php?name=%22<xss></xss>//", 'data': null}"}
```  
2.未检测到漏洞
```
{"payload": null}
```
#结束任务
```
req = requests.get('http://127.0.0.1:2333/xssfork/kill_task/7T2o22NcQSLGk75/%s' % (task_id))
	print req.content
```
返回结果可能有4种
1.结束任务失败，因为任务不存在
```
{"status": "false", "msg": "task isn’t existed"}
```  
2.结束任务失败，因为任务根本没启动
```
{"status": "false", "msg": "task isn't started"}
```  
3.结束任务失败，因为任务本已经结束，不需要强制杀死
```
{"status": "false", "msg": "task has been done"}
```  
4.结束任务成功，任务原本是处于运行中的状态
```
{"status": "success", "msg": "task will be killed"}
```
#完整的例子
1.一次带有cookie验证的post xss
漏洞示例代码
```
<?php
if (isset($_COOKIE['usid']) && isset($_POST['id']))
{
	if ($_COOKIE['usid']=="admin")
		{
			echo $_POST['id'];
		}
}
?>
```
客户端代码
```
#! /usr/bin/env python
# coding=utf-8
import json
import time
import requests


def creat_task(url, data, cookie):
    json_data = json.dumps({'url': url, 'data': data, 'cookie': cookie})
    req = requests.post('http://127.0.0.1:2333/xssfork/create_task/7T2o22NcQSLGk75', data=json_data, headers={'Content-Type':'application/json'})
    return req.content


def start_task(task_id):
    req = requests.get('http://127.0.0.1:2333/xssfork/start_task/7T2o22NcQSLGk75/{}'.format(task_id))
    return req.content


def get_task_status(task_id):
    req = requests.get('http://127.0.0.1:2333/xssfork/task_status/7T2o22NcQSLGk75/{}'.format(task_id))
    return req.content


def get_task_result(task_id):
    req = requests.get('http://127.0.0.1:2333/xssfork/task_result/7T2o22NcQSLGk75/{}'.format(task_id))
    return req.content


def running(task_id):
    time.sleep(5)
    task_status = int(json.loads(get_task_status(task_id)).get('status'))
    return task_status in [0, 1]


if __name__ == "__main__":
    url = "http://10.211.55.3/xsstest/cookie_xss_post.php"
    data = "id=1"
    cookie = "usid=admin"
    task_id = json.loads(creat_task(url, data, cookie)).get('task_id')
    start_task(task_id)
    while running(task_id):
        print "the task is working"
    print get_task_result(task_id)

```


效果

![](http://pic.findbugs.top/17-7-28/70449749.jpg)
#免责申明
xssfork保证竭诚为网络用户提供最安全的上网服务，但因不可避免的问题导致出现的问题，我们尽力解决，期间引起的问题我们不承担以下责任。  
###第 一 条  
xssfork使用者因为违反本声明的规定而触犯中华人民共和国法律的，一切后果自己负担,xssfork.codersec.net站点以及作者不承担任何责任。 
###第 二 条  
凡以任何方式直接、间接使用xssfork资料者，视为自愿接受xssfork.codersec.net声明的约束。 
###第 三 条  
本声明未涉及的问题参见国家有关法律法规，当本声明与国家法律法规冲突时，以国家法律法规为准。 
### 第 四 条  
对于因不可抗力或xssfork不能控制的原因造成的网络服务中断或其它缺陷，xssfork.codersec.net网站以及作者不承担任何责任。
### 第 五 条  
xssfork之声明以及其修改权、更新权及最终解释权均属xssfork.codersec.net网所有。
