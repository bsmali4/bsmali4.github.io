---
layout: post
title: "Web 缓存欺骗攻击"
date: 2017-02-28
description: "前沿技术"
tag: 前沿技术
---
 
像https://www.paypal.com/myaccount/home/stylesheet.css或者https://www.paypal.com/myaccount/settings/notifications/logo.png这样的链接引起过你的注意吗？它们额恤会泄漏你的敏感数据，甚至有可能控制你的帐户哦。web缓存欺骗是一种新的web攻击方式，它使得现有各种技术和框架都可能面临风险。
##关于缓存和反应(caching and reactions)的一些事
1.网站经常会使用缓存功能(例如 cdn,负载均衡,甚至一个简单的反向代理)。目的很简单，存储经常需要检索的数据，依减少web服务器的延迟。让我们看一个简单的例子.让我们看一个网络缓存的例子。 网站http://www.example.com是通过反向代理配置的。 存储在服务器上显示用户个人的页面（如http://www.example.com/home.php），这类动态网页必须根据不同用户动态创建的，因为每个用户的数据不同。 这类数据，或者其它需要个性化定义的数据，不被缓存。
像 css,js,png,等等这类静态文件被用于缓存显得更加常见，更加合理。这样做是有道理的，因为这类文件不包含任何敏感的信息。像一些十分经典的缓存配置教程都推荐将所有的静态文件作为缓存，这意味着所有的静态文件都是公开的，直接忽视http缓存头。


2.web缓存欺骗攻击和rpo攻击是相同的方式，都是在浏览器和服务器之间交互。关于rpo攻击可以看，(http://www.thespanner.co.uk/2014/03/21/rpo/ and http://blog.innerht.ml/rpo-gadgets/)。想象一下，当请求像http://www.example.com/home.php/non-existent.css?这样的链接时，一个get请求由浏览器创建。有趣的是服务器的反应，它将怎样去解析这个请求url呢？这个取决于它的配置(不同的配置策略，解析的结构不同)，这个服务器将会返回http://www.example.com/home.php的。很好，请求的url不变，仍然是http://www.example.com/home.php/non-existent.css。这个http头将直接访问http://www.example.com/home.php：它们拥有相同的缓存头和相同的内容类型(都是text/html)
##简单介绍
当我们请求 http://www.example.com/home.php/non-existent.css时，它将会发生什么呢？当静态文件缓存被设置在反向代理之上，会无视这类文件的缓存头？让我们分析一下这个流程。  
1.浏览器请求 http://www.example.com/home.php/non-existent.css.
2.服务器实际会返回http://www.example.com/home.php的内容，极可能携带一些敏感数据。
3.这个响应包经过代理
4.这个代理确定是对静态css做了缓存的
5.在缓存目录里面，这个代理将创建一个名字为existent.css的缓存，里面的内容实际上是home.php的内容。
##浅谈利用
一个黑客向一个已经处于登陆状态的用户发送 http://www.example.com/home.php/logo.png这个链接，这个home.php实际上是包含用户个人信息。但是代理服务器会创建一个logo.png静态资源，里面的内容实际上是home.php的内容，这里面有可能会包含cookie,session等等之类的。但是这类静态文件是公开的，大家都可以访问。攻击思路可以参考下面这张图
![](http://i1.piimg.com/567571/f2cebfa3ef756e30.png)

##一些杂事
通常，网站不需要身份验证即可访问其公共静态文件。因此，缓存的文件是可公开访问的 - 不需要验证

##满足条件
因此，基本上，需要两个条件来存在此漏洞：
1.Web缓存功能设置为Web应用程序通过其扩展名来缓存文件  
2.请求 http://www.example.com/home.php/non-existent.css这类网页，服务器返回的实际上是home.php内容而不是css内容

##视频链接
https://www.youtube.com/watch?v=e_jYtALsqFs&feature=youtu.be



##个人理解
我是这样理解的，像一个很大用户量的网站，比如zone.qq.com。它会在全世界有很多的代理服务器(cdn)，假设他就在上海有一个，这类网站为了保证用户体验(就是加载网页的时候不能太慢，卡在那半天不动),会在上海的这台代理服务器上存有一些静态资源，图片,js,css之类的。假设你的个人设置页面的链接是zone.qq.com/setting 。当你请求zone.qq.com/setting/2333.css的时候，总服务那里会知道不存在2333.css 这个文件，你请求的一定是setting这个页面，好，他会把响应包发送给代理服务器，然后代理服务器发现你请求的是一个静态资源，2333.css。怎么办呢，我这代理服务器上现在没有2333.css这个文件啊，缓存下来吧。方便后面其它的上海地区qq用户也请求 2333.css的时候又要去总服务器下载一次2333.css。(这里代理服务就是保存静态资源)。好了，现在就会在代理服务器上创建一个缓存，2333.css，里面实际上的内容是setting的内容。
其它上海用户再通过这台上海代理服务器访问2333.css的时候，代理服务器就会访问静态资源2333.css。这么以来，一次攻击就完成了。

原文
http://omergil.blogspot.hk/2017/02/web-cache-deception-attack.html
翻译:b5mali4

