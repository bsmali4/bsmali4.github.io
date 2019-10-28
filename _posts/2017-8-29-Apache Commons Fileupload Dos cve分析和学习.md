---
layout: post  
title: "Apache Commons Fileupload cve分析和复习"  
date: 2017-08-29
description: "java安全"  
tag: java安全
---

##  1.介绍
Apache Commons Fileupload是阿帕奇基金会开源的一个java上传文件工具类。历史上爆出了两个dos漏洞，了解详情可以查阅[http://commons.apache.org/proper/commons-fileupload/security-reports.html](http://commons.apache.org/proper/commons-fileupload/security-reports.html)
### CVE2014-0050  
一个比较古老的 dos漏洞，通过查看commit提交纪录,可以看到一条古老的提交纪录  
[https://github.com/apache/commons-fileupload/commit/c61ff05b3241cb14d989b67209e57aa71540417a](https://github.com/apache/commons-fileupload/commit/c61ff05b3241cb14d989b67209e57aa71540417a)
```  
-        this.boundary = new byte[boundary.length + BOUNDARY_PREFIX.length];  
        this.boundaryLength = boundary.length + BOUNDARY_PREFIX.length;
 +        if (bufSize < this.boundaryLength + 1) {
 +            throw new IllegalArgumentException(
 +                    "The buffer size specified for the MultipartStream is too small");
 +        }
 +        this.boundary = new byte[this.boundaryLength];
```
可以看出修复方案是 在new byte[this.boundaryLength] 之前检查了一下长度，如果 this.boundaryLength > bufSize - 1就抛出异常。从调用的地方可以看到  
![](http://pic.findbugs.top/17-8-29/66931659.jpg)
size的值是4096，加上BOUNDARY_PREFIX这个默认长度为4的数组之后要大于4095，那么boundaryLength本身的值只要大于4091即可。BOUNDARY_PREFIX的定义可以在类的开始位置找到
![](http://pic.findbugs.top/17-8-29/39972941.jpg)  
整个流程可以理解Apache Commons Fileupload默认会在用户上传的头部添加一些标识。
其实漏洞真正的触发原因是死循环，在代码处
![](http://pic.findbugs.top/17-8-29/77083798.jpg)
原本开发者的意图是想通过抛出异常让程序跳出死循环，可是把buffer的长度设置为4096的话，input.read()的返回值永远不会为－1，这就导致了作者企图让程序跳出循环的条件被破坏了。
其中跟踪到findSeparator发现buffer其实是会添加boundary到其内容中的。
![](http://pic.findbugs.top/17-8-30/2263169.jpg)
那么整个流程就可以理解了，如果boundary超过4091，会导致buffer超过4096,那么input.read()恒不为－1，这样一样就永远无法抛出异常，那么程序就会一直在死循环里面，这样导致了dos。
###测试攻击
boundary之类的可以根据rfc2046[http://tools.ietf.org/html/rfc2046](http://tools.ietf.org/html/rfc2046)去查阅，我们只要伪造下就可以了。
![](http://pic.findbugs.top/17-8-30/43324866.jpg)
用burp多开几个线程去跑，然后就回发现cpu占用的比较多。
![](http://pic.findbugs.top/17-8-30/25105076.jpg)

### CVE-2016-3092  
分析commit了，发现了修改的地方如下
![](http://pic.findbugs.top/17-8-30/59279019.jpg)
修复的地方还是和CVE2014-0050一样的位置，只是这次将bufSize扩容了。从修复层面上来看，buffer的长度的不足回导致整个程序源码算法的性能受到影响。


## 参考链接
https://threathunter.org/topic/594139ee03027c9d712abeff
