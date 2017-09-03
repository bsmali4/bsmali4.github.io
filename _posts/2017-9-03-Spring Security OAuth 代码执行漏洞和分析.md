---
layout: post  
title: "Spring Security OAuth 代码执行漏洞和分析"  
date: 2017-09-3
description: "java安全"
tag: java安全
---

## 介绍  
Spring Security OAuth历史上爆出过一个CVE-2016-4977，本篇文章主要作为本人在学习和调试这个漏洞时候的过程记录。
## 漏洞描述  
官方对于CVE-2016-4977的描述比较模糊，大概讲了下漏洞触发的原理，我们只知道最终的原因是因为执行了SpEL表达式[https://pivotal.io/de/security/cve-2016-4977](https://pivotal.io/de/security/cve-2016-4977)。对比给出的利用poc，我们来理解下整个运行的流程。
http://localhost:8080/oauth/authorize?responsetype=token&clientid=acme&redirect_uri=${1-65535}
##  漏洞复现  
![](http://ohsqlm7gj.bkt.clouddn.com/17-9-3/71366994.jpg)可以看到表达式是被执行了的。
##  漏洞分析  
对别补丁，![](http://ohsqlm7gj.bkt.clouddn.com/17-9-3/9636761.jpg)
我们可以知道是org.springframework.security.oauth2.provider.endpoint.SelView.java处出了问题。
我们在关键位置下断点来调适我们的程序，经过调试之后发现在代码处String result = this.helper.replacePlaceholders(this.template, this.resolver)执行后,${1-65535}被执行
继续在此处下断点，其中内容是spring框架定义的一个模版
![](http://ohsqlm7gj.bkt.clouddn.com/17-9-3/39716306.jpg)，后面所有的异常信息网页都是基于这个模版去修改的。进入这个函数来到org.springframework.util.PropertyPlaceholderHelper里面，其中parseStringValue函数是整个异常网页内容的生成函数。
![](http://ohsqlm7gj.bkt.clouddn.com/17-9-3/10984658.jpg)经过对整个函数的调试分析，可以理出函数的大致流程如下，关键代码有注释:  
```
protected String parseStringValue(String strVal, PropertyPlaceholderHelper.PlaceholderResolver placeholderResolver, Set<String> visitedPlaceholders) {
        StringBuilder result = new StringBuilder(strVal);// 新建一个string buffer ，第一次是默认的 <html><body><h1>OAuth Error</h1><p>${errorSummary}</p></body></html>**/
        int startIndex = strVal.indexOf(this.placeholderPrefix);//获取result中${的位置，其实后面整个流程就是，将异常的信息替换掉${}中的内容，然后将其包装成html流

        while(startIndex != -1) {
            int endIndex = this.findPlaceholderEndIndex(result, startIndex);//获取}结束的位置
            if(endIndex != -1) {
                String placeholder = result.substring(startIndex + this.placeholderPrefix.length(), endIndex);// 提取出${}之间的字符
                String originalPlaceholder = placeholder;
                if(!visitedPlaceholders.add(placeholder)) {
                    throw new IllegalArgumentException("Circular placeholder reference \'" + placeholder + "\' in property definitions");
                }

                placeholder = this.parseStringValue(placeholder, placeholderResolver, visitedPlaceholders);//再次解析，通过递归调用一次性将${}中的字符提取出来
                String propVal = placeholderResolver.resolvePlaceholder(placeholder);//将上面提到的${}之间的内容作为参数传给resolvePlaceholder生成异常信息
                if(propVal == null && this.valueSeparator != null) {
                    ...
                }

                if(propVal != null) {
                    propVal = this.parseStringValue(propVal, placeholderResolver, visitedPlaceholders);//将生成之后的异常信息再次调用parseStringValue函数
                    result.replace(startIndex, endIndex + this.placeholderSuffix.length(), propVal);
                    ...
        }

        return result.toString();
    } 
```  
![](http://ohsqlm7gj.bkt.clouddn.com/17-9-3/83104366.jpg)
SpEL表达式，当函数将error=&quot;invalid_grant&quot;, error_description=&quot;Invalid redirect: ${1-65535} does not match one of the registered values: [http://www.baidu.com]&quot;中的1-65535提取出来并解析了。于是1-65535被执行了。这也符合了官方的描述。
整理整个流程如下:  
1.首次进入时，系统以默认模版内容<html><body><h1>OAuth Error</h1><p>${errorSummary}</p></body></html>作为函数parseStringValue的参数。  
2. 函数将参数中被${}包裹的内容替换成具体的报错信息，最后展现给用户,具体的报错信息是怎么生成的在函数resolvePlaceholder里面。  
3. 第一次经过resolvePlaceholder处理，举报的报错信息为如下error=&quot;invalid_grant&quot;, error_description=&quot;Invalid redirect: ${1-65535} does not match one of the registered values: [http://www.baidu.com]&quot;  
4. 系统再次调用函数parseStringValue解析，将error=&quot;invalid_grant&quot;, error_description=&quot;Invalid redirect: ${1-65535} does not match one of the registered values: [http://www.baidu.com]&quot;作为参数传给parseStringValue。  
5. 函数再次解析出${}  中的内容也就是1-65535，将其传给resolvePlaceholder处理，但是resolvePlaceholder里面是什么？
SpEL表达式啊，于是就被解析，最终一步步封装展示到网页上。
##  补丁分析  
![](http://ohsqlm7gj.bkt.clouddn.com/17-9-3/20671371.jpg)
可以看到它是将this.helper = new PropertyPlaceholderHelper("${", "}");变成了  this.helper = new PropertyPlaceholderHelper( new RandomValueStringGenerator().generate() + "{", "}")换言之也就是将$先变成一个随机数，那么我们的${1-65535}无法被解析成SpEL,但是RandomValueStringGenerator().generate()是一个随机的6位数，理论上依旧存在被爆破的风险。假设我们爆破出来为123456,然后http://localhost:8080/oauth/authorize?responsetype=token&clientid=acme&redirect_uri=123456{1-65535}即可执行。
