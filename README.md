# Automated_Connectivity_Test
基于树莓派3B+的连通性判断自动化小程序
## 为什么要写这个小程序 ##

 - 对于Mesh类的产品来说，同一个Mesh网络中，不同的Mesh station都是共SSID的，且每一个Mesh station可能存在2.4G与5G两个频段（某些产品可能存在两个5G频段），而这两个频段一般也是共SSID的。基于这种情况，对于一个典型的Mesh网络：一个主Mesh station加上两个从 Mesh Station，这个Mesh网络中可能存在3（3台设备）* 2（2个频段）= 6 个可供关联的共SSID的信号，如果再开启了访客网络，将有**很多重复工作量**
 - 对于共SSID的信号，我们无法通过简单的关联去区分，必须通过关联不同的BSSID进行区分，工作中常用的手段就是用WirelessMon这款工具，但生产环境总会有莫名其妙的问题，因此采用这种手段**无法给人操之在我的保证，影响工作效率**
 
 - 整套代码基于Linux C，这意味着可以轻松地部署到除了树莓派之外的其余小开发版上，大大提升了**部署的便捷性**
 
## 简略流程图 ##
![Image text](https://github.com/yanqiaoyu/Automated_Connectivity_Test/blob/master/picture/1.jpg)

## 一些需要改进的地方 ##
- [ ] 清晰地保存Log，能快速得知关联失败的位置
- [ ] 对于某些不需要针对访客网络进行测试的情况，可以跳过
- [ ] 优化代码的可读性，为了方便，目前只分了两个C文件
- [ ] 容错处理
