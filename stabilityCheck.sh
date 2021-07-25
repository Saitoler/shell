#! /bin/bash

#################################################
##########    AC 稳定性检测脚本   ###############

# 将所有的检查项，输出到一份文档中，便于查看 
# 最终日志结果： 于运行目录下寻找以当天日期命名的，.stabilityCheckLog 的文件


## 1. 宕机检查
## 2. 版本号检查
## 3. 运行时间检查 
## 4. 堆栈检查
## 5. 系统日志检查
## 6. 系统 CPU 检查
## 7. 系统内存检查
## 8. 进程句柄检查（可自定义添加要监测的进程）
## 9. 进程 CPU 占用（可自定义添加要监测的进程）
## 10.进程内存占用（可自定义添加要监测的进程）
## 11.异常进程监控（持续在 z Z D 状态进程）
## 12.磁盘占用检查
## 13.IO 水平检查
## 14.驱动调试日志检查




### 打印一点提示信息：
echo ""
echo "##################  欢迎使用 稳定性监控自动化脚本   ############################"
echo "脚本运行预计需要 10+ min，运行完成会生成以当天日期命名的 .stabilityCheckLog 文件"
echo "###########          请在脚本运行当前目录下获取           ######################"
echo "###########  脚本同一天可重复执行，不用手动清理 log 文件  ######################"

# 日志信息保存到 .stabilityCheckLog 文件中, 以当天日期命名
logfile="`date -d "today" +%Y%m%d`.stabilityCheckLog"

# 运行前先监测日志文件是否已存在，若已存在，为避免重复写，先删除该文件

if [ -f $logfile ];then
	rm $logfile
fi


splitInfo(){
	echo "" >> $logfile
	echo "###~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~###" >> $logfile
	echo "" >> $logfile
}




### 1. 宕机检查
###  - 若有宕机，则打印宕机日期，并保存宕机文件到 以当前日期命名的 .crash 文本中
###  - 若无宕机，则打印 Crash Check ok!!! no crash accurred these days

# 检查前的操作： 创建宕机备份目录
crashBak="/data/crash/"
if [ ! -d $crashBak ];then
	mkdir -p "/data/crash/"
fi

splitInfo

echo "宕机监测：" >> $logfile
if [ `lkcd_cnf -r  2>/dev/null | wc -l` -gt 0 ];then
	echo "宕机时间为： `lkcd_cnf -r | head -1| awk -F ":" '{print $2}' | awk -F " " '{print $1}'`" >> $logfile
	today=$(date -d "today" +%Y%m%d)
	lkcd_cnf -r > "$crashBak$today.crash"
	echo "宕机信息已备份到 /data/crash 目录中" >> $logfile
else
	echo "宕机检查通过！ 未发现宕机信息" >> $logfile
fi


### 2. 设备当前版本号检查：
splitInfo
echo "设备当前版本号: " >> $logfile
cat /app/appversion  | head -3 >> $logfile


### 3. 设备运行时间检查：
splitInfo
echo "设备运行时间: `uptime`" >> $logfile


### 4. 堆栈检查：
splitInfo
echo "堆栈监测：" >> $logfile
if [ `ls -l /ac/debug/bugreport/core.bak | grep nac | wc -l` -eq 0 ];then
	echo "/ac/debug/bugreport/core.bak 目录下未发现 nac_agent 的新堆栈，其他堆栈信息如下：" >> $logfile
	ls -l /ac/debug/bugreport/core.bak >> $logfile

fi

echo "" >> $logfile
if [ `ls -l /ac/debug/bugreport/core | grep nac | wc -l` -eq 0 ];then
	echo "/ac/debug/bugreport/core 目录下未发现 nac_agent 的新堆栈，其他堆栈信息如下：" >> $logfile
	ls -l /ac/debug/bugreport/core >> $logfile
fi


### 5.系统日志检查
###    检查分两部分：
###    a. 所有模块的 错误  日志，查今天，昨天两天的日志
###    b. 所有模块的 告警  日志，查今天，昨天两天的日志

splitInfo
echo "系统日志监测："  >> $logfile
echo "同步监测最近两天的错误日志，告警日志，针对所有模块，获取前 100 条" >> $logfile
touch /ac/module/debug/cgibase_debug_flag

today=$(date -d "today" +%Y%m%d)
yestaday=$(date -d "yesterday" +%Y%m%d)

cgiName="/ac/webui/cgi/logview.cgi"

errjdata='{"start":0,"limit":50,"filter":{"option":{"report":["error"],"info":false,"error":true,"warn":false,"debug":false},"filter":["DLAN总部(lmdlan)","防火墙(fwserver)","智能报表(listener)","MLineDetect_VPN(MLineDetect_VPN)","邮件审计(delaysnd)","应用审计(actrace)","访问日志系统(aclog)","流量统计(fluxlogd)","病毒库升级(kvupd)","DOS防御(dosckctl)","多线路检测(link_monitord)","SSL内容识别(sslproxy)","磁盘故障检测(data_fsck.sh)","网络准入系统(singress)","日志中心同步器(datasync)","邮件告警(alarmmailsnd)","网关杀毒(kvd)","SSL控制(ssl_ctl)","ARP防护系统(arpguardctl)","DHCP(lfwdhcp)","流量管理(fluxctrld)","邮件代理(maildispatcher)","外发文件告警(FileAlarm)","snmpBulk(snmpBulk)","高可用性(ha_sync)","流量告警(fluxalarm)","上网策略管理(netpolicyd)","流量配额(fluxmgrd)","用户同步(syncusrd)","SYNCCAMSD 查询进程 (synccamsd)","日志中心异常告警(mailbubbalarm)","表创建器(actablecreator)","日志清理(aclogcleanner)","Bypassd 后台进程(fiberbpd)","附件列表生成器(attachlistcreator)","共享上网检测(proxycheck)","移动终端(acwireless)","SMS_SP后台(sms_sp)","SMS_PROXY后台(sms_proxy)","sync_ldap后台(sync_ldapd)","ac_radiusd后台(ac_radiusd)","网络质量监测(qoe_app)","假死检测(monitor_daemon)","clearuser(ac-clear-expire-user)","SYNCORACLED查询进程(syncoracled)","SYNCMSSQLD 查询进程(syncmssqld)","SYNCMYSQLD 查询进程(syncmysqld)","用户认证服务监控(ac-auth-mon)","告警事件检测(alarmevent)","SYNCDB2D 查询进程(syncdb2d)","ADNSHOST后台(adnshost)","SOCKS45代理(socksproxy)","ICAP客户端(icap_client)","HTTP代理(web_proxy)","网安对接(nm-monitor)","NTLM认证(ac-auth-ntlm)","radius服务器(radius_server)","网安RESTful对接服务(nm-docksvr)","线路流量(line_flux)","BBC客户端","规则库升级(database_update)","故障中心(fault_center)","双机伴随升级(ha_upgrade)","apt后台服务(aptserver)","slapdsync(slapd)","日志导出(ftp_upfile)","fradius后台服务(freeradius-server)","https-redirect-mon后台服务(https-redirect-mon)","链路负载统计(prstatd)","资产上报(asset-report)"],"time":"dateTorep"},"opr":"list"}'

# 查询今天的错误日志
echo "今天的错误日志：" >> $logfile
echo ${errjdata} | sed "s/dateTorep/${today}/g" > logview.json
${cgiName} -f ./logview.json | grep "\"data\"" >> $logfile
echo "-----------------------------------------------------------------------------" >> $logfile


# 查询昨天的错误日志
echo "昨天的错误日志：" >> $logfile
echo ${errjdata} | sed "s/dateTorep/${yestaday}/g" > logview.json
${cgiName} -f ./logview.json | grep "\"data\"" >> $logfile
echo "-----------------------------------------------------------------------------" >> $logfile


warnjdata='{"start":0,"limit":50,"filter":{"option":{"report":["warn"],"info":false,"warn":true,"error":false,"debug":false},"filter":["DLAN总部(lmdlan)","防火墙(fwserver)","智能报表(listener)","MLineDetect_VPN(MLineDetect_VPN)","邮件审计(delaysnd)","应用审计(actrace)","访问日志系统(aclog)","流量统计(fluxlogd)","病毒库升级(kvupd)","DOS防御(dosckctl)","多线路检测(link_monitord)","SSL内容识别(sslproxy)","磁盘故障检测(data_fsck.sh)","网络准入系统(singress)","日志中心同步器(datasync)","邮件告警(alarmmailsnd)","网关杀毒(kvd)","SSL控制(ssl_ctl)","ARP防护系统(arpguardctl)","DHCP(lfwdhcp)","流量管理(fluxctrld)","邮件代理(maildispatcher)","外发文件告警(FileAlarm)","snmpBulk(snmpBulk)","高可用性(ha_sync)","流量告警(fluxalarm)","上网策略管理(netpolicyd)","流量配额(fluxmgrd)","用户同步(syncusrd)","SYNCCAMSD 查询进程 (synccamsd)","日志中心异常告警(mailbubbalarm)","表创建器(actablecreator)","日志清理(aclogcleanner)","Bypassd 后台进程(fiberbpd)","附件列表生成器(attachlistcreator)","共享上网检测(proxycheck)","移动终端(acwireless)","SMS_SP后台(sms_sp)","SMS_PROXY后台(sms_proxy)","sync_ldap后台(sync_ldapd)","ac_radiusd后台(ac_radiusd)","网络质量监测(qoe_app)","假死检测(monitor_daemon)","clearuser(ac-clear-expire-user)","SYNCORACLED查询进程(syncoracled)","SYNCMSSQLD 查询进程(syncmssqld)","SYNCMYSQLD 查询进程(syncmysqld)","用户认证服务监控(ac-auth-mon)","告警事件检测(alarmevent)","SYNCDB2D 查询进程(syncdb2d)","ADNSHOST后台(adnshost)","SOCKS45代理(socksproxy)","ICAP客户端(icap_client)","HTTP代理(web_proxy)","网安对接(nm-monitor)","NTLM认证(ac-auth-ntlm)","radius服务器(radius_server)","网安RESTful对接服务(nm-docksvr)","线路流量(line_flux)","BBC客户端","规则库升级(database_update)","故障中心(fault_center)","双机伴随升级(ha_upgrade)","apt后台服务(aptserver)","slapdsync(slapd)","日志导出(ftp_upfile)","fradius后台服务(freeradius-server)","https-redirect-mon后台服务(https-redirect-mon)","链路负载统计(prstatd)","资产上报(asset-report)"],"time":"dateTorep"},"opr":"list"}'


# 查询今天的告警日志
echo "今天的告警日志" >> $logfile
echo ${warnjdata} | sed "s/dateTorep/${today}/g" > logview.json
${cgiName} -f ./logview.json | grep "\"data\"" >> $logfile
echo "-----------------------------------------------------------------------------" >> $logfile


# 查询昨天的告警日志
echo "昨天的告警日志" >> $logfile
echo ${warnjdata} | sed "s/dateTorep/${yestaday}/g" > logview.json
${cgiName} -f ./logview.json | grep "\"data\"" >> $logfile


# 善后处理，清理掉中间文件： logview.json
rm ./logview.json


### 6. 系统 CPU 持续占用检查：
splitInfo
echo "系统 CPU 持续占用检查：" >> $logfile
echo "当前设备 CPU数：`cat /proc/cpuinfo | grep processor | wc -l`" >> $logfile
echo "统计整体 CPU 空闲值，采集间隔 10s 采集 2 分钟" >> $logfile
echo "" >> $logfile
mpstat -P ALL 10 12 | grep Average >> $logfile

echo "" >> $logfile
echo "统计原始 mpstat 数据，采集间隔 10s，采集1分钟（这项为了发现是否有 CPU 分发不均，网卡队列异常的情况）" >> $logfile
echo "" >> $logfile
mpstat -P ALL 10 6 | grep -v Average >> $logfile


### 7. 系统内存持续占用检查：
###    每10s 检查一次，检查1分钟
splitInfo

echo "系统内存持续监测：" >> $logfile
echo "连续1分钟监测系统内存使用情况，采集间隔10s, 采集6次数据" >> $logfile
echo "" >> $logfile
for i in {1..6}
do
	free -m >> $logfile
	sleep 10
done


### 8. 进程句柄监控
###   此处可自定义添加要监控的进程
splitInfo

echo "句柄数监控：" >> $logfile
echo "nac_agent 句柄占用数：`lsof -nc nac_agent | wc -l`" >> $logfile


### 9. 进程CPU占用监控
###    此处可自定义添加要监控的进程
###    每 10s 采集一次数据，采集 6次数据
splitInfo

echo "进程 CPU 占用监测：" >> $logfile
echo "top 中统计 nac_agent CPU 占用情况，采集间隔 10s，采集 6 次" >> $logfile
echo "" >> $logfile
top -b -n 6 -d 10 | grep nac_agent >> $logfile


### 10.进程内存监控
###    此处可自定义添加要监控的进程
###    每 10s 采集一次数据，采集6次数据
splitInfo

echo "进程内存监测：" >> $logfile
echo "进程 nac_agent 内存占用数据采集，10s 采集一次，采集 6次：" >> $logfile
echo " " >> $logfile
for i in {1..6}
do
	ps auxf | grep -w "/ac/module/nac_server/app/nac_agent" | grep -v grep >> $logfile
	echo "" >> $logfile
	sleep 10
done


### 11.异常进程监控
###   监测是否有一直是z Z D 状态的进程
###   排除已知非问题的 fiberbp_thread 进程，该进程确认非问题
splitInfo

echo "异常状态（z Z D） 进程监控，10s 采集一次，采集 12 次" >> $logfile
echo "无进程结果输出，或无持续该状态进程即表示检测通过！ " >> $logfile
echo "" >> $logfile

for i in {1..12}
do
	ps auxf | grep -E "z|Z|D" | grep -v grep | grep -v fiberbp_thread | grep -v apache | grep -v snmp >> $logfile
	echo "" >> $logfile
	sleep 10
done


### 12.磁盘检查
###   采集间隔 60s, 采集 5次

splitInfo


echo "磁盘使用情况监测，采集间隔 1min, 采集5次" >> $logfile
echo "" >> $logfile

for i in {1..5}
do
	df -h >> $logfile
	echo "" >> $logfile
	sleep 60
done


### 13.IO检查
###   采集间隔 10s, 采集 2min

splitInfo

echo "IO 监测：采集间隔 10s, 采集 1min:" >> $logfile
echo "" >> $logfile

for i in {1..6}
do
	iostat >> $logfile
	sleep 10
done


### 14.驱动调试
###  采集间隔 10s, 采集3次

splitInfo

echo "驱动调试日志监测：无输出代表检测通过，无异常！" >> $logfile

for i in {1..3}
do
	dmesg -c >> $logfile
	sleep 10
done


splitInfo
### 检查完毕
echo ""
echo "稳定性检查完毕！！！  请于脚本执行当前目录获取检查报告。"