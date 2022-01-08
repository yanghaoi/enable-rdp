## fast-enable-rdp
This toool Enable RDP and set firewall by Windows API.

## How to use？

``` python
 enablerdp.exe
         -- this help
 enablerdp.exe any
         -- Output system version, registry value, service status and firewall status
 enablerdp.exe port 1
         -- Only set fDenyTSConnections=0 And fEnableWinStation=1(Ignore port set)
 enablerdp.exe port 2
         -- Modify the registry, start services, and set up firewalls
 enablerdp.exe port 3
         -- Set firewall on the specified port(Allow In,It will be remove same rule)
 enablerdp.exe port 4
         -- Try to start service(Ignore port input)
 enablerdp.exe port 5
         -- Try to Modify the registry for enable RDP on a lower version system(Ignore port input)
```

 ```enablerdp.exe any (get system information)```
 
 ![](https://cdn.jsdelivr.net/gh/yanghaoi/enable-rdp/images/howtouse.png)

 ```TermService is stop and  Firewall is ON```
  
![](https://cdn.jsdelivr.net/gh/yanghaoi/enable-rdp/images/check.png)
 
 ```Use  enablerdp.exe  3389 2 (start TermService  and  add rule-in in  Firewall )```
 
 ![](https://cdn.jsdelivr.net/gh/yanghaoi/enable-rdp/images/enable.png)
 
 
## reference

 https://docs.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwrule 
 
 https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-osversioninfoa 
 
 https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-gettcptable 
 
 https://docs.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwpolicy2-get_rules 
 
 https://docs.microsoft.com/zh-cn/windows/win32/termserv/detecting-the-terminal-services-environment 
 