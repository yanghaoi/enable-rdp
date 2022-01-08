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
 enablerdp.exe any (get system information)
 
 
 TermService is stop and  Firewall is ON
 
 Use  enablerdp.exe  3389 2 (start TermService  and  add rule-in in  Firewall )
 
 
 