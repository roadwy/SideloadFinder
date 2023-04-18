<h1 align="center">
<p align="center">
  <img alt="Logo" src="doc/SideLoadFinder.png" height="30%" width="30%">
</p>
  SideloadFinder
  <br>
</h1>


## Description

A simple script which automates the process of discovering and exploiting DLL Hijacks in target binaries by frida hook, icon created by [ERNIE Bot](https://yiyan.baidu.com/).

## Features

- Dynamic DLL Hijacks(use like LoadLibrary)
- Static DLL Hijacks(DIRECTORY_ENTRY_IMPORT)

## Usage:
```
sideload_finder.py  -i  testcase -o out.csv

{'type': 'send', 'payload': {'payload_type': 'dll', 'dll': 'wsc.dll', 'flag': 0}}
{'type': 'send', 'payload': {'payload_type': 'proc', 'proc': '_run@4'}}
ae90c0a08698d698182043ede236e528.exe,wsc.dll,0x0,_run@4
```

<p align="center">
 <img alt="output" src="doc/output.jpg" height="80%" width="80%">
</p>

## Reference 
https://github.com/knight0x07/ImpulsiveDLLHijack

