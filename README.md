<h1 align="center">
  <br>
  <a href="https://github.com/mkdirlove/RevShellz"><img src="https://github.com/mkdirlove/RevShellz/blob/main/logo.png" alt="RevShellz
"></a>
  <br>
  Yet another reverse shell generator written in Python.
  <br>
</h1>

#### Installation

Copy-paste this into your terminal:

```sh
git clone https://github.com/mkdirlove/RevShellz.git
```
```
cd RevShellz
```
```
python3 revshellz.py
```
or
```
python3 revshellz.py -h
```
#### Usage
``` 
░█▀▄░█▀▀░█░█░█▀▀░█░█░█▀▀░█░░░█░░░▀▀█
░█▀▄░█▀▀░▀▄▀░▀▀█░█▀█░█▀▀░█░░░█░░░▄▀░
░▀░▀░▀▀▀░░▀░░▀▀▀░▀░▀░▀▀▀░▀▀▀░▀▀▀░▀▀▀

     Made with ❤️  by @mkdirlove

usage: revshellz.py [-h] [-ip IP_ADD] [-p PORT] [-os OPERATING_SYS] [-rs REV_SHELL] [-l LIST]

RevShellz - Yet another reverse shell generator written in Python.

options:
  -h, --help            show this help message and exit
  -ip IP_ADD, --ip_add IP_ADD
                        IP address
  -p PORT, --port PORT  Port number
  -os OPERATING_SYS, --operating_sys OPERATING_SYS
                        Operating system
  -rs REV_SHELL, --rev_shell REV_SHELL
                        Reverse shell type
  -l LIST, --list LIST  List available reverse shells by OS category

```
#### Example

Listing reverse shells
```
python3 revshellz.py -l linux, windows, macos
```

#### Example

Generating reverse shell for Linux
```
python3 revshellz.py -ip 10.10.10.1 -p 1337 -rs 'bash -i' -os linux
```
Generating reverse shell for Windows
```
python3 revshellz.py -ip 10.10.10.1 -p 1337 -rs 'PowerShell #1' -os windows
```
Generating reverse shell for MacOS
```
python3 revshellz.py -ip 10.10.10.1 -p 1337 -rs 'nc mkfifo' -os linux
```
