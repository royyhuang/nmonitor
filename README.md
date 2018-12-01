# NetworkMonitor

## Description

NetMonitor is a Linux Kernel Module used to monitor network packets from different IP addresses or ports. You can monitor the status of every packet passed to your PC. Furthermore, you can specify some rules to accept or block some packets from a certain IP addresses or ports. This project is based on Netfilter, a subsystem of Linux.


## Usage

First, make sure you got gcc and libelf-dev installed on your computer. If your computer runs Ubuntu, you can install them like as the follows:
```
$ sudo apt install build-essential
$ sudo apt install libelf-dev
```


### Shell Script

Switch to the project directory, run the following commands:

```
$ dos2unix ./launcher.sh
$ chmod -x laucher.sh
$ ./launcher.sh
```

### Manual
The shell script should be able to walk you through the process. If not, please manually compile both kernel module and config program as follow: 
```
$ depmod -a
$ make
$ make install
```
Then run the config program by:
```
$ ./config
```
If the kernel module is already running, you need to remove the module to make the change affect by:
```
$ sudo rmmod nmonitor
```
Then insert kernel module by:
```
$ sudo modprobe -C nmonitor.conf nmonitor
```
