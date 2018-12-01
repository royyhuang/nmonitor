#!/bin/bash -f
sudo depmod -a
sudo make
sudo make install
sudo insmod nmonitor.ko

clear
echo " "
echo " "
echo "-------------------------------------------------------------------------"
echo "Welcome to use Network Monitor."
echo "Press [1] to enter configration interface; [2] to skip config, [3] to remove module, and [4] to exit."
read -p "Please enter your option and press enter:" option

if [ $option == 1 ]
then
	./config
	sudo rmmod nmonitor
	sudo modprobe -C nmonitor.conf nmonitor
elif [ $option == 2 ]
then
	sudo rmmod nmonitor
	sudo modprobe -C nmonitor.conf nmonitor
elif [ $option == 3 ]
then
	sudo rmmod nmonitor
elif [ $option == 4 ]
then
   echo "Goodbye"
else
   echo "Invalid input."
fi
