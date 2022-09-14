This repository contains the u-dccp project.

## Instructions

Possibly you have to install the kernel headers to compile:
sudo apt-get install linux-headers-$(uname -r)

make

run: sudo insmod dccp_udp_converter.ko
exit: sudo rmmod dccp_udp_converter.ko

## Licensing

u-dccp is NOT open source software. 
u-dccp is made available to you under a source-available license, which
means only non-commercial usage is permitted.

The specific terms of this source-available license can be found in the file
"LICENSE".