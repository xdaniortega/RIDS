# RIDS

Motivated by the continuous evolution in electronic device attack techniques and the sophistication they achieve, this research is based on being able to report unwanted modifications that an attacker can make to the most important part of an operating system, the kernel. Among the objectives of the project will aim that this detection code does not have a large impact on the performance of the equipment, adapting to existing workloads and that it is applicable to the market of HP printers. The latest protection measures such as the kernel page table isolation will be taken into account and the architecture of the page tables will be used to detect any attempt to modify their memory space, placing this project among the few which attempt to mitigate kernel vulnerabilities on devices that integrate an updated version of Linux.

## Launch RIDS and bareflank hypervisor  
`  
make driver_quick  
make start
`  
## Enjoy :)
