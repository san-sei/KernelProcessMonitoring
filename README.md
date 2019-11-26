ProcessHooking.sys

This is a rootkit system kerenel driver that will recive commands (program name/process ID) from user mode and will start monitoring programs activities by hooking System Call Table.

The result that is a graph will be written into a file and then will be used to extract malicuious behavior. The entire approach is detailed in my paper here. https://ieeexplore.ieee.org/document/8277225
