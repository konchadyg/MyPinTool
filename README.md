# MyPinTool
EXECUTION TRACING W/ DYNAMIC BINARY INSTRUMENTATION

Pin is a tool for the instrumentation of programs. It supports the Linux, OS X and Windows operating systems and executables for the IA-32, Intel(R) 64 and Intel(R) Many Integrated Core architectures. Pin allows a tool to insert arbitrary code (written in C or C++) in arbitrary places in the executable. The code is added dynamically while the executable is running. This also makes it possible to attach Pin to an already running process.
Pin provides a rich API that abstracts away the underlying instruction set idiosyncrasies and allows context information such as register contents to be passed to the injected code as parameters. Pin automatically saves and restores the registers that are overwritten by the injected code so the application continues to work. Limited access to symbol and debug information is available as well.
Pin includes the source code for several example instrumentation tools like basic block profilers, cache simulators, instruction trace generators, etc. It is easy to derive new tools using the examples as a template. 

Modules Implemented:
1.	Counting the number of instructions executed with the target binary code.
2.	Printing of loaded images whilst binary is in execution.
3.	Counting the number of instructions for each instruction (Both static and dynamic).
4.	Printing of all function calls/returns and function symbol names.
5.	Spotting heap management calls like malloc, free etc. and bytes allocated.
6.	Seek and detect all syscalls interpret a set of well-known system calls with its arguments and return values.

Setup and Execution of Plugin:
Setup:
1.	First and foremost, download the Pin Tool from here (For Linux systems).
2.	Unzip and untar the file pin-3.4-97438-gf90d1f746-gcc-linux.tar.gz in home directory.
3.	Unzip the attachment MyPinTool.zip into ~/pin-3.4-97438-gf90d1f746-gcc-linux/source/tools directory.
4.	Go to the directory MyPinTool.
Execution:
5.	Run the make all command:
 
A new directory obj-intel64 will be created. With .o and .so files in it.
6.	Go into obj-intel64.
7.	Run the PIN command giving the absolute path to a binary, say ls.
8.	The program will generate several .out files, each name corresponding to the modules described earlier. Each output file can be viewed on screen using vi or any other text editor.
