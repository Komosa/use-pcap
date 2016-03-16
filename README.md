# use-pcap

Small tool to call `pcap_*` functions in desired order
with desired parameters (conf.txt, but sensible defaults)
without recompilation.

## example
- `use-pcap fdevs` - list interfaces
pick one and set it in conf.txt, _sniff=interfacenamehere_
- `use-pcap create bufsize promisc snap timeout activate nonblock filter dispatch` - create, configure, activate and run sniffing
- `use-pcap help` - list of possible functions

code is quite short, so you probably could tailor it to your needs

### linux
`g++ main.cpp -o use-pcap -O3 -W -Wextra -lpcap`
run with sudo

### noncygwin windows
requirement: VS2015
there is .sln file and .vcxproj, so you can compile it via gui

alternative: use msbuild.exe in similar fashion as is presented in _build-cygwin.sh_
