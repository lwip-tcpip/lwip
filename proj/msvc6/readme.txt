lwIP for Win32

***WARNING***
The current CVS code of this port isn't much tested.
***WARNING***

This is a quickly hacked port and example project of the lwIP library to
Win32/MSVC.

Due to the nature of the lwip library you have to copy this whole project
into a new subdir in proj and modify lwipopts.h to your needs. If you move
it to another directory besides proj, you have to update the include paths
in the project settings.

Included in the proj/msvc6 directory is the network interface driver using
the winpcap library.

There is no more documentation yet. Try to figure it out yourself.

This is provided as is, it's just a hack to test some stuff, no serious
implementation.

Florian Schulze (florian.proff.schulze@gmx.net)

lwIP: http://www.sics.se/~adam/lwip/
WinPCap: http://netgroup-serv.polito.it/winpcap/