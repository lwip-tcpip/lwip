# Microsoft Developer Studio Project File - Name="lwip4" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** NICHT BEARBEITEN **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=lwip4 - Win32 Debug
!MESSAGE Dies ist kein gültiges Makefile. Zum Erstellen dieses Projekts mit NMAKE
!MESSAGE verwenden Sie den Befehl "Makefile exportieren" und führen Sie den Befehl
!MESSAGE 
!MESSAGE NMAKE /f "lwip4.mak".
!MESSAGE 
!MESSAGE Sie können beim Ausführen von NMAKE eine Konfiguration angeben
!MESSAGE durch Definieren des Makros CFG in der Befehlszeile. Zum Beispiel:
!MESSAGE 
!MESSAGE NMAKE /f "lwip4.mak" CFG="lwip4 - Win32 Debug"
!MESSAGE 
!MESSAGE Für die Konfiguration stehen zur Auswahl:
!MESSAGE 
!MESSAGE "lwip4 - Win32 Release" (basierend auf  "Win32 (x86) Static Library")
!MESSAGE "lwip4 - Win32 Debug" (basierend auf  "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "lwip4 - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD CPP /nologo /W3 /GX /O2 /I "..\..\..\src\include" /I "..\..\..\src\include\ipv4" /I "..\..\..\proj\msvc6" /I "..\..\..\src\arch\msvc6\include" /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD BASE RSC /l 0x407 /d "NDEBUG"
# ADD RSC /l 0x407 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ELSEIF  "$(CFG)" == "lwip4 - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /YX /FD /GZ /c
# ADD CPP /nologo /W3 /Gm /GX /ZI /Od /I "..\..\..\src\include" /I "..\..\..\src\include\ipv4" /I "..\..\..\proj\msvc6" /I "..\..\..\src\arch\msvc6\include" /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /YX /FD /GZ /c
# ADD BASE RSC /l 0x407 /d "_DEBUG"
# ADD RSC /l 0x407 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"Debug\lwip4_d.lib"

!ENDIF 

# Begin Target

# Name "lwip4 - Win32 Release"
# Name "lwip4 - Win32 Debug"
# Begin Group "Quellcodedateien"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\..\..\src\core\ipv4\icmp.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\core\inet.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\core\ipv4\ip.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\core\ipv4\ip_addr.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\core\mem.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\core\memp.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\core\netif.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\core\pbuf.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\core\stats.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\core\sys.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\core\tcp.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\core\tcp_in.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\core\tcp_out.c
# End Source File
# Begin Source File

SOURCE=..\..\..\src\core\udp.c
# End Source File
# End Group
# Begin Group "Header-Dateien"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=..\..\..\src\include\lwip\api.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\include\lwip\api_msg.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\include\lwip\arch.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\arch\msvc6\include\arch\cc.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\arch\msvc6\include\arch\cpu.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\include\lwip\debug.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\include\lwip\def.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\include\lwip\err.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\include\lwip\event.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\include\ipv4\lwip\icmp.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\include\ipv4\lwip\inet.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\include\ipv4\lwip\ip.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\include\ipv4\lwip\ip_addr.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\arch\msvc6\include\arch\lib.h
# End Source File
# Begin Source File

SOURCE=..\lwipopts.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\include\lwip\mem.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\include\lwip\memp.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\include\lwip\netif.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\include\lwip\opt.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\include\lwip\pbuf.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\include\lwip\sys.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\include\lwip\tcp.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\include\lwip\tcpip.h
# End Source File
# Begin Source File

SOURCE=..\..\..\src\include\lwip\udp.h
# End Source File
# End Group
# End Target
# End Project
