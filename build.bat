@echo off
cls

cl /Ox getiptables.cpp utf8/*.cpp json/*.cpp network/*.cpp -D_USING_V110_SDK71_ -DSUBSYSTEM_CONSOLE /link /FILEALIGN:512 /OPT:REF /OPT:ICF /INCREMENTAL:NO /subsystem:console,5.01 user32.lib advapi32.lib ws2_32.lib iphlpapi.lib /out:getiptables.exe
cl /Ox getiptables.cpp utf8/*.cpp json/*.cpp network/*.cpp -D_USING_V110_SDK71_ -DSUBSYSTEM_WINDOWS /link /FILEALIGN:512 /OPT:REF /OPT:ICF /INCREMENTAL:NO /subsystem:windows,5.01 user32.lib shell32.lib advapi32.lib ws2_32.lib iphlpapi.lib /out:getiptables-win.exe
