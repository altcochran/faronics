md c:\temp

xcopy \\utlsoftdeploy\installs\Sophos\SophosZap.exe C:\temp\ /Y

cd c:\temp

start .\SophosZap.exe --confirm
