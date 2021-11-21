pushd \\vmware-host\Shared Folders\hevd-drivexp
cd stackoverflow
cd shellcode
gcc scAdresses.c -o scAdresses.exe
scAdresses.exe
cd ..
gcc bofPayload.c -lpsapi -o bofPayload.exe
bofPayload.exe
cmd /k