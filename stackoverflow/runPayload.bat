pushd \\vmware-host\Shared Folders\hevd-drivexp
cd stackoverflow
gcc bofPayload.c -lpsapi -o bofPayload.exe
bofPayload.exe
cmd /k