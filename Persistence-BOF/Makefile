all: bof

bof:
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin' || echo '_bin exists'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -O2 -c -o _bin/registry_run.x64.o registry_run/registry_run.c -mno-stack-arg-probe && x86_64-w64-mingw32-strip --strip-unneeded _bin/registry_run.x64.o) && echo '[+] registry_run' || echo '[!] registry_run build failed'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -O2 -c -o _bin/schtask.x64.o schtask/schtask.c -mno-stack-arg-probe && x86_64-w64-mingw32-strip --strip-unneeded _bin/schtask.x64.o) && echo '[+] schtask' || echo '[!] schtask build failed'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -O2 -c -o _bin/service_persist.x64.o service/service_persist.c -mno-stack-arg-probe && x86_64-w64-mingw32-strip --strip-unneeded _bin/service_persist.x64.o) && echo '[+] service_persist' || echo '[!] service_persist build failed'

clean:
	@(rm -rf _bin)

