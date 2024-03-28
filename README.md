# LKM Info

A simple tool for parsing and patching linux loadable kernel module files(*.ko).

## Build

```
$ python3 -m venv .env
$ source .env/bin/activate
$ (.env) pip install -r requirements.txt
```

## Run

Verify KO file:
```
$python -m lkminfo verify -k kernel -s kallsyms -m qca_cld3_wlan.ko 
Kernel Info:
File name: kernel (size: 45588488)
Symbol name: kallsyms
Symbols in kernel:
	PDE_DATA crc: 176800512
	PageMovable crc: 363328703
	__ClearPageMovable crc: 1387416466
	__SetPageMovable crc: 820313904
	___pskb_trim crc: 3229430162
	___ratelimit crc: 1379520059
	// ...
	zlib_inflate_blob crc: 1698726776
	zlib_inflate_workspacesize crc: 3462054479

Module info:
File name: qca_cld3_wlan.ko
ELF:
	format: ELF
	arch: AARCH64
	sections:
		0x0 - 0x0 
		0x64 - 0x100 .note.gnu.build-id
		0x104 - 0x3038880 .text
		0x6586344 - 0x8821008 .rela.text
		// ...
		0x6162832 - 0x6586343 .strtab
Modinfo:
	parmtype = country_code:charp
	parmtype = enable_11d:int
	parmtype = enable_dfs_chan_scan:int
	description = WLAN HOST DEVICE DRIVER
	author = Qualcomm Atheros, Inc.
	license = Dual BSD/GPL
	parmtype = prealloc_disabled:byte
	depends = 
	vermagic = 4.4.192-perf-g2bcc393 SMP preempt mod_unload modversions aarch64
Versions:
	[NORMAL] module_layout crc: 403325714
	[IMPORT] PDE_DATA crc: 176800512
	[IMPORT] ipa_get_wdi_stats crc: 3754529128
	[IMPORT] dev_alloc_name crc: 501337273
	// ...
	[IMPORT] mutex_lock crc: 631107233
	[IMPORT] netlink_broadcast crc: 1557548019
	[IMPORT] __init_waitqueue_head crc: 2873150633
	[IMPORT] printk crc: 669098057
	[IMPORT] unregister_sysctl_table crc: 582500287
	[IMPORT] crypto_destroy_tfm crc: 7994579

Verify module by kernel:
[Warning]: crc of symbol `crypto_destroy_tfm` do not exists in kernel
[Warning]: crc of symbol `flush_work` do not exists in kernel
//...
[Warning]: crc of symbol `destroy_workqueue` do not exists in kernel
[Warning]: crc of symbol `unregister_netevent_notifier` do not exists in kernel
[Warning]: crc of symbol `crypto_shash_setkey` do not exists in kernel
verify result: True

Process finished with exit code 0
```

Patch KO file:
```
$ python -m lkminfo patch -k /Volumes/T7S/tmp/xiaomi11/kernel_origin/kernel -s /Volumes/T7S/tmp/xiaomi11/kernel/kallsyms -m /Volumes/T7S/tmp/xiaomi11/ko/helloko.ko -o /Volumes/T7S/tmp/xiaomi11/ko/helloko_patched.ko 
Before patch verify:
[Error]: module_layout mismatch, expect value in kernel: `1318537844`, actual value in module: `4056467412`
[Error]: vermagic mismatch, expect value in kernel: `5.4.210-qgki-g092ff07a848d SMP preempt mod_unload modversions aarch64`, actual value in module: `5.4.61-qgki-g7db0abb67-dirty SMP preempt mod_unload modversions aarch64`

After patch verify:
Verify result: OK
Patch done, output: /Volumes/T7S/tmp/xiaomi11/ko/helloko_patched.ko
```
