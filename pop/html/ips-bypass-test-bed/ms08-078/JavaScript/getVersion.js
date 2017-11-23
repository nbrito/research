/* 
 * $Id: getVersion.js,v 1.0 2008-12-25 08:55:53-02 nbrito Exp $ 
 *
 * Author: Nelson Brito <nbrito@sekure.org>
 *
 * Copyright© 2004-2009 Nelson Brito Research Center.
 * This file is part of Exploit Next Generation Private Tool.
 *
 * THIS IS UNPUBLISHED, CONFIDENTIAL, PROPRIETARY, AND PROTECTED SOURCE CODE BY
 * Nelson Brito Research Center.

   The Copyright notice above does not evidence any actual or intended *RELEASE
   PUBLICATION, AND/OR DISCLOSURE OF SUCH SOURCE CODE*.

   This code *MAY BE* provided as open source but IS NOT LICENSED under the GPL 
   or other common open source licenses.

   This computer software is protected by Brazil Copyright Laws:
   - Lei n.º 9.610, de 19.02.98 (Direitos Autorais);
   - Lei n.º 9.609, de 19.02.98 (Lei de Software);
   - Decreto n.º 2.553, de 16.04.1998.

  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES ARE
  DISCLAIMED. IN NO EVENT SHALL Nelson Brito BE LIABLE FOR ANY DIRECT, INDIRECT,
  INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES RESULTING FROM THE 
  USE OR MISUSE OF THIS SOFTWARE. */

/* Some module details to show when checking the modules. */
var getvers_caller  = "GETVERS";
var getvers_info    = "JavaScript OS and Browser Fingerprint Engine";
var getvers_version = "4.01.0001";

/* Function Name: Routine to check both major and minor versions of Operating Systems and Browser.
 *                
 *                *BOROWED FROM METASPLOIT*
 *
 * Description:   This can reliably detect browser versions for IE and Firefox even in the presence 
                  of a spoofed User-Agent. OS detection is more fragile and requires truthful 
                  navigator.appVersion and navigator.userAgent strings in order to be accurate for 
                  more than just IE on Windows.

   Targets:       Microsoft Windows (2000/XP/2003/VISTA), Microsoft Internet Explorer (4/5/5.5/6/7).
                  Linux (Gentoo/Ubuntu/Debian/RHEL/CentOS), Mozilla Firefox (1/1.5/2/3). */
function getVersion(){
	var useragent = navigator.userAgent, platform = "";

	platform = useragent;

	/* Identifying the major version of Microsoft Windows or Linux. */
	if(platform.indexOf("Windows NT 5.0")      != -1) { major = "2000";   }
	else if(platform.indexOf("Windows NT 5.1") != -1) { major = "XP";     }
	else if(platform.indexOf("Windows NT 5.2") != -1) { major = "2003";   }
	else if(platform.indexOf("Windows NT 6.0") != -1) { major = "VISTA";  }
	else if(platform.indexOf("Linux")          != -1) { major = "Linux";  }

	/* Identifying the minor version (distribution) of Linux. */
	if(major == "Linux"){
		if(useragent.indexOf("Gentoo")      != -1)  { minor = "Gentoo"; }
		else if(useragent.indexOf("Ubuntu") != -1)  { minor = "Ubuntu"; }
		else if(useragent.indexOf("Debian") != -1)  { minor = "Debian"; }
		else if(useragent.indexOf("RHEL")   != -1)  { minor = "RHEL";   }
		else if(useragent.indexOf("CentOS") != -1)  { minor = "CentOS"; }
	}

	/* Identifying Mozilla Firefox. */
	if(window.getComputedStyle){
		// Then this is a gecko derivative, assume firefox since that's the
		// only one we have sploits for.  We may need to revisit this in the
		// future.
		name = "Firefox";

		/* Identifying the minor version of Mozilla Firefox. */
		if(document.getElementsByClassName){
			version = "3.0";
		} else if (window.Iterator) {
			version = "2.0";
		} else if (Array.every) {
			version = "1.5";
		} else {
			version = "1.0";
		}
	}

	/* Identifying Microsoft Internet Explorer. */
	if(typeof ScriptEngineMajorVersion == "function"){
		name = "IExplorer";
		platform      = ScriptEngineMajorVersion().toString();
		platform     += ScriptEngineMinorVersion().toString();
		platform     += ScriptEngineBuildVersion().toString();

		/* Identifying the minor version of Microsoft Windows. */
		switch(platform){
			case "514615":
				major = "2000";
				minor = "SP0";
				break;
			case "515907":
				major = "2000";
				minor = "SP3";	//or SP2: oCC.getComponentVersion('{22d6f312-b0f6-11d0-94ab-0080c74c7e95}', 'componentid') => 6,4,9,1109
				break;
			case "518513":
				major = "2000";
				minor = "SP4";
				break;
			case "566626":
				// IE 6.0.2600.0000, XP SP0 English
				os_flaver = "XP"; 
				minor = "SP0";
				break;
			case "568515":
				// IE 6.0.3790.0, 2003 Standard SP0 English
				major = "2003";
				minor = "SP0";
				break;
			case "568827":
				major = "2003";
				minor = "SP1";
				break;
			case "568831":	//XP SP2 -OR- 2K SP4
				if (major == "2000"){
					minor = "SP4";
				}
				else{
					major = "XP";
					minor = "SP2";
				}
				break;
			case "568832":
				major = "2003";
				minor = "SP2";
				break;
			case "575730":
				// IE 7.0.5730.13, Server 2003 Standard SP2 English
				// IE 7.0.5730.13, XP Professional SP2 English
				// rely on the user agent matching above to determine the OS,
				// but we know it's SP2 either way
				minor = "SP2";
				break;
		}

		/* Identifying the major version of Microsoft Internet Explorer. */
		if(!version){
			if(document.documentElement && typeof document.documentElement.style.maxHeight!="undefined") {
				version = "7.0";
			} else if (document.compatMode) { 
				version = "6.0";
			} else if (window.createPopup) {
				version = "5.5";
			} else if (window.attachEvent) {
				version = "5.0";
			} else {
				version = "4.0";
			}

			/* Identifying the minor version of Microsoft Internet Explorer. */
			switch(navigator.appMinorVersion){
				case ";SP2;":
					version += ";SP2";
					break;
			}
		}
	}

	/* Identifying the architecture plataform (IA-32/PPC). */
	platform = navigator.platform;
	if(("Win32" == platform) || (platform.match(/i.86/))) {
	    arch = "IA-32";
	} else if (-1 != platform.indexOf('PPC'))  {
		arch = "PPC";
	}

	return { major:major, minor:minor, arch:arch, name:name, version:version };
}