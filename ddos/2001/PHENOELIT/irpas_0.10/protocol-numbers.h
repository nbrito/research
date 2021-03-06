/* $Id: protocol-numbers.h,v 1.7 2001/04/20 16:24:17 fx Exp $ 
 *
 * file part of protos.c 
 *
 * generated from
 * ftp://ftp.isi.edu/in-notes/iana/assignments/protocol-numbers
 * becuse IANA thinks it's fun to add proto numbers all nose long
 */
#ifndef _PROTOCOL_NUMBERS_H_
#define _PROTOCOL_NUMBERS_H_

typedef struct proto_t {
        int         number;
	char        *keyword;
	char        *name;
} Protocols;

#define PROTOCOLS 255
static Protocols prts[] = {
{0,"HOPOPT","IPv6 Hop-by-Hop Option [RFC1883]"},
{1,"ICMP","Internet Control Message [RFC792]"},
{2,"IGMP","Internet Group Management [RFC1112]"},
{3,"GGP","Gateway-to-Gateway [RFC823]"},
{4,"IPenc","IP in IP (encapsulation) [RFC2003]"},
{5,"ST","Stream [RFC1190,IEN119]"},
{6,"TCP","Transmission Control [RFC793]"},
{7,"CBT","CBT [Ballardie]"},
{8,"EGP","Exterior Gateway Protocol [RFC888,DLM1]"},
{9,"IGP","any private interior gateway [IANA]"},
{10,"BBN-RCC-MON","BBN RCC Monitoring [SGC]"},
{11,"NVP-II","Network Voice Protocol [RFC741,SC3]"},
{12,"PUP","PUP [PUP,XEROX]"},
{13,"ARGUS","ARGUS [RWS4]"},
{14,"EMCON","EMCON [BN7]"},
{15,"XNET","Cross Net Debugger [IEN158,JFH2]"},
{16,"CHAOS","Chaos [NC3]"},
{17,"UDP","User Datagram [RFC768,JBP]"},
{18,"MUX","Multiplexing [IEN90,JBP]"},
{19,"DCN-MEAS","DCN Measurement Subsystems [DLM1]"},
{20,"HMP","Host Monitoring [RFC869,RH6]"},
{21,"PRM","Packet Radio Measurement [ZSU]"},
{22,"XNS-IDP","XEROX NS IDP [ETHERNET,XEROX]"},
{23,"TRUNK-1","Trunk-1 [BWB6]"},
{24,"TRUNK-2","Trunk-2 [BWB6]"},
{25,"LEAF-1","Leaf-1 [BWB6]"},
{26,"LEAF-2","Leaf-2 [BWB6]"},
{27,"RDP","Reliable Data Protocol [RFC908,RH6]"},
{28,"IRTP","Internet Reliable Transaction [RFC938,TXM]"},
{29,"ISO-TP4","ISO Transport Protocol Class 4 [RFC905,RC77]"},
{30,"NETBLT","Bulk Data Transfer Protocol [RFC969,DDC1]"},
{31,"MFE-NSP","MFE Network Services Protocol [MFENET,BCH2]"},
{32,"MERIT-INP","MERIT Internodal Protocol [HWB]"},
{33,"SEP","Sequential Exchange Protocol [JC120]"},
{34,"3PC","Third Party Connect Protocol [SAF3]"},
{35,"IDPR","Inter-Domain Policy Routing Protocol [MXS1]"},
{36,"XTP","XTP [GXC]"},
{37,"DDP","Datagram Delivery Protocol [WXC]"},
{38,"IDPR-CMTP","IDPR Control Message Transport Proto [MXS1]"},
{39,"TP++","TP++ Transport Protocol [DXF]"},
{40,"IL","IL Transport Protocol [Presotto]"},
{41,"IPv6","Ipv6 [Deering]"},
{42,"SDRP","Source Demand Routing Protocol [DXE1]"},
{43,"IPv6-Route","Routing Header for IPv6 [Deering]"},
{44,"IPv6-Frag","Fragment Header for IPv6 [Deering]"},
{45,"IDRP","Inter-Domain Routing Protocol [Sue Hares]"},
{46,"RSVP","Reservation Protocol [Bob Braden]"},
{47,"GRE","General Routing Encapsulation [Tony Li]"},
{48,"MHRP","Mobile Host Routing Protocol[David Johnson]"},
{49,"BNA","BNA [Gary Salamon]"},
{50,"ESP","Encap Security Payload for IPv6 [RFC1827]"},
{51,"AH","Authentication Header for IPv6 [RFC1826]"},
{52,"I-NLSP","Integrated Net Layer Security TUBA [GLENN]"},
{53,"SWIPE","IP with Encryption [JI6]"},
{54,"NARP","NBMA Address Resolution Protocol [RFC1735]"},
{55,"MOBILE","IP Mobility [Perkins]"},
{56,"TLSP","Transport Layer Security Protocol [Oberg]"},
{57,"SKIP","SKIP [Markson]"},
{58,"IPv6-ICMP","ICMP for IPv6 [RFC1883]"},
{59,"IPv6-NoNxt","No Next Header for IPv6 [RFC1883]"},
{60,"IPv6-Opts","Destination Options for IPv6 [RFC1883]"},
{61,"61","any host internal protocol [IANA]"},
{62,"CFTP","CFTP [CFTP,HCF2]"},
{63,"63","any local network [IANA]"},
{64,"SAT-EXPAK","SATNET and Backroom EXPAK [SHB]"},
{65,"KRYPTOLAN","Kryptolan [PXL1]"},
{66,"RVD","MIT Remote Virtual Disk Protocol [MBG]"},
{67,"IPPC","Internet Pluribus Packet Core [SHB]"},
{68,"68","any distributed file system [IANA]"},
{69,"SAT-MON","SATNET Monitoring [SHB]"},
{70,"VISA","VISA Protocol [GXT1]"},
{71,"IPCV","Internet Packet Core Utility [SHB]"},
{72,"CPNX","Computer Protocol Network Executive [DXM2]"},
{73,"CPHB","Computer Protocol Heart Beat [DXM2]"},
{74,"WSN","Wang Span Network [VXD]"},
{75,"PVP","Packet Video Protocol [SC3]"},
{76,"BR-SAT-MON","Backroom SATNET Monitoring [SHB]"},
{77,"SUN-ND","SUN ND PROTOCOL-Temporary [WM3]"},
{78,"WB-MON","WIDEBAND Monitoring [SHB]"},
{79,"WB-EXPAK","WIDEBAND EXPAK [SHB]"},
{80,"ISO-IP","ISO Internet Protocol [MTR]"},
{81,"VMTP","VMTP [DRC3]"},
{82,"SECURE-VMTP","SECURE-VMTP [DRC3]"},
{83,"VINES","VINES [BXH]"},
{84,"TTP","TTP [JXS]"},
{85,"NSFNET-IGP","NSFNET-IGP [HWB]"},
{86,"DGP","Dissimilar Gateway Protocol [DGP,ML109]"},
{87,"TCF","TCF [GAL5]"},
{88,"EIGRP","EIGRP [CISCO,GXS]"},
{89,"OSPFIGP","OSPFIGP [RFC1583,JTM4]"},
{90,"Sprite-RPC","Sprite RPC Protocol [SPRITE,BXW]"},
{91,"LARP","Locus Address Resolution Protocol [BXH]"},
{92,"MTP","Multicast Transport Protocol [SXA]"},
{93,"AX.25","AX.25 Frames [BK29]"},
{94,"IPIP","IP-within-IP Encapsulation Protocol [JI6]"},
{95,"MICP","Mobile Internetworking Control Pro. [JI6]"},
{96,"SCC-SP","Semaphore Communications Sec. Pro. [HXH]"},
{97,"ETHERIP","Ethernet-within-IP Encapsulation [RDH1]"},
{98,"ENCAP","Encapsulation Header [RFC1241,RXB3]"},
{99,"99PrivEncr","any private encryption scheme [IANA]"},
{100,"GMTP","GMTP [RXB5]"},
{101,"IFMP","Ipsilon Flow Management Protocol [Hinden]"},
{102,"PNNI","PNNI over IP [Callon]"},
{103,"PIM","Protocol Independent Multicast [Farinacci]"},
{104,"ARIS","ARIS [Feldman]"},
{105,"SCPS","SCPS [Durst]"},
{106,"QNX","QNX [Hunter]"},
{107,"A/N","Active Networks [Braden]"},
{108,"IPComp","IP Payload Compression Protocol [RFC2393]"},
{109,"SNP","Sitara Networks Protocol [Sridhar]"},
{110,"Compaq-Peer","Compaq Peer Protocol [Volpe]"},
{111,"IPX-in-IP","IPX in IP [Lee]"},
{112,"VRRP","Virtual Router Redundancy Protocol [Hinden]"},
{115,"L2TP","Layer Two Tunneling Protocol [Aboba]"},
{116,"DDX","D-II Data Exchange (DDX) [Worley]"},
{117,"IATP","Interactive Agent Transfer Protocol [Murphy]"},
{118,"STP","Schedule Transfer Protocol [JMP]"},
{119,"SRP","SpectraLink Radio Protocol [Hamilton]"},
{120,"UTI","UTI [Lothberg]"},
{121,"SMP","Simple Message Protocol [Ekblad]"},
{122,"SM","SM [Crowcroft]"},
{123,"PTP","Performance Transparency Protocol [Welzl]"},
{124,"ISIS over IPv4","[Przygienda]"},
{125,"FIRE","[Partridge]"},
{126,"CRTP","Combat Radio Transport Protocol [Sautter]"},
{127,"CRUDP","Combat Radio User Datagram [Sautter]"},
{128,"SSCOPMCE","[Waber]"},
{129,"IPLT","[Hollbach]"},
{130,"SPS","Secure Packet Shield [McIntosh]"},
{131,"PIPE","Private IP Encapsulation within IP [Petri]"},
{132,"SCTP","Stream Control Transmission Protocol [Stewart]"},
{133,"FC","Fibre Channel [Rajagopal]"},
{134,"134","[IANA]"},
{135,"135","[IANA]"},
{136,"136","[IANA]"},
{137,"137","[IANA]"},
{138,"138","[IANA]"},
{139,"139","[IANA]"},
{140,"140","[IANA]"},
{141,"141","[IANA]"},
{142,"142","[IANA]"},
{143,"143","[IANA]"},
{144,"144","[IANA]"},
{145,"145","[IANA]"},
{146,"146","[IANA]"},
{147,"147","[IANA]"},
{148,"148","[IANA]"},
{149,"149","[IANA]"},
{150,"150","[IANA]"},
{151,"151","[IANA]"},
{152,"152","[IANA]"},
{153,"153","[IANA]"},
{154,"154","[IANA]"},
{155,"155","[IANA]"},
{156,"156","[IANA]"},
{157,"157","[IANA]"},
{158,"158","[IANA]"},
{159,"159","[IANA]"},
{160,"160","[IANA]"},
{161,"161","[IANA]"},
{162,"162","[IANA]"},
{163,"163","[IANA]"},
{164,"164","[IANA]"},
{165,"165","[IANA]"},
{166,"166","[IANA]"},
{167,"167","[IANA]"},
{168,"168","[IANA]"},
{169,"169","[IANA]"},
{170,"170","[IANA]"},
{171,"171","[IANA]"},
{172,"172","[IANA]"},
{173,"173","[IANA]"},
{174,"174","[IANA]"},
{175,"175","[IANA]"},
{176,"176","[IANA]"},
{177,"177","[IANA]"},
{178,"178","[IANA]"},
{179,"179","[IANA]"},
{180,"180","[IANA]"},
{181,"181","[IANA]"},
{182,"182","[IANA]"},
{183,"183","[IANA]"},
{184,"184","[IANA]"},
{185,"185","[IANA]"},
{186,"186","[IANA]"},
{187,"187","[IANA]"},
{188,"188","[IANA]"},
{189,"189","[IANA]"},
{190,"190","[IANA]"},
{191,"191","[IANA]"},
{192,"192","[IANA]"},
{193,"193","[IANA]"},
{194,"194","[IANA]"},
{195,"195","[IANA]"},
{196,"196","[IANA]"},
{197,"197","[IANA]"},
{198,"198","[IANA]"},
{199,"199","[IANA]"},
{200,"200","[IANA]"},
{201,"201","[IANA]"},
{202,"202","[IANA]"},
{203,"203","[IANA]"},
{204,"204","[IANA]"},
{205,"205","[IANA]"},
{206,"206","[IANA]"},
{207,"207","[IANA]"},
{208,"208","[IANA]"},
{209,"209","[IANA]"},
{210,"210","[IANA]"},
{211,"211","[IANA]"},
{212,"212","[IANA]"},
{213,"213","[IANA]"},
{214,"214","[IANA]"},
{215,"215","[IANA]"},
{216,"216","[IANA]"},
{217,"217","[IANA]"},
{218,"218","[IANA]"},
{219,"219","[IANA]"},
{220,"220","[IANA]"},
{221,"221","[IANA]"},
{222,"222","[IANA]"},
{223,"223","[IANA]"},
{224,"224","[IANA]"},
{225,"225","[IANA]"},
{226,"226","[IANA]"},
{227,"227","[IANA]"},
{228,"228","[IANA]"},
{229,"229","[IANA]"},
{230,"230","[IANA]"},
{231,"231","[IANA]"},
{232,"232","[IANA]"},
{233,"233","[IANA]"},
{234,"234","[IANA]"},
{235,"235","[IANA]"},
{236,"236","[IANA]"},
{237,"237","[IANA]"},
{238,"238","[IANA]"},
{239,"239","[IANA]"},
{240,"240","[IANA]"},
{241,"241","[IANA]"},
{242,"242","[IANA]"},
{243,"243","[IANA]"},
{244,"244","[IANA]"},
{245,"245","[IANA]"},
{246,"246","[IANA]"},
{247,"247","[IANA]"},
{248,"248","[IANA]"},
{249,"249","[IANA]"},
{250,"250","[IANA]"},
{251,"251","[IANA]"},
{252,"252","[IANA]"},
{253,"253","[IANA]"},
{254,"254","[IANA]"},
{255,"255","Reserved [IANA]"},
{0,NULL,NULL}
};

#endif _PROTOCOL_NUMBERS_H_

