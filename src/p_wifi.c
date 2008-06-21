/*
 * This file is part of Firestorm NIDS
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * This program is released under the terms of the GNU GPL version 3
*/

#include <firestorm.h>
#include <f_packet.h>
#include <f_decode.h>

#define DLT_IEEE802_11_RADIO 0x7f
#define DLT_IEEE802_11 0x69

#if 0
#define dmesg mesg
#else
#define dmesg(x...) do{}while(0);
#endif

static void radio_decode(struct _pkt *p)
{
}

static struct _decoder radio_decoder = {
	.d_label = "802.11-radio",
	.d_decode = radio_decode,
};

static struct _decoder wifi_decoder = {
	.d_label = "802.11",
	.d_decode = radio_decode,
};

static struct _proto p_radio = {
	.p_label = "radio",
};

static struct _proto p_wifi = {
	.p_label = "wifi",
};

__attribute__((constructor)) static void _ctor(void)
{
	decoder_add(&radio_decoder);
	decoder_register(&radio_decoder, NS_DLT, DLT_IEEE802_11_RADIO);
	decoder_register(&wifi_decoder, NS_DLT, DLT_IEEE802_11);
	proto_add(&radio_decoder, &p_radio);
	proto_add(&wifi_decoder, &p_wifi);
}
