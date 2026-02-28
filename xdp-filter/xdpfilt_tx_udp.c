/* SPDX-License-Identifier: GPL-2.0 */

#define FILT_MODE_TX
#undef FILT_MODE_ETHERNET
#undef FILT_MODE_IPV4
#undef FILT_MODE_IPV6
#define FILT_MODE_UDP
#undef FILT_MODE_TCP
#define FUNCNAME xdpfilt_tx_udp
#include "xdpfilt_prog.h"
