/* SPDX-License-Identifier: GPL-2.0 */

#define FILT_MODE_DENY
#undef FILT_MODE_ETHERNET
#undef FILT_MODE_IPV4
#undef FILT_MODE_IPV6
#undef FILT_MODE_UDP
#undef FILT_MODE_TCP
#define FILT_MODE_ETHTYPE
#define FUNCNAME xdpfilt_dny_ethtyp
#include "xdpfilt_prog.h"
