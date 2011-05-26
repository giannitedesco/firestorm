#ifndef _CSUM_H
#define _CSUM_H

#ifdef __x86_64__
#include <csum_x86_64.h>
#else
#include <csum_sw.h>
#endif

#endif /* _CSUM_H */
