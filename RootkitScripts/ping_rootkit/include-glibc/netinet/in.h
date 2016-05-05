#ifndef	_NETINET_IN_H
#define	_NETINET_IN_H	1

#include "glibc-bugs.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/in.h>

#define SOL_IP	0

#include <stdint.h>

/* Functions to convert between host and network byte order.

   Please note that these functions normally take `unsigned long int' or
   `unsigned short int' values as arguments and also return them.  But
   this was a short-sighted decision since on different systems the types
   may have different representations but the values are always the same.  */

extern uint32_t ntohl (uint32_t __netlong) __THROW __attribute__ ((__const__));
extern uint16_t ntohs (uint16_t __netshort)
     __THROW __attribute__ ((__const__));
extern uint32_t htonl (uint32_t __hostlong)
     __THROW __attribute__ ((__const__));
extern uint16_t htons (uint16_t __hostshort)
     __THROW __attribute__ ((__const__));


#endif	/* netinet/in.h */
