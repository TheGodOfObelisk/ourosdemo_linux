#ifndef MY_MAC_LOOKUP_H
#define MY_MAC_LOOKUP_H

#include "base.h"

/* Takes a three byte MAC address prefix (passing the whole MAC is OK
   too) and returns the company which has registered the prefix.
   NULL is returned if no vendor is found for the given prefix or if there
   is some other error. */
const char *MACPrefix2Corp(const u8 *prefix);

/* Takes a string and looks through the table for a vendor name which
   contains that string.  Sets the first three bytes in mac_data and
   returns true for the first matching entry found.  If no entries
   match, leaves mac_data untouched and returns false.  Note that this
   is not particularly efficient and so should be rewritten if it is
   called often */
bool MACCorp2Prefix(const char *vendorstr, u8 *mac_data);

#endif