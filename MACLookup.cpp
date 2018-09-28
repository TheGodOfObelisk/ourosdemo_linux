#include "MACLookup.h"
#include "base.h"
#include "scanops.h"
#include "errorhandle.h"
#include "charpool.h"
#include <map>
#include <assert.h>

extern ScanOps o;

std::map<int, char *> MacTable;

static inline int MacCharPrefix2Key(const u8 *prefix) {
  return (prefix[0] << 16) + (prefix[1] << 8) + prefix[2];
}

static void mac_prefix_init() {
  static int initialized = 0;
  if (initialized) return;
  initialized = 1;
  char filename[256];
  FILE *fp;
  char line[128];
  int pfx;
  char *endptr, *vendor;
  int lineno = 0;

  /* Now it is time to read in all of the entries ... */
  if (nmap_fetchfile(filename, sizeof(filename), "nmap-mac-prefixes") != 1){
    error("Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed");
    return;
  }

  fp = fopen(filename, "r");
  if (!fp) {
    error("Unable to open %s.  Ethernet vendor correlation will not be performed ", filename);
    return;
  }
  /* Record where this data file was found. */
  o.loaded_data_files["nmap-mac-prefixes"] = filename;

  while(fgets(line, sizeof(line), fp)) {
    lineno++;
    if (*line == '#') continue;
    if (!isxdigit((int) (unsigned char) *line)) {
      error("Parse error on line #%d of %s. Giving up parsing.", lineno, filename);
      break;
    }
    /* First grab the prefix */
    pfx = strtol(line, &endptr, 16);
    if (!endptr || !isspace((int) (unsigned char) *endptr)) {
      error("Parse error on line #%d of %s. Giving up parsing.", lineno, filename);
      break;
    }
    /* Now grab the vendor */
    while(*endptr && isspace((int) (unsigned char) *endptr)) endptr++;
    assert(*endptr);
    vendor = endptr;
    while(*endptr && *endptr != '\n' && *endptr != '\r') endptr++;
    *endptr = '\0';

    if (MacTable.find(pfx) == MacTable.end()) {
      MacTable[pfx] = cp_strdup(vendor);
    } else {
      if (o.debugging > 1)
        error("MAC prefix %06X is duplicated in %s; ignoring duplicates.", pfx, filename);
    }

  }

  fclose(fp);
  return;
}

static const char *findMACEntry(int prefix) {
  std::map<int, char *>::iterator i;

  i = MacTable.find(prefix);
  if (i == MacTable.end())
    return NULL;

  return i->second;
}


/* Takes a three byte MAC address prefix (passing the whole MAC is OK
   too) and returns the company which has registered the prefix.
   NULL is returned if no vendor is found for the given prefix or if there
   is some other error. */
const char *MACPrefix2Corp(const u8 *prefix) {
  if (!prefix) fatal("%s called with a NULL prefix", __func__);
  mac_prefix_init();

  return findMACEntry(MacCharPrefix2Key(prefix));
}

/* Takes a string and looks through the table for a vendor name which
   contains that string.  Sets the first three bytes in mac_data and
   returns true for the first matching entry found.  If no entries
   match, leaves mac_data untouched and returns false.  Note that this
   is not particularly efficient and so should be rewritten if it is
   called often */
bool MACCorp2Prefix(const char *vendorstr, u8 *mac_data) {
  std::map<int, char *>::iterator i;

  if (!vendorstr) fatal("%s: vendorstr is NULL", __func__);
  if (!mac_data) fatal("%s: mac_data is NULL", __func__);
  mac_prefix_init();

  for (i = MacTable.begin(); i != MacTable.end(); i++) {
    if (strcasestr(i->second, vendorstr)) {
      mac_data[0] = i->first >> 16;
      mac_data[1] = (i->first >> 8) & 0xFF;
      mac_data[2] = i->first & 0xFF;
      return true;
    }
  }
  return false;
}
