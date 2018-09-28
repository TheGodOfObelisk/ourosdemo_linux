#include "protocols.h"
#include "errorhandle.h"
#include "util.h"
#include "scanops.h"
#include "charpool.h"
#include "services.h"

extern ScanOps o;

static int numipprots = 0;
static struct protocol_list *protocol_table[PROTOCOL_TABLE_SIZE];
static int protocols_initialized = 0;


static int nmap_protocols_init() {
  if (protocols_initialized) return 0;

  char filename[512];
  FILE *fp;
  char protocolname[128];
  unsigned short protno;
  char *p;
  char line[1024];
  int lineno = 0;
  struct protocol_list *current, *previous;
  int res;

  if (nmap_fetchfile(filename, sizeof(filename), "nmap-protocols") != 1) {
    error("Unable to find nmap-protocols!  Resorting to /etc/protocols");
    strcpy(filename, "/etc/protocols");
  }

  fp = fopen(filename, "r");
  if (!fp) {
    fatal("Unable to open %s for reading protocol information", filename);
  }
  /* Record where this data file was found. */
  o.loaded_data_files["nmap-protocols"] = filename;

  memset(protocol_table, 0, sizeof(protocol_table));

  while(fgets(line, sizeof(line), fp)) {
    lineno++;
    p = line;
    while(*p && isspace((int) (unsigned char) *p))
      p++;
    if (*p == '#')
      continue;
    res = sscanf(line, "%127s %hu", protocolname, &protno);
    if (res !=2)
      continue;

    /* Now we make sure our protocols don't have duplicates */
    for(current = protocol_table[protno % PROTOCOL_TABLE_SIZE], previous = NULL;
        current; current = current->next) {
      if (protno == current->protoent->p_proto) {
        if (o.debugging) {
          error("Protocol %d is duplicated in protocols file %s", ntohs(protno), filename);
        }
        break;
      }
      previous = current;
    }
    if (current)
      continue;

    numipprots++;

    current = (struct protocol_list *) cp_alloc(sizeof(struct protocol_list));
    current->protoent = (struct protoent *) cp_alloc(sizeof(struct protoent));
    current->next = NULL;
    if (previous == NULL) {
      protocol_table[protno % PROTOCOL_TABLE_SIZE] = current;
    } else {
      previous->next = current;
    }
    current->protoent->p_name = cp_strdup(protocolname);
    current->protoent->p_proto = protno;
    current->protoent->p_aliases = NULL;
  }
  fclose(fp);
  protocols_initialized = 1;
  return 0;
}


/* Adds protocols whose names match mask to porttbl.
 * Increases the prot_count in ports by the number of protocols added.
 * Returns the number of protocols added.
 */


int addprotocolsfromservmask(char *mask, u8 *porttbl) {
  struct protocol_list *current;
  int bucket, t=0;

  if (!protocols_initialized && nmap_protocols_init() == -1)
    fatal("%s: Couldn't get protocol numbers", __func__);

  for(bucket = 0; bucket < PROTOCOL_TABLE_SIZE; bucket++) {
    for(current = protocol_table[bucket % PROTOCOL_TABLE_SIZE]; current; current = current->next) {
      if (wildtest(mask, current->protoent->p_name)) {
        porttbl[ntohs(current->protoent->p_proto)] |= SCAN_PROTOCOLS;
        t++;
      }
    }
  }

  return t;

}

struct protoent *nmap_getprotbynum(int num) {
  struct protocol_list *current;

  if (nmap_protocols_init() == -1)
    return NULL;

  for(current = protocol_table[num % PROTOCOL_TABLE_SIZE];
      current; current = current->next) {
    if (num == current->protoent->p_proto)
      return current->protoent;
  }

  /* Couldn't find it ... oh well. */
  return NULL;
}