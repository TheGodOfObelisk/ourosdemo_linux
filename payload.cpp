#include "payload.h"
#include "errorhandle.h"
#include "scanops.h"
#include "util.h"

#include <stdio.h>
#include <errno.h>

#include <map>

extern ScanOps o;

struct payload {
  std::string data;
  /* Extra data such as source port goes here. */
};

/* The key for the payload lookup map is a (proto, port) pair. */
struct proto_dport {
  u8 proto;
  u16 dport;

  proto_dport(u8 proto, u16 dport) {
    this->proto = proto;
    this->dport = dport;
  }

  bool operator<(const proto_dport& other) const {
    if (proto == other.proto)
      return dport < other.dport;
    else
      return proto < other.proto;
  }
};

static std::map<struct proto_dport, struct payload> payloads;

/* Newlines are significant because keyword directives (like "source") that
   follow the payload string are significant to the end of the line. */
enum token_type {
  TOKEN_EOF = 0,
  TOKEN_NEWLINE,
  TOKEN_SYMBOL,
  TOKEN_STRING,
};

struct token {
  char text[1024];
  size_t len;
};

/* Returns a malloc-allocated list of the ports in portlist. portlist must
   contain one or more integers 0 <= p < 65536, separated by commas. */
static unsigned short *parse_portlist(const char *portlist, unsigned int *count) {
  uint32_t bitmap[65536 / 32];
  unsigned short *result;
  unsigned short i;
  unsigned int p;

  memset(bitmap, 0, sizeof(bitmap));
  *count = 0;
  for (;;) {
    long l;
    char *tail;

    errno = 0;
    l = strtol(portlist, &tail, 10);
    if (portlist == tail || errno != 0 || l < 0 || l > 65535)
      return NULL;
    if (!(bitmap[l / 32] & (1 << (l % 32)))) {
      bitmap[l / 32] |= (1 << (l % 32));
      (*count)++;
    }
    if (*tail == '\0')
      break;
    else if (*tail == ',')
      portlist = tail + 1;
    else
      return NULL;
  }

  result = (unsigned short *) malloc(sizeof(*result) * *count);
  if (result == NULL)
    return NULL;
  i = 0;
  for (p = 0; p < 65536 && i < *count; p++) {
    if (bitmap[p / 32] & (1 << (p % 32)))
      result[i++] = p;
  }

  return result;
}


static unsigned long line_no;

/* Get the next token from fp. The return value is the token type, or -1 on
   error. The token type is also stored in token->type. For TOKEN_SYMBOL and
   TOKEN_STRING, the text is stored in token->text and token->len. The text is
   null terminated. */
static int next_token(FILE *fp, struct token *token) {
  unsigned int i, tmplen;
  int c;

  token->len = 0;

  /* Skip whitespace and comments. */
  while (isspace(c = fgetc(fp)) && c != '\n')
    ;

  if (c == EOF) {
    return TOKEN_EOF;
  } else if (c == '\n') {
    line_no++;
    return TOKEN_NEWLINE;
  } else if (c == '#') {
    while ((c = fgetc(fp)) != EOF && c != '\n')
      ;
    if (c == EOF) {
      return TOKEN_EOF;
    } else {
      line_no++;
      return TOKEN_NEWLINE;
    }
  } else if (c == '"') {
    i = 0;
    while ((c = fgetc(fp)) != EOF && c != '\n' && c != '"') {
      if (i + 1 >= sizeof(token->text))
        return -1;
      if (c == '\\') {
        token->text[i++] = '\\';
        if (i + 1 >= sizeof(token->text))
          return -1;
        c = fgetc(fp);
        if (c == EOF)
          return -1;
      }
      token->text[i++] = c;
    }
    if (c != '"')
      return -1;
    token->text[i] = '\0';
    if (cstring_unescape(token->text, &tmplen) == NULL)
      return -1;
    token->len = tmplen;
    return TOKEN_STRING;
  } else {
    i = 0;
    if (i + 1 >= sizeof(token->text))
      return -1;
    token->text[i++] = c;
    while ((c = fgetc(fp)) != EOF && (isalnum(c) || c == ',')) {
      if (i + 1 >= sizeof(token->text))
        return -1;
      token->text[i++] = c;
    }
    ungetc(c, fp);
    token->text[i] = '\0';
    token->len = i;
    return TOKEN_SYMBOL;
  }

  return -1;
}

/* Loop over fp, reading tokens and adding payloads to the global payloads map
   as they are completed. Returns -1 on error. */
static int load_payloads_from_file(FILE *fp) {
  struct token token;
  int type;

  line_no = 1;
  type = next_token(fp, &token);
  for (;;) {
    unsigned short *ports;
    unsigned int count, p;
    std::string payload_data;

    while (type == TOKEN_NEWLINE)
      type = next_token(fp, &token);
    if (type == TOKEN_EOF)
      break;
    if (type != TOKEN_SYMBOL || strcmp(token.text, "udp") != 0) {
      fprintf(stderr, "Expected \"udp\" at line %lu of %s.\n", line_no, PAYLOAD_FILENAME);
      return -1;
    }

    type = next_token(fp, &token);
    if (type != TOKEN_SYMBOL) {
      fprintf(stderr, "Expected a port list at line %lu of %s.\n", line_no, PAYLOAD_FILENAME);
      return -1;
    }
    ports = parse_portlist(token.text, &count);
    if (ports == NULL) {
      fprintf(stderr, "Can't parse port list \"%s\" at line %lu of %s.\n", token.text, line_no, PAYLOAD_FILENAME);
      return -1;
    }

    payload_data.clear();
    for (;;) {
      type = next_token(fp, &token);
      if (type == TOKEN_STRING)
        payload_data.append(token.text, token.len);
      else if (type == TOKEN_NEWLINE)
        ; /* Nothing. */
      else
        break;
    }

    /* Ignore keywords like "source" to the end of the line. */
    if (type == TOKEN_SYMBOL && strcmp(token.text, "udp") != 0) {
      while (type != -1 && type != TOKEN_EOF && type != TOKEN_NEWLINE)
        type = next_token(fp, &token);
    }

    for (p = 0; p < count; p++) {
      struct proto_dport key(IPPROTO_UDP, ports[p]);
      struct payload payload;

      payload.data = payload_data;
      payloads[key] = payload;
    }

    free(ports);
  }

  return 0;
}

/* Ensure that the payloads map is initialized from the nmap-payloads file. This
   function keeps track of whether it has been called and does nothing after it
   is called the first time. */
int init_payloads(void) {
  static bool payloads_loaded = false;
  char filename[256];
  FILE *fp;
  int ret;

  if (payloads_loaded)
    return 0;

  payloads_loaded = true;

  if (nmap_fetchfile(filename, sizeof(filename), PAYLOAD_FILENAME) != 1) {
    error("Cannot find %s. UDP payloads are disabled.", PAYLOAD_FILENAME);
    return 0;
  }

  fp = fopen(filename, "r");
  if (fp == NULL) {
    fprintf(stderr, "Can't open %s for reading.\n", filename);
    return -1;
  }
  /* Record where this data file was found. */
  o.loaded_data_files[PAYLOAD_FILENAME] = filename;

  ret = load_payloads_from_file(fp);
  fclose(fp);

  return ret;
}

/* Get a payload appropriate for the given UDP port. If --data-length was used,
   returns the global random payload. Otherwise, for certain selected ports a
   payload is returned, and for others a zero-length payload is returned. The
   length is returned through the length pointer. */
const char *get_udp_payload(u16 dport, size_t *length) {
  if (o.extra_payload != NULL) {
    *length = o.extra_payload_length;
    return o.extra_payload;
  } else {
    return udp_port2payload(dport, length);
  }
}

/* Get a payload appropriate for the given UDP port. For certain selected ports
   a payload is returned, and for others a zero-length payload is returned. The
   length is returned through the length pointer. */
const char *udp_port2payload(u16 dport, size_t *length) {
  static const char *payload_null = "";
  std::map<struct proto_dport, struct payload>::iterator it;
  proto_dport pp(IPPROTO_UDP, dport);

  it = payloads.find(pp);
  if (it != payloads.end()) {
    *length = it->second.data.size();
    return it->second.data.data();
  } else {
    *length = 0;
    return payload_null;
  }
}