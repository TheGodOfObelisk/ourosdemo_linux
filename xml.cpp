#include "output.h"
#include "xml.h"
#include "base.h"
#include <string.h>
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <list>


struct xml_writer {
  /* Sanity checking: Don't open a new tag while still defining
     attributes for another, like "<elem1<elem2". */
  bool tag_open;
  /* Has the root element been started yet? If so, and if
     element_stack.size() == 0, then the document is finished. */
  bool root_written;
  std::list<const char *> element_stack;
};

static struct xml_writer xml;

char *xml_unescape(const char *str) {
  char *result = NULL;
  size_t n = 0, len;
  const char *p;
  int i;

  i = 0;
  for (p = str; *p != '\0'; p++) {
    const char *repl;
    char buf[32];

    if (*p != '&') {
      /* Based on the asumption that ampersand is only used for escaping. */
      buf[0] = *p;
      buf[1] = '\0';
      repl = buf;
    } else if (strncmp(p, "&lt;", 4) == 0) {
      repl = "<";
      p += 3;
    } else if (strncmp(p, "&gt;", 4) == 0) {
      repl = ">";
      p += 3;
    } else if (strncmp(p, "&amp;", 5) == 0) {
      repl = "&";
      p += 4;
    } else if (strncmp(p, "&quot;", 6) == 0) {
      repl = "\"";
      p += 5;
    } else if (strncmp(p, "&apos;", 6) == 0) {
      repl = "\'";
      p += 5;
    } else if (strncmp(p, "&#45;", 5) == 0) {
      repl = "-";
      p += 4;
    } else {
      /* Escaped control characters and anything outside of ASCII. */
      Strncpy(buf, p + 3, sizeof(buf));
      char *q;
      q = strchr(buf, ';');
      if(!q)
        buf[0] = '\0';
      else
        *q = '\0';
      repl = buf;
    }

    len = strlen(repl);
    /* Double the size of the result buffer if necessary. */
    if (i == 0 || i + len > n) {
      n = (i + len) * 2;
      result = (char *) safe_realloc(result, n + 1);
    }
    memcpy(result + i, repl, len);
    i += len;
  }
  /* Trim to length. (Also does initial allocation when str is empty.) */
  result = (char *) safe_realloc(result, i + 1);
  result[i] = '\0';

  return result;
}

/* Escape a string for inclusion in XML. This gets <>&, "' for attribute
   values, -- for inside comments, and characters with value > 0x7F. It
   also gets control characters with value < 0x20 to avoid parser
   normalization of \r\n\t in attribute values. If this is not desired
   in some cases, we'll have to add a parameter to control this. */
static char *escape(const char *str) {
  /* result is the result buffer; n + 1 is the allocated size. Double the
     allocation when space runs out. */
  char *result = NULL;
  size_t n = 0, len;
  const char *p;
  int i;

  i = 0;
  for (p = str; *p != '\0'; p++) {
    const char *repl;
    char buf[32];

    if (*p == '<')
      repl = "&lt;";
    else if (*p == '>')
      repl = "&gt;";
    else if (*p == '&')
      repl = "&amp;";
    else if (*p == '"')
      repl = "&quot;";
    else if (*p == '\'')
      repl = "&apos;";
    else if (*p == '-' && p > str && *(p - 1) == '-') {
      /* Escape -- for comments. */
      repl = "&#45;";
    } else if (*p < 0x20 || (unsigned char) *p > 0x7F) {
      /* Escape control characters and anything outside of ASCII. We have to
         emit UTF-8 and an easy way to do that is to emit ASCII. */
      Snprintf(buf, sizeof(buf), "&#x%x;", (unsigned char) *p);
      repl = buf;
    } else {
      /* Unescaped character. */
      buf[0] = *p;
      buf[1] = '\0';
      repl = buf;
    }

    len = strlen(repl);
    /* Double the size of the result buffer if necessary. */
    if (i == 0 || i + len > n) {
      n = (i + len) * 2;
      result = (char *) safe_realloc(result, n + 1);
    }
    memcpy(result + i, repl, len);
    i += len;
  }
  /* Trim to length. (Also does initial allocation when str is empty.) */
  result = (char *) safe_realloc(result, i + 1);
  result[i] = '\0';

  return result;
}

/* Write data directly to the XML file with no escaping. Make sure you
   know what you're doing. */
int xml_write_raw(const char *fmt, ...) {
  va_list va;
  char *s;

  va_start(va, fmt);
  alloc_vsprintf(&s, fmt, va);
  va_end(va);
  if (s == NULL)
    return -1;

  printf("%s", s);
  free(s);

  return 0;
}

/* Write data directly to the XML file after escaping it. */
int xml_write_escaped(const char *fmt, ...) {
  va_list va;
  int n;

  va_start(va, fmt);
  n = xml_write_escaped_v(fmt, va);
  va_end(va);

  return n;
}

/* Write data directly to the XML file after escaping it. This version takes a
   va_list like vprintf. */
int xml_write_escaped_v(const char *fmt, va_list va) {
  char *s, *esc_s;

  alloc_vsprintf(&s, fmt, va);
  if (s == NULL)
    return -1;
  esc_s = escape(s);
  free(s);
  if (esc_s == NULL)
    return -1;

  printf("%s", esc_s);
  free(esc_s);

  return 0;
}

/* Write the XML declaration: <?xml version="1.0" encoding="UTF-8"?>
 * and the DOCTYPE declaration: <!DOCTYPE rootnode>
 */
int xml_start_document(const char *rootnode) {
  if (xml_open_pi("xml") < 0)
    return -1;
  if (xml_attribute("version", "1.0") < 0)
    return -1;
  /* Practically, Nmap only uses ASCII, but UTF-8 encompasses ASCII and allows
   * for future expansion */
  if (xml_attribute("encoding", "UTF-8") < 0)
    return -1;
  if (xml_close_pi() < 0)
    return -1;
  if (xml_newline() < 0)
    return -1;

  printf("<!DOCTYPE %s>\n", rootnode);

  return 0;
}

int xml_start_comment() {
  printf("<!--");

  return 0;
}

int xml_end_comment() {
  printf("-->");

  return 0;
}

int xml_open_pi(const char *name) {
  assert(!xml.tag_open);
  printf("<?%s", name);
  xml.tag_open = true;

  return 0;
}

int xml_close_pi() {
  assert(xml.tag_open);
  printf("?>");
  xml.tag_open = false;

  return 0;
}

/* Open a start tag, like "<name". The tag must be later closed with
   xml_close_start_tag or xml_close_empty_tag. Usually the tag is closed
   after writing some attributes. */
int xml_open_start_tag(const char *name, const bool write) {
  assert(!xml.tag_open);
  if (write)
    printf("<%s", name);
  xml.element_stack.push_back(name);
  xml.tag_open = true;
  xml.root_written = true;

  return 0;
}

int xml_close_start_tag(const bool write) {
  assert(xml.tag_open);
  if(write)
    printf(">");
  xml.tag_open = false;

  return 0;
}

/* Close an empty-element tag. It should have been opened with
   xml_open_start_tag. */
int xml_close_empty_tag() {
  assert(xml.tag_open);
  assert(!xml.element_stack.empty());
  xml.element_stack.pop_back();
  printf("/>");
  xml.tag_open = false;

  return 0;
}

int xml_start_tag(const char *name, const bool write) {
  if (xml_open_start_tag(name, write) < 0)
    return -1;
  if (xml_close_start_tag(write) < 0)
    return -1;

  return 0;
}

/* Write an end tag for the element at the top of the element stack. */
int xml_end_tag() {
  const char *name;

  assert(!xml.tag_open);
  assert(!xml.element_stack.empty());
  name = xml.element_stack.back();
  xml.element_stack.pop_back();

  printf("</%s>", name);

  return 0;
}

/* Write an attribute. The only place this makes sense is between
   xml_open_start_tag and either xml_close_start_tag or
   xml_close_empty_tag. */
int xml_attribute(const char *name, const char *fmt, ...) {
  va_list va;
  char *val, *esc_val;

  assert(xml.tag_open);

  va_start(va, fmt);
  alloc_vsprintf(&val, fmt, va);
  va_end(va);
  if (val == NULL)
    return -1;
  esc_val = escape(val);
  free(val);
  if (esc_val == NULL)
    return -1;

  printf(" %s=\"%s\"", name, esc_val);
  free(esc_val);

  return 0;
}

int xml_newline() {
  printf("\n");

  return 0;
}

/* Return the size of the element stack. */
int xml_depth() {
  return xml.element_stack.size();
}

/* Return true iff a root element has been started. */
bool xml_tag_open() {
  return xml.tag_open;
}

/* Return true iff a root element has been started. */
bool xml_root_written() {
  return xml.root_written;
}
