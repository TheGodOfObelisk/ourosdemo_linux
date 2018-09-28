#include "util.h"
#include "base.h"
#include "errorhandle.h"
#include <stdlib.h>
#include <memory.h>
#include <ctype.h>

void shortfry(unsigned short *arr, int num_elem) {
  int num;
  unsigned short tmp;
  int i;

  if (num_elem < 2)
    return;

  for (i = num_elem - 1; i > 0 ; i--) {
    num = get_random_ushort() % (i + 1);
    if (i == num)
      continue;
    tmp = arr[i];
    arr[i] = arr[num];
    arr[num] = tmp;
  }

  return;
}

/* Scramble the contents of an array. */
void genfry(unsigned char *arr, int elem_sz, int num_elem) {
  int i;
  unsigned int pos;
  unsigned char *bytes;
  unsigned char *cptr;
  unsigned short *sptr;
  unsigned int *iptr;
  unsigned char *tmp;
  int bpe;

  if (sizeof(unsigned char) != 1)
    fatal("%s() requires 1 byte chars", __func__);

  if (num_elem < 2)
    return;

  if (elem_sz == sizeof(unsigned short)) {
    shortfry((unsigned short *)arr, num_elem);
    return;
  }

  /* OK, so I am stingy with the random bytes! */
  if (num_elem < 256)
    bpe = sizeof(unsigned char);
  else if (num_elem < 65536)
    bpe = sizeof(unsigned short);
  else
    bpe = sizeof(unsigned int);

  bytes = (unsigned char *) safe_malloc(bpe * num_elem);
  tmp = (unsigned char *) safe_malloc(elem_sz);

  get_random_bytes(bytes, bpe * num_elem);
  cptr = bytes;
  sptr = (unsigned short *)bytes;
  iptr = (unsigned int *) bytes;

  for (i = num_elem - 1; i > 0; i--) {
    if (num_elem < 256) {
      pos = *cptr;
      cptr++;
    } else if (num_elem < 65536) {
      pos = *sptr;
      sptr++;
    } else {
      pos = *iptr;
      iptr++;
    }
    pos %= i + 1;
    if ((unsigned) i != pos) { /* memcpy is undefined when source and dest overlap. */
      memcpy(tmp, arr + elem_sz * i, elem_sz);
      memcpy(arr + elem_sz * i, arr + elem_sz * pos, elem_sz);
      memcpy(arr + elem_sz * pos, tmp, elem_sz);
    }
  }
  free(bytes);
  free(tmp);
}

/* A simple function to form a character from 2 hex digits in ASCII form. */
static unsigned char hex2char(unsigned char a, unsigned char b) {
  int val;

  if (!isxdigit((int) a) || !isxdigit((int) b))
    return 0;
  a = tolower((int) a);
  b = tolower((int) b);
  if (isdigit((int) a))
    val = (a - '0') << 4;
  else
    val = (10 + (a - 'a')) << 4;

  if (isdigit((int) b))
    val += (b - '0');
  else
    val += 10 + (b - 'a');

  return (unsigned char) val;
}

/* Convert a string in the format of a roughly C-style string literal
   (e.g. can have \r, \n, \xHH escapes, etc.) into a binary string.
   This is done in-place, and the new (shorter or the same) length is
   stored in newlen.  If parsing fails, NULL is returned, otherwise
   str is returned. */
char *cstring_unescape(char *str, unsigned int *newlen) {
  char *dst = str, *src = str;
  char newchar;

  while (*src) {
    if (*src == '\\' ) {
      src++;
      switch (*src) {
      case '0':
        newchar = '\0';
        src++;
        break;
      case 'a': // Bell (BEL)
        newchar = '\a';
        src++;
        break;
      case 'b': // Backspace (BS)
        newchar = '\b';
        src++;
        break;
      case 'f': // Formfeed (FF)
        newchar = '\f';
        src++;
        break;
      case 'n': // Linefeed/Newline (LF)
        newchar = '\n';
        src++;
        break;
      case 'r': // Carriage Return (CR)
        newchar = '\r';
        src++;
        break;
      case 't': // Horizontal Tab (TAB)
        newchar = '\t';
        src++;
        break;
      case 'v': // Vertical Tab (VT)
        newchar = '\v';
        src++;
        break;
      case 'x':
        src++;
        if (!*src || !*(src + 1)) return NULL;
        if (!isxdigit((int) (unsigned char) *src) || !isxdigit((int) (unsigned char) * (src + 1))) return NULL;
        newchar = hex2char(*src, *(src + 1));
        src += 2;
        break;
      default:
        if (isalnum((int) (unsigned char) *src))
          return NULL; // I don't really feel like supporting octals such as \015
        // Other characters I'll just copy as is
        newchar = *src;
        src++;
        break;
      }
      *dst = newchar;
      dst++;
    } else {
      if (dst != src)
        *dst = *src;
      dst++;
      src++;
    }
  }
  *dst = '\0'; // terminated, but this string can include other \0, so use newlen
  if (newlen)
    *newlen = dst - str;

  return str;
}

/* Like the perl equivalent, removes the terminating newline from string IF one
   exists. It then returns the POSSIBLY MODIFIED string. */
char *chomp(char *string) {
  int len = strlen(string);
  if (len && string[len - 1] == '\n') {
    if (len > 1 && string[len - 2] == '\r')
      string[len - 2] = '\0';
    else
      string[len - 1] = '\0';
  }
  return string;
}

/* Wrapper for nbase function hexdump. */
void nmap_hexdump(unsigned char *cp, unsigned int length) {
  char *string = NULL;

  string = hexdump((u8*) cp, length);
  if (string) {
    // log_write(LOG_PLAIN, "%s", string);
    printf("%s", string);
    free(string);
  }

  return;
}

void bintohexstr(char *buf, int buflen, char *src, int srclen) {
  int bp = 0;
  int i;

  for (i = 0; i < srclen; i++) {
    bp += Snprintf(buf + bp, buflen - bp, "\\x%02hhx", src[i]);
    if (bp >= buflen)
      break;
    if (i % 16 == 7) {
      bp += Snprintf(buf + bp, buflen - bp, " ");
      if (bp >= buflen)
        break;
    }
    if (i % 16 == 15) {
      bp += Snprintf(buf + bp, buflen - bp, "\n");
      if (bp >= buflen)
        break;
    }
  }
  if (i % 16 != 0 && bp < buflen)
    bp += Snprintf(buf + bp, buflen - bp, "\n");
}

/* Test a wildcard mask against a test string. Wildcard mask can include '*' and
   '?' which work the same as they do in /bin/sh (except it's case insensitive).
   Return val of 1 means it DID match. 0 means it DIDN'T. - Doug Hoyte, 2005 */
int wildtest(char *wild, char *test) {
  int i;

  while (*wild != '\0'  ||  *test != '\0') {
    if (*wild == '*') {
      /* --- Deal with multiple asterisks. --- */
      while (wild[1] == '*')
        wild++;

      /* --- Deal with terminating asterisks. --- */
      if (wild[1] == '\0')
        return 1;

      for (i = 0; test[i] != '\0'; i++) {
        if ((tolower((int) (unsigned char) wild[1]) == tolower((int) (unsigned char) test[i]) || wild[1] == '?')
            && wildtest(wild + 1, test + i) == 1) {
          return 1;
        }
      }

      return 0;
    }

    /* --- '?' can't match '\0'. --- */
    if (*wild == '?' && *test == '\0')
      return 0;

    if (*wild != '?' && tolower((int) (unsigned char) *wild) != tolower((int) (unsigned char) *test))
      return 0;
    wild++;
    test++;
  }

  return tolower((int) (unsigned char) *wild) == tolower((int) (unsigned char) *test);
}
