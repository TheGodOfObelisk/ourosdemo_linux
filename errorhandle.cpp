#include "errorhandle.h"
#include "xml.h"
#include "base.h"
#include "output.h"
#include <errno.h>
#include <stdio.h>//cannot recognize exit(1)
#include <string.h>//strerror()
#include <time.h>//time()

void fatal(const char *fmt, ...){
   time_t timep;
  struct timeval tv;
  va_list  ap;

  gettimeofday(&tv, NULL);
  timep = time(NULL);

  va_start(ap, fmt);
  //log_vwrite(LOG_NORMAL|LOG_STDERR, fmt, ap);
  va_end(ap);
  //log_write(LOG_NORMAL|LOG_STDERR, "\nQUITTING!\n");
    printf("\nQUITTING!\n");
  if (xml_tag_open())
    xml_close_start_tag();
  if (!xml_root_written())
    xml_start_tag("nmaprun");
  /* Close all open XML elements but one. */
  while (xml_depth() > 1) {
    xml_end_tag();
    xml_newline();
  }
  if (xml_depth() == 1) {
    char errbuf[1024];

    va_start(ap, fmt);
    Vsnprintf(errbuf, sizeof(errbuf), fmt, ap);
    va_end(ap);

    xml_start_tag("runstats");
    print_xml_finished_open(timep, &tv);
    xml_attribute("exit", "error");
    xml_attribute("errormsg", "%s", errbuf);
    xml_close_empty_tag();

    print_xml_hosts();
    xml_newline();

    xml_end_tag(); /* runstats */
    xml_newline();

    xml_end_tag(); /* nmaprun */
    xml_newline();
  }

	exit(1);//remain to fill
}

void error(const char *fmt, ...) {
  va_list  ap;

  va_start(ap, fmt);
  // log_vwrite(LOG_NORMAL|LOG_STDERR, fmt, ap);
  printf("error message:%s",fmt);
  va_end(ap);
  // log_write(LOG_NORMAL|LOG_STDERR , "\n");
  return;
}

void pfatal(const char *fmt, ...) {
  time_t timep;
  struct timeval tv;
  va_list ap;
  int error_number;
  char errbuf[1024], *strerror_s;

#ifdef WIN32
  error_number = GetLastError();
  FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,
                NULL, error_number, MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPTSTR) &strerror_s,  0, NULL);
#else
  error_number = errno;
  strerror_s = strerror(error_number);
#endif

  gettimeofday(&tv, NULL);
  timep = time(NULL);

  va_start(ap, fmt);
  Vsnprintf(errbuf, sizeof(errbuf), fmt, ap);
  va_end(ap);

  // log_write(LOG_NORMAL|LOG_STDERR, "%s: %s (%d)\n",
  //           errbuf, strerror_s, error_number);
  printf("%s: %s (%d)\n",
            errbuf, strerror_s, error_number);

  if (xml_tag_open())
    xml_close_start_tag();
  if (!xml_root_written())
    xml_start_tag("nmaprun");
  /* Close all open XML elements but one. */
  while (xml_depth() > 1) {
    xml_end_tag();
    xml_newline();
  }
  if (xml_depth() == 1) {
    xml_start_tag("runstats");
    print_xml_finished_open(timep, &tv);
    xml_attribute("exit", "error");
    xml_attribute("errormsg", "%s: %s (%d)", errbuf, strerror_s, error_number);
    xml_close_empty_tag();

    print_xml_hosts();
    xml_newline();

    xml_end_tag(); /* runstats */
    xml_newline();

    xml_end_tag(); /* nmaprun */
    xml_newline();
  }

#ifdef WIN32
  HeapFree(GetProcessHeap(), 0, strerror_s);
#endif

  //log_flush(LOG_NORMAL);
  fflush(stderr);
  exit(1);
}

/* This function is the Nmap version of perror. It is like pfatal, but it
   doesn't write to XML and it only returns, doesn't exit. */
void gh_perror(const char *fmt, ...) {
  va_list ap;
  int error_number;
  char *strerror_s;

#ifdef WIN32
  error_number = GetLastError();
  FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,
                NULL, error_number, MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPTSTR) &strerror_s,  0, NULL);
#else
  error_number = errno;
  strerror_s = strerror(error_number);
#endif

  va_start(ap, fmt);
  // log_vwrite(LOG_NORMAL|LOG_STDERR, fmt, ap);
  // I hate you!
  va_end(ap);
  // log_write(LOG_NORMAL|LOG_STDERR, ": %s (%d)\n",
  //   strerror_s, error_number);
  printf(": %s (%d)\n",
    strerror_s, error_number);

#ifdef WIN32
  HeapFree(GetProcessHeap(), 0, strerror_s);
#endif

  //log_flush(LOG_NORMAL);
  fflush(stderr);
  return;
}