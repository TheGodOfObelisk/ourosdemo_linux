#ifndef MY_XML_H
#define MY_XML_H

#include <stdarg.h>

int xml_write_raw(const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));
int xml_write_escaped(const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));
int xml_write_escaped_v(const char *fmt, va_list va) __attribute__ ((format (printf, 1, 0)));

int xml_start_document(const char *rootnode);

int xml_start_comment();
int xml_end_comment();

int xml_open_pi(const char *name);
int xml_close_pi();

int xml_open_start_tag(const char *name, const bool write = true);
int xml_close_start_tag(const bool write = true);
int xml_close_empty_tag();
int xml_start_tag(const char *name, const bool write = true);
int xml_end_tag();

int xml_attribute(const char *name, const char *fmt, ...) __attribute__ ((format (printf, 2, 3)));

int xml_newline();

int xml_depth();
bool xml_tag_open();
bool xml_root_written();


char *xml_unescape(const char *str);

#endif