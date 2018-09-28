#ifndef MY_SCAN_OUTPUT_TABLE_H
#define MY_SCAN_OUTPUT_TABLE_H
//borrowed from NmapOutputTable.h

#include "base.h"
#include <assert.h>

/**********************  DEFINES/ENUMS ***********************************/

/**********************  STRUCTURES  ***********************************/

/**********************  CLASSES     ***********************************/

struct NmapOutputTableCell {
  char *str;
  int strlength;
  bool weAllocated; // If we allocated str, we must free it.
  bool fullrow;
};

class NmapOutputTable {
 public:
  // Create a table of the given dimensions. Any completely
  // blank rows will be removed when printableTable() is called.
  // If the number of table rows is unknown then the highest
  // number of possible rows should be specified.
  NmapOutputTable(int nrows, int ncols);
  ~NmapOutputTable();

  // Copy specifies whether we must make a copy of item.  Otherwise we'll just save the
  // ptr (and you better not free it until this table is destroyed ).  Skip the itemlen parameter if you
  // don't know (and the function will use strlen).
  void addItem(unsigned int row, unsigned int column, bool copy, const char *item, int itemlen = -1);
  // Same as above but if fullrow is true, 'item' spans across all columns. The spanning starts from
  // the column argument (ie. 0 will be the first column)
  void addItem(unsigned int row, unsigned int column, bool fullrow, bool copy, const char *item, int itemlen = -1);

  // Like addItem except this version takes a printf-style format string followed by varargs
  void addItemFormatted(unsigned int row, unsigned int column, bool fullrow, const char *fmt, ...)
          __attribute__ ((format (printf, 5, 6))); // Offset by 1 to account for implicit "this" parameter.

  // This function sticks the entire table into a character buffer.
  // Note that the buffer is likely to be reused if you call the
  // function again, and it will also be invalidated if you free the
  // table. If size is not NULL, it will be filled with the size of
  // the ASCII table in bytes (not including the terminating NUL)
  // All blank rows will be removed from the returned string
  char *printableTable(int *size);

 private:

  bool emptyRow(unsigned int nrow);
  // The table, squished into 1D.  Access a member via getCellAddy
  struct NmapOutputTableCell *table;
  struct NmapOutputTableCell *getCellAddy(unsigned int row, unsigned int col) {
    assert(row < numRows);  assert(col < numColumns);
    return table + row * numColumns + col;
  }
  int *maxColLen; // An array that gives the maximum length of any member of each column
                  // (excluding terminator)
  // Array that tells the number of valid (> 0 length) items in each row
  int *itemsInRow;
  unsigned int numRows;
  unsigned int numColumns;
  char *tableout; // If printableTable() is called, we return this
  int tableoutsz; // Amount of space ALLOCATED for tableout.  Includes space allocated for NUL.
};


/**********************  PROTOTYPES  ***********************************/


#endif