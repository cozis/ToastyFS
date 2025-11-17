#ifndef WAL_INCLUDED
#define WAL_INCLUDED

typedef struct {
} WAL;

int  wal_open   (WAL *wal, FileTree *file_tree, string file_path)
void wal_close  (WAL *wal);
int  wal_append (WAL *wal, WALEntry entry);

#endif // WAL_INCLUDED
