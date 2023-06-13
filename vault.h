#include "zip.h"

typedef struct VAULT {
    struct zip* archive;
    char* source;
    zip_source_t *zip_source;
    char* exclude_suffix;
    char* encryption_key;
} VAULT;

// An alias to zip_stat_t that holds information about an item in a vault.
typedef zip_stat_t vault_stat;
#define VAULT_FILE_OVERWRITE 8192u
#define VAULT_CREATE 1
#define VAULT_DISCARD 1

// Open the zip archive saved as filename and reads into VAULT struct.
// Setting an `exclude_suffix` means files with this suffix won't be listed by default when calling `vault_list`. Set to null if this feature won't be used.
// Specify whether to create a new vault if the specified one doesn't exist by setting create_flag to a non-zero value.
VAULT* vault_open(const char* filename, char* key, char* exclude_suffix, int create_flag);

// Opens a zip archive from a buffer *buf with size bufsize.
// Returns the vault if successful and NULL otherwise.
VAULT *vault_open_from_buffer(const void *buf, size_t bufsize, char *key, char* ex_suffix);

// Retrieves a file from an open vault.
// Returns the file data if successful and NULL otherwise.
char* vault_get(VAULT* vault, const char* filename);

// Deletes a file from an open vault.
// Returns 0 if successful and -1 otherwise.
int vault_del(VAULT* vault, const char* filename);

// Replaces the old vault key with the new one right after re-encrypting all files in the vault.
// You can only make changes to items in the vault  if the previous changes were saved.
// Returns 0 if successful, -2 if changes to the vault haven't been saved yet (vault_close()) and -1 otherwise.
int vault_rotate_key(VAULT *vault, char *new_key);

// Inserts the specified buffer into the vault, saved under 'filename'.
// set flag_ovrwrt to VAULT_FILE_OVERWRITE to overwrite a file if it exists with the same name in the vault
// Returns the index of the new item in the vault if successful, and -1 otherwise.
int vault_put(VAULT *vault, const char *filebuf, size_t filesize, int flag_ovrwrt, const char *filename);

// Closes the vault provided by freeing the memory it occupies and writing changes to disk.
// Setting `flag_discard` to VAULT_DISCARD, or a value greater than 0, discards the changes made to the vault.
// Returns 0 if successful and -1 otherwise.
int vault_close(VAULT *vault, int flag_discard);

// Closes a vault that was opened from a buffer, returning the zip archive file data. If an error is encountered, NULL is returned.
char *vault_close_buffer(VAULT *vault);

// Saves changes to the vault, and reopens the vault with the same properties as the previous one.
// Returns NULL if unsuccessful.
int vault_refresh(VAULT **vault);

// Frees memory allocated for the call to vault_list().
void vault_list_free(vault_stat **list);

// Returns a pointer to pointers to item information, the last of the pointers being NULL.
// If there is nothing in the archive, only NULL is returned.
// Setting flag_include_all to a number>0 will list all items, including those with the exclude suffix.
vault_stat **vault_list_items(VAULT* vault, int flag_include_all);