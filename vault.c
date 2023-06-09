#include "stdlib.h"
#include "stdio.h"
#include "string.h"
#include "vault.h"

int vault_close(VAULT *vault, int flag_discard)
{
    int i = 0;
    if (flag_discard > 0)
        zip_discard(vault->archive);
    else
        i = zip_close(vault->archive);
    free(vault);
    return i;
}

VAULT *vault_refresh(VAULT* vault)
{
    char *enc_key, *source, *exclude_suf = NULL; // could be null

    // copy so as to keep values after vault is freed
    enc_key = malloc(strlen(vault->encryption_key) + 1);
    source = malloc(strlen(vault->source) + 1);

    strcpy(enc_key, vault->encryption_key);
    strcpy(source, vault->source);
    // handle if exclude suffix is null
    if (vault->exclude_suffix){
        exclude_suf = malloc(strlen(vault->exclude_suffix) + 1);
        strcpy(exclude_suf, vault->exclude_suffix);        
    }
    int i = zip_close(vault->archive);
    if (i < 0) return NULL;
    free(vault);

    int err = 0;
    VAULT* new_vault = vault_open(source, enc_key, exclude_suf, 0, &err);
    if (err < 0) return NULL;
    return new_vault;
}

VAULT *vault_open(const char *filename, char *key, char* ex_suffix, int create_flag, int *errorp)
{
    int flag = 0;
    if (create_flag) flag = ZIP_CREATE; 
    // must create with encryption key
    if (!key) return NULL;
    zip_t *arch = NULL;

    VAULT *vault = malloc(sizeof(VAULT));
    vault->archive = zip_open(filename, flag, errorp);
    if (!vault->archive) return NULL;
    vault->source = (char*)filename;
    vault->encryption_key = key;
    vault->exclude_suffix = ex_suffix;
    return vault;
}


int vault_del(VAULT *vault, const char *filename)
{
    vault_stat *finfo = NULL;
    
    finfo = calloc(256, sizeof(int));
    zip_stat_init(finfo);
    if ((zip_stat(vault->archive, filename, 0, finfo)) != 0) return -1;

    int i = zip_delete(vault->archive, finfo->index);
    free(finfo);
    return i;
}

char *vault_get(VAULT *vault, const char *filename)
{
    zip_file_t *fd = NULL;
    char *data = NULL;
    vault_stat *finfo = NULL;
    finfo = calloc(256, sizeof(int));
    zip_stat_init(finfo);
    if ((zip_stat(vault->archive, filename, 0, finfo)) != 0) return NULL;

    fd = zip_fopen_encrypted(vault->archive, filename, 0, vault->encryption_key);
    data = calloc(finfo->size, sizeof(char));
    zip_fread(fd, data, finfo->size);
    zip_fclose(fd);
    free(finfo);
    return data;
}

// returns 0 if str ends in suffix.
int ends_in(const char *str, const char* suffix)
{
    if (!suffix) return -1;
    char* ptr;
    if ((ptr=strrchr(str, suffix[0])) != NULL)
        return strcmp(ptr, suffix); 
    return -1;
}

int count_items(VAULT *vault, int flag_include_all)
{
    vault_stat *finfo = NULL;
    finfo = calloc(256, sizeof(int));
    zip_stat_init(finfo);
    int count = 0;
    int item_count = 0;
    while ((zip_stat_index(vault->archive, count, 0, finfo)) == 0)
    {
        if (flag_include_all > 0){
            item_count++;
            count++;
            continue;
        }
        if ((ends_in(finfo->name, vault->exclude_suffix)) != 0) item_count++;
        count++;
    }
    return item_count;
}

vault_stat **vault_list_items(VAULT *vault, int flag_include_all)
{
    int num_items;
    vault_stat **stat_ptr;

    num_items = count_items(vault, flag_include_all) + 1; // +1 for nullptr termination
    stat_ptr = malloc(num_items * sizeof(vault_stat*));
    int count = 0;
    while (count < zip_get_num_entries(vault->archive, 0))
    {
        vault_stat *finfo = calloc(256, sizeof(int));
        zip_stat_init(finfo);

        if ((zip_stat_index(vault->archive, count, 0, finfo)) < 0) {
            free(finfo);
            return NULL;
        }
        // skip if name ends in _exclude
        if ((ends_in(finfo->name, vault->exclude_suffix)) == 0 && !flag_include_all)
        {
            count++;
            continue;
        }
        stat_ptr[count] = finfo;
        count++;
    }
    stat_ptr[num_items - 1] = NULL;
    return stat_ptr;
}

int vault_put(VAULT *vault, const char *filebuf, size_t filesize, const char *filename)
{
    int errCode = 0;
    zip_source_t *s = NULL;
    if ((s=zip_source_buffer(vault->archive, filebuf, filesize, 0)) == NULL) return -1;
    int n, err = 0;
    n = zip_file_add(vault->archive, filename, s, ZIP_FL_ENC_UTF_8);
    if (n < 0) return n;
    err = zip_file_set_encryption(vault->archive, n, ZIP_EM_AES_256, vault->encryption_key);
    if (err < 0) return err;
    return n;
}

int vault_rotate_key(VAULT *vault, char *new_key)
{
    char *data = NULL;
    zip_file_t *fd = NULL;
    zip_source_t *source = NULL;
    vault_stat *finfo = NULL;

    int count = 0;
    while (count < zip_get_num_entries(vault->archive, 0))
    {
        finfo = calloc(256, sizeof(int));
        zip_stat_init(finfo);

        if ((zip_stat_index(vault->archive, count, 0, finfo)) < 0) {
            free(finfo);
            return -1;
        }
        fd = zip_fopen_encrypted(vault->archive, finfo->name, 0, vault->encryption_key);
        if (!fd) return -2;
        zip_fread(fd, data, finfo->size);
        zip_fclose(fd);
        // create zip source from data
        source = zip_source_buffer(vault->archive, data, finfo->size, 1);
        // replace existing file with created source (decrypted version of same file)
        zip_file_replace(vault->archive, count, source, 0);
        // re-encrypt file with new key
        zip_file_set_encryption(vault->archive, count, ZIP_EM_AES_256, new_key);
        free(finfo);
        count++;
    }
    vault->encryption_key = new_key;
    return 0;
}