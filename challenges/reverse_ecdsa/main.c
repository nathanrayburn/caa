#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ecdsa.h"

const char *g_filelist[] = {
        "ecdsa.c",
        "ecdsa.h",
        "main.c",
        ".passwd",
        NULL
};

const char *g_blacklist[] = {
        ".passwd",
        NULL
};

static int filename_is_allowed(const char *filename) {
    int i;

    for (i = 0; g_blacklist[i]; i++) {
        if (!strcmp(filename, g_blacklist[i]))
            return 0;
    }
    return 1;
}

static int filename_exists(const char *filename) {
    int i;

    for (i = 0; g_filelist[i]; i++) {
        if (!strcmp(filename, g_filelist[i]))
            return 1;
    }
    return 0;
}

static int get_string(const char *msg, char *buffer, size_t size) {
    printf("%s", msg);

    if (!fgets(buffer, size, stdin))
        return 0;

    buffer[strlen(buffer) - 1] = 0;
    return 1;
}
static int get_signature(struct ecdsa_private_key *private, char *filename_to_read){
        struct ecdsa_sig sig = {NULL, NULL};
        char filename[256];
        uint8_t random[32];
        BIGNUM *k = NULL;
        int ret = 0;
        strcpy(filename,filename_to_read);

        if (RAND_bytes(random, sizeof random) != 1) {
            printf("Failed to generate random bytes!\n");
            goto do_free;
        }

      //  if (!get_string("Filename: ", filename, sizeof filename))
       //     goto do_free;

        if (!filename_is_allowed(filename)) {
            printf("Permission denied!\n");
            goto do_free;
        }

        if (!(k = BN_new())) {
            printf("Failed to allocate k!\n");
            goto do_free;
        }

        if (!BN_bin2bn(random, sizeof random, k)) {
            printf("Failed to convert random to k!\n");
            goto do_free;
        }

        if (!ecdsa_sign(&sig, private, filename, strlen(filename), k)) {
            printf("Failed to generate signature!\n");
            goto do_free;
        }

        printf("R: ");
        BN_print_fp(stdout, sig.r);
        printf("\n");

        printf("S: ");
        BN_print_fp(stdout, sig.s);
        printf("\n");

        ret = 1;

        do_free:
        ecdsa_sig_free(&sig);
        OPENSSL_cleanse(random, sizeof random);
        if (k)
            BN_clear_free(k);

        return ret;
}/*
static int get_signature(struct ecdsa_private_key *private) {
    struct ecdsa_sig sig = {NULL, NULL};
    char filename[256];
    uint8_t random[32];
    BIGNUM *k = NULL;
    int ret = 0;

    if (RAND_bytes(random, sizeof random) != 1) {
        printf("Failed to generate random bytes!\n");
        goto do_free;
    }

    if (!get_string("Filename: ", filename, sizeof filename))
        goto do_free;

    if (!filename_is_allowed(filename)) {
        printf("Permission denied!\n");
        goto do_free;
    }

    if (!(k = BN_new())) {
        printf("Failed to allocate k!\n");
        goto do_free;
    }

    if (!BN_bin2bn(random, sizeof random, k)) {
        printf("Failed to convert random to k!\n");
        goto do_free;
    }

    if (!ecdsa_sign(&sig, private, filename, strlen(filename), k)) {
        printf("Failed to generate signature!\n");
        goto do_free;
    }

    printf("R: ");
    BN_print_fp(stdout, sig.r);
    printf("\n");

    printf("S: ");
    BN_print_fp(stdout, sig.s);
    printf("\n");

    ret = 1;

    do_free:
    ecdsa_sig_free(&sig);
    OPENSSL_cleanse(random, sizeof random);
    if (k)
        BN_clear_free(k);

    return ret;
}*/

static int print_filecontent(const char *filename) {
    char buffer[1024];
    FILE *fp;

    if ((fp = fopen(filename, "r")) == NULL) {
        perror("fopen: ");
        return 0;
    }

    while (fgets(buffer, sizeof buffer, fp)) {
        printf("%s", buffer);
    }
    fclose(fp);
    return 1;
}

static int get_filecontent(struct ecdsa_public_key *public) {
    struct ecdsa_sig sig = {NULL, NULL};
    char filename[256];
    char r[256];
    char s[256];
    int ret = 0;

    memset(filename, 0, sizeof filename);

    if (!get_string("Filename: ", filename, sizeof filename))
        goto do_free;

    if (!filename_exists(filename)) {
        printf("File not found!\n");
        goto do_free;
    }

    if (!get_string("R: ", r, sizeof r))
        goto do_free;

    if (!get_string("S: ", s, sizeof s))
        goto do_free;

    if (!(sig.r = BN_new())) {
        printf("Failed to allocate r!\n");
        goto do_free;
    }

    if (!(sig.s = BN_new())) {
        printf("Failed to allocate s!\n");
        goto do_free;
    }

    if (!BN_hex2bn(&sig.r, r)) {
        printf("Bad format for r!\n");
        goto do_free;
    }

    if (!BN_hex2bn(&sig.s, s)) {
        printf("Bad format for s!\n");
        goto do_free;
    }

    if (ecdsa_verify(&sig, public, filename, strlen(filename))) {
        print_filecontent(filename);
    } else {
        printf("Bad signature!\n");
    }

    ret = 1;

    do_free:
    ecdsa_sig_free(&sig);
    return ret;
}

static void prompt(void) {
    int i;

    printf("\n\n");
    printf("Welcome to our secure, remote and signed filesystem!\n");
    printf("1) Get file signature\n");
    printf("2) Get file content\n");
    printf("3) Exit\n");
    printf("\n");
    printf("Available files:\n");
    for (i = 0; g_filelist[i]; i++) {
        printf("   * %s\n", g_filelist[i]);
    }
    printf("\n");
    printf(">>> ");

}

static void menu(struct ecdsa_public_key *public,
                 struct ecdsa_private_key *private) {
    char buffer[4];

    prompt();
    while (fgets(buffer, sizeof buffer, stdin)) {
        buffer[strcspn(buffer, "\r\n")] = 0;

        if (!strcmp(buffer, "1")) {
            char filename[256] = "ecdsa.c";
            printf("20 Signatures for file : %s\n",filename);
            for(int i = 0; i<20;++i){
                if (!get_signature(private,filename))
                    break;
                printf("\n");
            }

        } else if (!strcmp(buffer, "2")) {
            if (!get_filecontent(public))
                break;
        } else if (!strcmp(buffer, "3")) {
            break;
        } else {
            printf("%s: invalid option.\n", buffer);
        }

        prompt();
    }
}

int main(void) {
    struct ecdsa_public_key public;
    struct ecdsa_private_key private;

    setvbuf(stdout, NULL, _IONBF, 0);

    if (!ecdsa_generate_keys(&public, &private)) {
        printf("Failed to generate ECDSA keypair!\n");
        exit(EXIT_FAILURE);
    }



    menu(&public, &private);

    ecdsa_private_key_free(&private);
    ecdsa_public_key_free(&public);

    return EXIT_SUCCESS;
}