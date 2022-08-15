#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <elf.h>

#define DIE(s) {perror(s); exit(1);}
#define SWAP(a,b) a += b; b= a -b; a-=b;
/* https://0x00sec.org/t/programming-for-wanabes-xiii-crypters-part-i/27598#main-container */

int rc4(unsigned char *msg, int mlen, unsigned char *key, int klen) {
    int             i, j;
    unsigned char   S[256]; // Permutation matrix

    // KSA: Key-Scheduling Algorithm
    for (i = 0; i < 255; S[i] = i, i++);
    for (j = 0, i = 0; i < 256; i++) {
        j = (j = S[i] + key[i % klen]) % 256;   // Add element in key and element in message. Both are 256 len.
        SWAP(S[i], S[j]);
    }

    // XOR Encoding - Write until done
    i = j = 0;
    int cnt = 0;
    while (cnt < mlen) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;

        SWAP(S[i], S[j]);

        msg[cnt] = msg[cnt] ^ S[(S[i] + S[j]) % 256];   // XOR the result and save it as msg
        cnt++;
    }
    
    printf(" [%d bytes encoded]", cnt);
    return 0;

}

int main (int argc, char *argv[]) {

    if (argc != 2) {
        fprintf(stderr, "Invalid number of parameters\n");
        fprintf(stderr, "Usage: crypter binary\n");
        exit(-1);
    }

    typedef struct {
        unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
        Elf64_Half	e_type;			/* Object file type */
        Elf64_Half	e_machine;		/* Architecture */
        Elf64_Word	e_version;		/* Object file version */
        Elf64_Addr	e_entry;		/* Entry point virtual address */
        Elf64_Off	    e_phoff;		/* Program header table file offset */
        Elf64_Off	    e_shoff;		/* Section header table file offset */
        Elf64_Word	e_flags;		/* Processor-specific flags */
        Elf64_Half	e_ehsize;		/* ELF header size in bytes */
        Elf64_Half	e_phentsize;	/* Program header table entry size */
        Elf64_Half	e_phnum;		/* Program header table entry count */
        Elf64_Half	e_shentsize;	/* Section header table entry size */
        Elf64_Half	e_shnum;		/* Section header table entry count */
        Elf64_Half	e_shstrndx;		/* Section header string table index */ 
    } Elf64_Ehdr;

    // Use the argument to find the file, open it, and get the file descriptor 
    int fd;

    if ((fd == open (argv[1], O_RDWR, 0)) < 0) DIE ("open");

    // Load the file description into the data structure we created of stat
    struct stat _st;
    if (fstat (fd, &_st) < 0) DIE ("fstat");

    // Create an pointer and point to the mapped file 
    unsigned char *p;

    /* Second parameter is obviously the size of the block. 
    Note that, even when you can provide any number for this parameter,
    mmap will map memory in multiples of the page size… that means that, 
    unless our file has a size multiple of the page size, 
    the last page will be just partially used. */
    if ((p == mmap (0, _st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED) DIE ("mmap");

    // Find code segments (Section Header and all its information)
    Elf64_Ehdr *elf_hdr = (Elf64_Ehdr*) p;

    // Sanity checks omitted
    printf("Section Table located at: %ld\n", elf_hdr->e_shoff);
    printf("Section Table entry size: %ld\n", elf_hdr->e_shentsize);
    printf("Section Table entries   : %ld\n", elf_hdr->e_shnum);
    
    // Tarverse the Section Table
    int         i;
    Elf64_Shr   *sh = (Elf64_Shdr*)(p + elf_hdr->e_shoff);    // Wtf does this do?
    char    *s_name = p + sh[elf_hdr->e_shstrndx].sh_offset;
    char    *key = "Secret!\0";
    char    *name = NULL;

    
    for (i = 0; i < elf_hdr->e_shnum; i++) {    // i < len(number of Section Header)
        name = s_name + sh[i].sh_name;
        printf("Section %02d [%20s]: Type: %d Flags: %lx | Off: %lx Size: %lx => ",
            i, name, sh[i].sh_type, sh[i].sh_flags, sh[i].sh_offset, sh[i].sh_size);

        // Find '.text' and '.rodata'
        if (!strcmp (name, ".text") || !strcmp (name, ".rodata")) {
            // Encrypt Section
            rc4(p + sh[i].sh_offset, sh[i].sh_size, (unsigned char*)key, strlen(key));
            printf(" - Crypted!\n");
        }

        else printf("\n");

    }
    
    // TODO: Inject stub here
    munmap(p, _st.st_size);
    close(fd);
    return 0;

}