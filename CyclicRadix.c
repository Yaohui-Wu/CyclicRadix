// Usage (encryption): CyclicBase -C/c plaintext.file ciphertext.file password
// Usage (decryption): CyclicBase -P/p ciphertext.file plaintext.file password
// Compiled on MacOS, Linux and *BSD in X86_64 platform.
// Talk is SO EASY, show you my GOD.
// Simple is beautiful.

#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

// Each value of 256 numbers of key table that you can set randomly,
// yet you can freely to change to key table of 65536 numbers that you can set the value randomly,
// you can also freely to change to key table of 4294967296 numbers that you can set the value randomly,
// even if to change to key table of 18446744073709551616 numberes is no problem, which is only limited by the memory of your machine. WOW!
unsigned char aucKeyTable[256] = {
    0xb3, 0x6E, 0xe9, 0x06, 0xcF, 0x60, 0x3E, 0xc5, 0x3D, 0x8D, 0xdE, 0x44, 0xcD, 0x3A, 0xeA, 0x61, 0x41, 0x99, 0xd3, 0x4C, 0x04, 0x70, 0x49, 0x94, 0x9E, 0xdB, 0xc4, 0x0F, 0xf9, 0xaE, 0x7B, 0xa1,
    0xfF, 0xeC, 0xb7, 0x3B, 0x79, 0x9F, 0x98, 0xf3, 0xc1, 0xc2, 0x39, 0xb1, 0xa9, 0x1C, 0xe5, 0xd8, 0x8E, 0x62, 0xfA, 0xbA, 0xaC, 0x1D, 0x3F, 0x5E, 0xd5, 0x69, 0x48, 0x29, 0x57, 0x59, 0x51, 0xcB,
    0xa5, 0x4A, 0x7F, 0x15, 0xbD, 0x64, 0x84, 0x4E, 0xaD, 0x43, 0x83, 0xf5, 0x8F, 0x91, 0xc8, 0xd1, 0x24, 0x78, 0x0B, 0x1B, 0x37, 0x7D, 0x6F, 0x97, 0x93, 0x21, 0x9C, 0x03, 0x42, 0xbE, 0x2D, 0xeF,
    0x74, 0x87, 0x2B, 0x9B, 0x7E, 0xc0, 0x72, 0x27, 0x07, 0x47, 0xdD, 0xcA, 0x80, 0x09, 0x34, 0x88, 0xa6, 0x16, 0xaA, 0x89, 0xb6, 0x46, 0x92, 0xdA, 0x40, 0x4D, 0xaF, 0x25, 0x30, 0x0E, 0x63, 0xd9,
    0xa2, 0xeE, 0x28, 0x19, 0x33, 0x50, 0x8C, 0x5D, 0x01, 0x5C, 0x53, 0xcE, 0xf6, 0xc9, 0x86, 0xb4, 0xd2, 0x71, 0x11, 0x4F, 0x65, 0x00, 0xa3, 0x0C, 0x75, 0xfE, 0x1F, 0xf4, 0x67, 0x6D, 0x7C, 0x2C,
    0x68, 0x4B, 0x45, 0xc6, 0x0A, 0x58, 0x23, 0x1E, 0x35, 0x2E, 0x8B, 0xf8, 0x95, 0xbB, 0x0D, 0x17, 0xeB, 0x82, 0x9A, 0xd6, 0x7A, 0xa8, 0x13, 0x1A, 0xf1, 0x02, 0x20, 0xd7, 0x81, 0xbC, 0xe1, 0x52,
    0xa7, 0x85, 0x56, 0x31, 0x38, 0xb0, 0xf7, 0x05, 0xe8, 0x77, 0x9D, 0xdC, 0xc7, 0xe4, 0x6A, 0xd0, 0x5A, 0x90, 0x22, 0x54, 0x96, 0xdF, 0x08, 0xe3, 0x36, 0xb5, 0x5F, 0xb8, 0xeD, 0xe0, 0x2A, 0x5B,
    0xfD, 0xe2, 0x6B, 0xe7, 0xc3, 0x73, 0x76, 0x66, 0x2F, 0x3C, 0x8A, 0x26, 0xcC, 0x12, 0xaB, 0xf0, 0xf2, 0x10, 0xe6, 0xa0, 0x18, 0xa4, 0xfB, 0xb9, 0x14, 0xfC, 0xb2, 0xd4, 0x55, 0xbF, 0x6C, 0x32};

// also Base8 coding
unsigned char aucBase7Coding[256][3] = {
    '0', '0', '0', '1', '0', '0', '2', '0', '0', '3', '0', '0', '4', '0', '0', '5', '0', '0', '6', '0', '0', '0', '1', '0', '1', '1', '0', '2', '1', '0', '3', '1', '0', '4', '1', '0', '5', '1', '0', '6', '1', '0', '0', '2', '0', '1', '2', '0', '2', '2', '0', '3', '2', '0', '4', '2', '0',
    '5', '2', '0', '6', '2', '0', '0', '3', '0', '1', '3', '0', '2', '3', '0', '3', '3', '0', '4', '3', '0', '5', '3', '0', '6', '3', '0', '0', '4', '0', '1', '4', '0', '2', '4', '0', '3', '4', '0', '4', '4', '0', '5', '4', '0', '6', '4', '0', '0', '5', '0', '1', '5', '0', '2', '5', '0',
    '3', '5', '0', '4', '5', '0', '5', '5', '0', '6', '5', '0', '0', '6', '0', '1', '6', '0', '2', '6', '0', '3', '6', '0', '4', '6', '0', '5', '6', '0', '6', '6', '0', '0', '0', '1', '1', '0', '1', '2', '0', '1', '3', '0', '1', '4', '0', '1', '5', '0', '1', '6', '0', '1', '0', '1', '1',
    '1', '1', '1', '2', '1', '1', '3', '1', '1', '4', '1', '1', '5', '1', '1', '6', '1', '1', '0', '2', '1', '1', '2', '1', '2', '2', '1', '3', '2', '1', '4', '2', '1', '5', '2', '1', '6', '2', '1', '0', '3', '1', '1', '3', '1', '2', '3', '1', '3', '3', '1', '4', '3', '1', '5', '3', '1',
    '6', '3', '1', '0', '4', '1', '1', '4', '1', '2', '4', '1', '3', '4', '1', '4', '4', '1', '5', '4', '1', '6', '4', '1', '0', '5', '1', '1', '5', '1', '2', '5', '1', '3', '5', '1', '4', '5', '1', '5', '5', '1', '6', '5', '1', '0', '6', '1', '1', '6', '1', '2', '6', '1', '3', '6', '1',
    '4', '6', '1', '5', '6', '1', '6', '6', '1', '0', '0', '2', '1', '0', '2', '2', '0', '2', '3', '0', '2', '4', '0', '2', '5', '0', '2', '6', '0', '2', '0', '1', '2', '1', '1', '2', '2', '1', '2', '3', '1', '2', '4', '1', '2', '5', '1', '2', '6', '1', '2', '0', '2', '2', '1', '2', '2',
    '2', '2', '2', '3', '2', '2', '4', '2', '2', '5', '2', '2', '6', '2', '2', '0', '3', '2', '1', '3', '2', '2', '3', '2', '3', '3', '2', '4', '3', '2', '5', '3', '2', '6', '3', '2', '0', '4', '2', '1', '4', '2', '2', '4', '2', '3', '4', '2', '4', '4', '2', '5', '4', '2', '6', '4', '2',
    '0', '5', '2', '1', '5', '2', '2', '5', '2', '3', '5', '2', '4', '5', '2', '5', '5', '2', '6', '5', '2', '0', '6', '2', '1', '6', '2', '2', '6', '2', '3', '6', '2', '4', '6', '2', '5', '6', '2', '6', '6', '2', '0', '0', '3', '1', '0', '3', '2', '0', '3', '3', '0', '3', '4', '0', '3',
    '5', '0', '3', '6', '0', '3', '0', '1', '3', '1', '1', '3', '2', '1', '3', '3', '1', '3', '4', '1', '3', '5', '1', '3', '6', '1', '3', '0', '2', '3', '1', '2', '3', '2', '2', '3', '3', '2', '3', '4', '2', '3', '5', '2', '3', '6', '2', '3', '0', '3', '3', '1', '3', '3', '2', '3', '3',
    '3', '3', '3', '4', '3', '3', '5', '3', '3', '6', '3', '3', '0', '4', '3', '1', '4', '3', '2', '4', '3', '3', '4', '3', '4', '4', '3', '5', '4', '3', '6', '4', '3', '0', '5', '3', '1', '5', '3', '2', '5', '3', '3', '5', '3', '4', '5', '3', '5', '5', '3', '6', '5', '3', '0', '6', '3',
    '1', '6', '3', '2', '6', '3', '3', '6', '3', '4', '6', '3', '5', '6', '3', '6', '6', '3', '0', '0', '4', '1', '0', '4', '2', '0', '4', '3', '0', '4', '4', '0', '4', '5', '0', '4', '6', '0', '4', '0', '1', '4', '1', '1', '4', '2', '1', '4', '3', '1', '4', '4', '1', '4', '5', '1', '4',
    '6', '1', '4', '0', '2', '4', '1', '2', '4', '2', '2', '4', '3', '2', '4', '4', '2', '4', '5', '2', '4', '6', '2', '4', '0', '3', '4', '1', '3', '4', '2', '3', '4', '3', '3', '4', '4', '3', '4', '5', '3', '4', '6', '3', '4', '0', '4', '4', '1', '4', '4', '2', '4', '4', '3', '4', '4',
    '4', '4', '4', '5', '4', '4', '6', '4', '4', '0', '5', '4', '1', '5', '4', '2', '5', '4', '3', '5', '4', '4', '5', '4', '5', '5', '4', '6', '5', '4', '0', '6', '4', '1', '6', '4', '2', '6', '4', '3', '6', '4', '4', '6', '4', '5', '6', '4', '6', '6', '4', '0', '0', '5', '1', '0', '5',
    '2', '0', '5', '3', '0', '5', '4', '0', '5', '5', '0', '5', '6', '0', '5', '0', '1', '5', '1', '1', '5', '2', '1', '5', '3', '1', '5'};

// also Base8 coding
unsigned char aucBase9Coding[256][3] = {
    '0', '0', '0', '1', '0', '0', '2', '0', '0', '3', '0', '0', '4', '0', '0', '5', '0', '0', '6', '0', '0', '7', '0', '0', '8', '0', '0', '0', '1', '0', '1', '1', '0', '2', '1', '0', '3', '1', '0', '4', '1', '0', '5', '1', '0', '6', '1', '0', '7', '1', '0', '8', '1', '0', '0', '2', '0',
    '1', '2', '0', '2', '2', '0', '3', '2', '0', '4', '2', '0', '5', '2', '0', '6', '2', '0', '7', '2', '0', '8', '2', '0', '0', '3', '0', '1', '3', '0', '2', '3', '0', '3', '3', '0', '4', '3', '0', '5', '3', '0', '6', '3', '0', '7', '3', '0', '8', '3', '0', '0', '4', '0', '1', '4', '0',
    '2', '4', '0', '3', '4', '0', '4', '4', '0', '5', '4', '0', '6', '4', '0', '7', '4', '0', '8', '4', '0', '0', '5', '0', '1', '5', '0', '2', '5', '0', '3', '5', '0', '4', '5', '0', '5', '5', '0', '6', '5', '0', '7', '5', '0', '8', '5', '0', '0', '6', '0', '1', '6', '0', '2', '6', '0',
    '3', '6', '0', '4', '6', '0', '5', '6', '0', '6', '6', '0', '7', '6', '0', '8', '6', '0', '0', '7', '0', '1', '7', '0', '2', '7', '0', '3', '7', '0', '4', '7', '0', '5', '7', '0', '6', '7', '0', '7', '7', '0', '8', '7', '0', '0', '8', '0', '1', '8', '0', '2', '8', '0', '3', '8', '0',
    '4', '8', '0', '5', '8', '0', '6', '8', '0', '7', '8', '0', '8', '8', '0', '0', '0', '1', '1', '0', '1', '2', '0', '1', '3', '0', '1', '4', '0', '1', '5', '0', '1', '6', '0', '1', '7', '0', '1', '8', '0', '1', '0', '1', '1', '1', '1', '1', '2', '1', '1', '3', '1', '1', '4', '1', '1',
    '5', '1', '1', '6', '1', '1', '7', '1', '1', '8', '1', '1', '0', '2', '1', '1', '2', '1', '2', '2', '1', '3', '2', '1', '4', '2', '1', '5', '2', '1', '6', '2', '1', '7', '2', '1', '8', '2', '1', '0', '3', '1', '1', '3', '1', '2', '3', '1', '3', '3', '1', '4', '3', '1', '5', '3', '1',
    '6', '3', '1', '7', '3', '1', '8', '3', '1', '0', '4', '1', '1', '4', '1', '2', '4', '1', '3', '4', '1', '4', '4', '1', '5', '4', '1', '6', '4', '1', '7', '4', '1', '8', '4', '1', '0', '5', '1', '1', '5', '1', '2', '5', '1', '3', '5', '1', '4', '5', '1', '5', '5', '1', '6', '5', '1',
    '7', '5', '1', '8', '5', '1', '0', '6', '1', '1', '6', '1', '2', '6', '1', '3', '6', '1', '4', '6', '1', '5', '6', '1', '6', '6', '1', '7', '6', '1', '8', '6', '1', '0', '7', '1', '1', '7', '1', '2', '7', '1', '3', '7', '1', '4', '7', '1', '5', '7', '1', '6', '7', '1', '7', '7', '1',
    '8', '7', '1', '0', '8', '1', '1', '8', '1', '2', '8', '1', '3', '8', '1', '4', '8', '1', '5', '8', '1', '6', '8', '1', '7', '8', '1', '8', '8', '1', '0', '0', '2', '1', '0', '2', '2', '0', '2', '3', '0', '2', '4', '0', '2', '5', '0', '2', '6', '0', '2', '7', '0', '2', '8', '0', '2',
    '0', '1', '2', '1', '1', '2', '2', '1', '2', '3', '1', '2', '4', '1', '2', '5', '1', '2', '6', '1', '2', '7', '1', '2', '8', '1', '2', '0', '2', '2', '1', '2', '2', '2', '2', '2', '3', '2', '2', '4', '2', '2', '5', '2', '2', '6', '2', '2', '7', '2', '2', '8', '2', '2', '0', '3', '2',
    '1', '3', '2', '2', '3', '2', '3', '3', '2', '4', '3', '2', '5', '3', '2', '6', '3', '2', '7', '3', '2', '8', '3', '2', '0', '4', '2', '1', '4', '2', '2', '4', '2', '3', '4', '2', '4', '4', '2', '5', '4', '2', '6', '4', '2', '7', '4', '2', '8', '4', '2', '0', '5', '2', '1', '5', '2',
    '2', '5', '2', '3', '5', '2', '4', '5', '2', '5', '5', '2', '6', '5', '2', '7', '5', '2', '8', '5', '2', '0', '6', '2', '1', '6', '2', '2', '6', '2', '3', '6', '2', '4', '6', '2', '5', '6', '2', '6', '6', '2', '7', '6', '2', '8', '6', '2', '0', '7', '2', '1', '7', '2', '2', '7', '2',
    '3', '7', '2', '4', '7', '2', '5', '7', '2', '6', '7', '2', '7', '7', '2', '8', '7', '2', '0', '8', '2', '1', '8', '2', '2', '8', '2', '3', '8', '2', '4', '8', '2', '5', '8', '2', '6', '8', '2', '7', '8', '2', '8', '8', '2', '0', '0', '3', '1', '0', '3', '2', '0', '3', '3', '0', '3',
    '4', '0', '3', '5', '0', '3', '6', '0', '3', '7', '0', '3', '8', '0', '3', '0', '1', '3', '1', '1', '3', '2', '1', '3', '3', '1', '3'};

// generate random number of "JunTai" distribution
void JunTai(unsigned char *pucPassword, unsigned long ulPasswordLength)
{
// key table convert 8 * 32 = 256 bytes of data at a time in order to generate the random number of "JunTai" distribution
        for(unsigned long i = 0; i < 32; ++i)
        {
            unsigned long *pulKeySwap1 = (unsigned long*)aucKeyTable, *pulKeySwap2 = (unsigned long*)aucKeyTable, ulKeyTemp, ulKeyIndex;

            ulKeyIndex = pucPassword[i % ulPasswordLength] % 32;

            ulKeyTemp = pulKeySwap1[i];

            pulKeySwap1[i] = pulKeySwap2[ulKeyIndex];

            pulKeySwap2[ulKeyIndex] = ulKeyTemp;
        }
}

void changePassword(unsigned char *pucPassword, unsigned long ulPasswordLength)
{
// use encoded table's value to change the password
    for(unsigned long j = 0; j < ulPasswordLength; ++j)
    {
        pucPassword[j] = aucKeyTable[pucPassword[j]];
    }
}

void Encrypt(char *argv[])
{
// any password length
    unsigned long ulPasswordLength = -1;

// get password length
    while(argv[2][++ulPasswordLength]);

    struct stat statFileSize;

    stat(argv[0], &statFileSize);

// get the plaintext length and ciphertext length
    unsigned long ulPlaintextLength = statFileSize.st_size, ulCiphertextLength = 3 * ulPlaintextLength;

// allocate storage space
    unsigned char *pucPlaintext = (unsigned char*)malloc(ulPlaintextLength), *pucCiphertext = (unsigned char*)malloc(ulCiphertextLength);

// open the plaintext file descriptor
    int iPlaintextOrCiphertextFD = open(argv[0], O_RDONLY, S_IRUSR | S_IWUSR);

// read data from the plaintext file
    read(iPlaintextOrCiphertextFD, pucPlaintext, ulPlaintextLength);

    close(iPlaintextOrCiphertextFD);

// process the plaintext data
    for(unsigned long i = 0, k = 0; i < ulPlaintextLength; i += 256)
    {
        JunTai((unsigned char*)argv[2], ulPasswordLength);

// rotate base
        for(unsigned long j = 0; j < 256 && i + j < ulPlaintextLength; ++j)
        {
            if(aucKeyTable[j] % 2)
            {
                pucCiphertext[k++] = aucBase9Coding[pucPlaintext[i + j]][0];

                pucCiphertext[k++] = aucBase9Coding[pucPlaintext[i + j]][1];

                pucCiphertext[k++] = aucBase9Coding[pucPlaintext[i + j]][2];
            }
            else
            {
                pucCiphertext[k++] = aucBase7Coding[pucPlaintext[i + j]][0];

                pucCiphertext[k++] = aucBase7Coding[pucPlaintext[i + j]][1];

                pucCiphertext[k++] = aucBase7Coding[pucPlaintext[i + j]][2];
            }
        }

        changePassword((unsigned char*)argv[2], ulPasswordLength);
    }
// open the ciphertext file descriptor
    iPlaintextOrCiphertextFD = open(argv[1], O_CREAT | O_WRONLY, S_IREAD | S_IWRITE);

// write data to the ciphertext file
    write(iPlaintextOrCiphertextFD, pucCiphertext, ulCiphertextLength);

    close(iPlaintextOrCiphertextFD);

    free(pucCiphertext);

    free(pucPlaintext);
}

void Decrypt(char *argv[])
{
// any password length
    unsigned long ulPasswordLength = -1;

// get password length
    while(argv[2][++ulPasswordLength]);

    struct stat statFileSize;

    stat(argv[0], &statFileSize);

// get the ciphertext length and plaintext length
    unsigned long ulCiphertextLength = statFileSize.st_size, ulPlaintextLength = ulCiphertextLength / 3;

// allocate storage space
    unsigned char *pucCiphertext = (unsigned char*)malloc(ulCiphertextLength), *pucPlaintext = (unsigned char*)malloc(ulPlaintextLength);

// open the ciphertext file descriptor
    int iCiphertextOrPlaintextFD = open(argv[0], O_RDONLY, S_IRUSR | S_IWUSR);

// read data from the ciphertext file
    read(iCiphertextOrPlaintextFD, pucCiphertext, ulCiphertextLength);

    close(iCiphertextOrPlaintextFD);

// process the ciphertext data
    for(unsigned long i = 0, k = 0; i < ulCiphertextLength; i += 768)
    {
        JunTai((unsigned char*)argv[2], ulPasswordLength);

// rotate base
        for(unsigned long j = 0; j < 768 && i + j < ulCiphertextLength; j += 3)
        {
            if(aucKeyTable[j / 3] % 2)
            {
                for(unsigned long l = 0; l < 256; ++l)
                {
                    if((*(unsigned int*)(pucCiphertext + i + j) & 0x00ffffff) == (*(unsigned int*)(aucBase9Coding[l]) & 0x00ffffff))
                    {
                        pucPlaintext[k++] = (unsigned char)l;

                        break;
                    }
                }
            }
            else
            {
                for(unsigned long l = 0; l < 256; ++l)
                {
                    if((*(unsigned int*)(pucCiphertext + i + j) & 0x00ffffff) == (*(unsigned int*)(aucBase7Coding[l]) & 0x00ffffff))
                    {
                        pucPlaintext[k++] = (unsigned char)l;

                        break;
                    }
                }
            }
        }

        changePassword((unsigned char*)argv[2], ulPasswordLength);
    }

// open the plaintext file descriptor
    iCiphertextOrPlaintextFD = open(argv[1], O_CREAT | O_WRONLY, S_IREAD | S_IWRITE);

// write data to the plaintext file
    write(iCiphertextOrPlaintextFD, pucPlaintext, ulPlaintextLength);

    close(iCiphertextOrPlaintextFD);

    free(pucPlaintext);

    free(pucCiphertext);
}

int main(int argc, char *argv[])
{
    if(argv[1][0] == '-')
    {
        if(argv[1][1] == 'C' || argv[1][1] == 'c')
        {
            Encrypt(argv + 2);
        }
        else if(argv[1][1] == 'P' || argv[1][1] == 'p')
        {
            Decrypt(argv + 2);
        }
    }

    return 0;
}
