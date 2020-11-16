#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sqlite/sqlite3.h"

#define SIZE_OF_BUF 10

void basic_overflows()
{
    // preparation
    const char ARR[SIZE_OF_BUF] = "123456789";

    // example 1 - ERROR ON STACK
    char buf1[SIZE_OF_BUF] = "abcdefghi";
    char *ptr1 = buf1;
    buf1[SIZE_OF_BUF-1] = 'Y';
    printf("String on ptr1: %s\n", ptr1);

    //example 2 - static - some kind of protection - 0s are behind the variable
    static char buf2[SIZE_OF_BUF] = "abcdefghi";
    char *ptr2 = buf2;
    ptr2[SIZE_OF_BUF-1] = 'X';
    //ptr2[SIZE_OF_BUF] = 'Y';
    printf("CHAR ON 9 AND 10: %i %i\n", ptr2[SIZE_OF_BUF - 1], ptr2[SIZE_OF_BUF]);
    printf("String on ptr2: %s\n", ptr2);

    // example 3 - THIS WILL PASS - HEAP
    // print more than SIZE_OF_BUF characters - information disclosure
    char *ptr3 = (char*) malloc(SIZE_OF_BUF * sizeof(char));
    strcpy(ptr3, ARR);
    ptr3[SIZE_OF_BUF - 1] = 'X';
    ptr3[SIZE_OF_BUF] = 'Y';
    printf("String on ptr3: %s\n", ptr3);

    // example 4 - INFORMATION DISCLOSURE + TAMPERING
    char *ptr4 = "123456789";
    printf("ptr 4:%p\n", ptr4);

    char *ptr5 = "SECRET";
    printf("ptr 5:%p\n", ptr5);
    // ptr5[0] = 's'; invalid
    printf("ptr 5:%p\n", ptr5);
//    ptr4[SIZE_OF_BUF - 1] = 'X';
//    ptr4[SIZE_OF_BUF ] = 'X';
//    ptr4[SIZE_OF_BUF +1] = 'X';
//    //ptr4[SIZE_OF_BUF +2] = 'X';
//    //ptr4[SIZE_OF_BUF +3] = 'X';
//    //ptr4[SIZE_OF_BUF +4] = 'X';
//    ptr4[SIZE_OF_BUF +5] = 'X';
//    ptr4[SIZE_OF_BUF +8] = 'Y';

    printf("ARRptr:%p\n", ARR);
    printf("ptr1:%p\n", ptr1);
    printf("ptr2:%p\n", ptr2);
    printf("ptr3:%p\n", ptr3);
    printf("ptr4:%p\n", ptr4);
    printf("ptr5:%p\n", ptr5);
}

void buffer_overflow_elevation_of_privilege()
{
    const char pwd[] = "CORRECT";
    char pwd_buff[12];
    int is_correct = 0;

    printf("Zadaj heslo:\n");
    gets(pwd_buff);
    if(strcmp(pwd, pwd_buff) != 0)
    {
        printf("Neuspesne prihlasenie.\n");
    }
    else
    {
        printf("Uspesne prihlasenie.\n");
        is_correct = 1;
    }

    if(is_correct)
    {
        printf("Udeleny root.\n");
    }

}

void buffer_overflow_elevation_of_privilege_mitigated()
{
    const char pwd[] = "CORRECT";
    char pwd_buff[12];
    int is_correct = 0;

    printf("Zadaj heslo:\n");
    fgets(pwd_buff, 12, stdin);
    if(strcmp(pwd, pwd_buff) != 0)
    {
        printf("Neuspesne prihlasenie.\n");
    }
    else
    {
        printf("Uspesne prihlasenie.\n");
        is_correct = 1;
    }

    if(is_correct)
    {
        printf("Udeleny root.\n");
    }

}


void format_string_user_input()
{
    char secure1[8];
    //adresa tajneho parametru
    printf("%p\n", secure1);
    char buff[64];
    strcpy(secure1, "SECURE1");

    printf("Program si vyziada meno a nasledne ho vypise. Funkcia obsahuje aj data, ktore by mali zostat tajne.\n");
    printf("zadaj meno:\n");
    gets(buff);

    //zranitelnost
    printf(buff);
    printf("\n");

    //tajny parameter
    char secure2[8];
    printf("%p\n", secure2);
    strcpy(secure2, "SECURE2");
    printf("Koniec funkcie.");
}

void format_string_user_input_mitigated()
{
    char secure1[8];
    //adresa tajneho parametru
    printf("%p\n", secure1);
    char buff[64];
    strcpy(secure1, "SECURE1");

    printf("Program si vyziada meno a nasledne ho vypise. Funkcia obsahuje aj data, ktore by mali zostat tajne.\n");
    printf("zadaj meno:\n");
    gets(buff);

    //zranitelnost osetrena
    printf("%s\n",buff);
    printf("\n");

    //tajny parameter
    char secure2[8];
    printf("%p\n", secure2);
    strcpy(secure2, "SECURE2");
    printf("Koniec funkcie.");
}

void sql_injection()
{
    sqlite3 *db;
    int rc = sqlite3_open("test.db", &db);
}

int main() {
    printf("UPB6!\n");

    //basic overflows
    //basic_overflows();

    //buffer overflow
    printf("Zadaj 30 nahodnych znakov pre explot. Napriklad 123456789123456789123456789123\n");
    buffer_overflow_elevation_of_privilege();
    buffer_overflow_elevation_of_privilege_mitigated();

    //format string
    //printf("%s", "Zadaj %s%s%s%s%s%s%s%s%s%s%s%s pre zrutenie programu.\n");
    //printf("%s", "Zadaj %08x %08x %08x %08x %08x pre citanie stacku.\n");
    //printf("%s", "Zadaj %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p pre citanie stacku.\n");
    //format_string_user_input();
    //format_string_user_input_mitigated();

    //sql injection
    //sql_injection();

    return 0;
}


