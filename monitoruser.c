#define _GNU_SOURCE
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 

FILE * config;
char * itoa(int value, char * string, int radix);
void split(char * src, const char * separator, char ** dest, int * num);

//Reference: http://www.cnblogs.com/piaoyang/p/9271879.html
void split(char * src, const char * separator, char ** dest, int * num) {
    char * pNext;
    int count = 0;
    if (src == NULL || strlen(src) == 0)
        return;
    if (separator == NULL || strlen(separator) == 0)
        return;
    pNext = strtok(src, separator);
    while (pNext != NULL) {
        * dest++ = pNext;
        ++count;
        pNext = strtok(NULL, separator);
    }
    * num = count;
}

void main(void) {
    char mode;
    char addOrRe;
    int ip1;
    int ip2;
    int ip3;
    int ip4;
    int port;
    ip1 = 0;
    ip2 = 0;
    ip3 = 0;
    ip4 = 0;
    port = 0;
    char cont;
    //printf("OK HERE");
    config = fopen("nmonitor.conf", "a+");
    size_t len = 0;
    char * strLine;;
    int read = getline( &strLine, &len, config);
    char * ptr[50] = {0};
    int num = 0;
	//Tokenize and store the origional configration.
    split(strLine, " ", ptr, & num);
	printf("Mode = 0, black list mode; mode = 1, white list mode.");
    printf("Current configration:\n");
    for (int i = 0; i < num; i++) {
        printf("%s\n", ptr[i]);
    }

    printf("Do you want to add IP and Port number(A), or rewrite the configration(R)?");
    scanf("%c", & addOrRe);
	//Consume empty line
	getchar();
	//The user wants to rewrite the file. In this way, s/he is able to change the mode.
    if (addOrRe == 'R' || addOrRe == 'r') {
        config = fopen("nmonitor.conf", "w+");
        printf("Please select black(B/b) list or white(W/w) list mode.");
        scanf("%c", &mode);
		getchar();
		// White list mode
        if (mode == 'W' || mode == 'w') {
            fprintf(config, "mode=1 addr=");
            printf("Please enter one IP address you want to add into white list:\n");
            printf("Please follow this format and end with enter:\n");
            printf("XXXX.XXXX.XXXX.XXXX\n");
            scanf("%d.%d.%d.%d", & ip1, & ip2, & ip3, & ip4);
			getchar();
            if (ip1 >= 0 && ip1 < 255 && ip2 >= 0 && ip2 < 255 && ip3 >= 0 && ip3 < 255 && ip4 >= 0 && ip4 < 255) {
                fprintf(config, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);
            }
            while (ip1 >= 0 && ip1 < 255 && ip2 >= 0 && ip2 < 255 && ip3 >= 0 && ip3 < 255 && ip4 >= 0 && ip4 < 255) {
                printf("Continue?(y/n)\n");
                scanf("%c", & cont);
				getchar();
                if (!(cont == 'Y' || cont == 'y')) {
                    break;
                }
                printf("Please enter one IP address you want to add into white list:\n");
                printf("Please follow this format and end with enter:\n");
                printf("XXXX.XXXX.XXXX.XXXX\n");
                scanf("%d.%d.%d.%d", & ip1, & ip2, & ip3, & ip4);
				getchar();
                fprintf(config, ",%d.%d.%d.%d", ip1, ip2, ip3, ip4);
            }

            fprintf(config, " port=");
            printf("Please enter one port number you want to add into white list:\n");
            printf("Please follow this format and end with enter:\n");
            printf("XXXX\n");
            scanf("%d", & port);
			getchar();
            if (port >= 0 && port < 65535) {
                fprintf(config, "%d", port);
            }
            while (port >= 0 && port < 65535) {
                printf("Continue?(y/n)\n");
                scanf("%c", & cont);
				getchar();
                if (!(cont == 'Y' || cont == 'y')) {
                    break;
                }
                printf("Please enter one port number you want to add into white list:\n");
                printf("Please follow this format and end with enter:\n");
                printf("XXXX\n");
                scanf("%d", & port);
				getchar();
                fprintf(config, ",%d", port);

            }
			//Black list mode
        } else if (mode == 'B' || mode == 'b') {
            fprintf(config, "mode=0 addr=");
            printf("Please enter one IP address you want to add into white list:\n");
            printf("Please follow this format and end with enter:\n");
            printf("XXXX.XXXX.XXXX.XXXX\n");
            scanf("%d.%d.%d.%d", & ip1, & ip2, & ip3, & ip4);
			getchar();
            if (ip1 >= 0 && ip1 < 255 && ip2 >= 0 && ip2 < 255 && ip3 >= 0 && ip3 < 255 && ip4 >= 0 && ip4 < 255) {
                fprintf(config, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);
            }
            while (ip1 >= 0 && ip1 < 255 && ip2 >= 0 && ip2 < 255 && ip3 >= 0 && ip3 < 255 && ip4 >= 0 && ip4 < 255) {
                printf("Continue?(y/n)\n");
                scanf("%c", & cont);
				getchar();
                if (!(cont == 'Y' || cont == 'y')) {
                    break;
                }
                printf("Please enter one IP address you want to add into white list:\n");
                printf("Please follow this format and end with enter:\n");
                printf("XXXX.XXXX.XXXX.XXXX\n");
                scanf("%d.%d.%d.%d", & ip1, & ip2, & ip3, & ip4);
				getchar();
                fprintf(config, ",%d.%d.%d.%d", ip1, ip2, ip3, ip4);
            }

            fprintf(config, " port=");
            printf("Please enter one port number you want to add into white list:\n");
            printf("Please follow this format and end with enter:\n");
            printf("XXXX\n");
            scanf("%d", & port);
			getchar();
            if (port >= 0 && port < 65535) {
                fprintf(config, "%d", port);
            }
            while (port >= 0 && port < 65535) {
                printf("Continue?(y/n)\n");
                scanf("%c", & cont);
				getchar();
                if (!(cont == 'Y' || cont == 'y')) {
                    break;
                }
                printf("Please enter one port number you want to add into white list:\n");
                printf("Please follow this format and end with enter:\n");
                printf("XXXX\n");
                scanf("%d", & port);
				getchar();
                fprintf(config, ",%d", port);

            }
        } else {
            printf("Wrong input.");
        }
		//The user wants to add new IP or port to the file. In this case s/he can not change the mode.
    } else if (addOrRe == 'A' || addOrRe == 'a') {
		config = fopen("nmonitor.conf", "w+");
        fprintf(config,"%s", ptr[0]);
        fprintf(config," %s",ptr[1]);
        while (ip1 >= 0 && ip1 < 255 && ip2 >= 0 && ip2 < 255 && ip3 >= 0 && ip3 < 255 && ip4 >= 0 && ip4 < 255) {
            printf("Continue to add a IP address? Yes to add, no to skip to port(y/n)\n");
            scanf("%c", & cont);
			getchar();
            if (!(cont == 'Y' || cont == 'y')) {
                break;
            }
            printf("Please enter one IP address you want to add into white list:\n");
            printf("Please follow this format and end with enter:\n");
            printf("XXXX.XXXX.XXXX.XXXX\n");
            scanf("%d.%d.%d.%d", & ip1, & ip2, & ip3, & ip4);
			getchar();
            fprintf(config, ",%d.%d.%d.%d", ip1, ip2, ip3, ip4);
        }
        fprintf(config," %s",ptr[2]);
        while (port >= 0 && port < 65535) {
			printf("Continue to add a port number?(y/n)\n");
            scanf("%c", & cont);
			getchar();
            if (!(cont == 'Y' || cont == 'y')) {
                break;
            }
            printf("Please enter one port number you want to add into white list:\n");
            printf("Please follow this format and end with enter:\n");
            printf("XXXX\n");
            scanf("%d", & port);
			getchar();
            fprintf(config, ",%d", port);
        }

    }
}
