#include <stdio.h>

FILE *white;
FILE *black;

void main(void)
{
  char mode;
  int ip1,ip2,ip3,ip4,port;
  ip1 = 0;
  ip2 = 0;
  ip3 = 0;
  ip4 = 0;
  port = 0;
  char cont;
  white = fopen("white.cfg","a+");
  black = fopen("black.cfg","a+");


      printf("Add input to black(B/b) list or white(W/w) list.");
      scanf("%c",&mode);
      if(mode == 'W' || mode == 'w')
	{
	  while(ip1>=0&&ip1<255&&ip2>=0&&ip2<255&&ip3>=0&&ip3<255&&ip4>=0&&ip4<255&&port>=0&&port<65535)
	    {
	      printf("Please enter the IP address and port number you want to add into white list:\n");
	      printf("Please follow this format: IP address,port number\n");
	      printf("XXXX.XXXX.XXXX.XXXX,XXXX\n");
	      scanf("%d.%d.%d.%d,%d",&ip1,&ip2,&ip3,&ip4,&port);
	      fprintf(white,"%d.%d.%d.%d,%d\n", ip1,ip2,ip3,ip4,port);
	      while ((getchar()) != '\n');
	      printf("Continue?(y/n)\n");
	      scanf("%c",&cont);
	      if(!(cont == 'Y'||cont == 'y'))
		{
		 break;
		}
	    }
	}
      else if(mode == 'B' || mode == 'b')
	{
	  while(ip1>=0&&ip1<255&&ip2>=0&&ip2<255&&ip3>=0&&ip3<255&&ip4>=0&&ip4<255&&port>=0&&port<65535)
	    {
	      printf("Please enter the IP address and port number you want to add into black list:\n");
	      printf("Please follow this format: IP address,port number\n");
	      printf("XXXX.XXXX.XXXX.XXXX,XXXX\n");
	      scanf("%d.%d.%d.%d,%d",&ip1,&ip2,&ip3,&ip4,&port);
	      fprintf(black,"%d.%d.%d.%d,%d\n", ip1,ip2,ip3,ip4,port);
	      while ((getchar()) != '\n');
	      printf("Continue?(y/n)\n");
	      scanf("%c",&cont);
	      if(!(cont == 'Y'||cont == 'y'))
		{
		 break;
		}
	    }
	}
      else
	{
	  printf("Wrong input.");
	}
}
