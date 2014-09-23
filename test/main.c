#include "LWE.h"
#include "poly.h"
#define BufferLen 2560000

#include <sys/time.h>
double get_ms_time(void) {
	struct timeval timev;

	gettimeofday(&timev, NULL);
	return (double) timev.tv_sec * 1000 + (double) timev.tv_usec / 1000;
}



int main(){

double time1 = get_ms_time();
	int i;
	void* ctxser = lwe_alloc();
	void* ctxcli = lwe_alloc();
	size_t olen =0;
	size_t rlen =0;
	char*  buffer = malloc(BufferLen);
	char*  buffer2 = malloc(BufferLen);


	lwe_write_ske(&olen, buffer, BufferLen  ,ctxser );
	lwe_read_ske( ctxcli , &rlen, buffer, BufferLen   );


//	printf("%d %d\n", olen, rlen);

	olen= rlen =0;
	
	lwe_write_response( &olen, buffer, BufferLen  , ctxcli  );
	lwe_read_response( ctxser , buffer, BufferLen   );

//	printf("%d \n", olen);
	olen= rlen =0;

/*
	for(i=0; i<2048; i++){
		mpi_write_file( NULL, (((lwe_context*)ctxcli ) ->y->a[i]) , 10, NULL );
	}
*/


/*
	for(i=0; i<2048; i++){
		printf("%d ", (((lwe_context*)ctxser ) ->w->a[i]) );
	}
*/

	lwe_write_premaster( &olen, buffer, BufferLen   , ctxser );
	lwe_write_premaster( &rlen, buffer2, BufferLen   , ctxcli  );
	
//	printf("%d %d\n", olen, rlen);
	
double time2 = get_ms_time();
//		mpi_write_file(NULL, a->a[i], 10, NULL);



	if(olen!=rlen)
		printf("wtf!!!!!!!!!!!!!!\n");

	for(i=0; i<olen; i++)
		if(buffer[i]!=buffer2[i])
			printf("%d wtf!!!!!!!!!!!!!!\n", i);

	printf("%f ms\n", time2- time1);
	
	return 0;
}