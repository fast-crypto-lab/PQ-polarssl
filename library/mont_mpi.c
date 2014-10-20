#include "lattice/mont_mpi.h"
#include "stdlib.h"
/*montgomery*/

mpi* Q;

void init_mont(){

	if(Q == NULL){
		//actually the same as ctx->q, but i think i should seperate them
		Q = malloc ( sizeof( mpi ));
		mpi_init(Q);
		mpi_read_string( Q, 10,  Q_STRING); 
	}

}

#define ciL    (sizeof(t_uint))         /* chars in limb  */
#define biL    (ciL << 3)               /* bits  in limb  */
#define biH    (ciL << 2)               /* half limb size */

static void mpi_get_right_Rbits(mpi *ROP, mpi *OP){

	int i;
#define LWE_NLIMB  ((RBIT+biL-1)/biL)

	mpi_grow( ROP, LWE_NLIMB);
	for(i =0; i< LWE_NLIMB; i++){
		ROP->p[i] = OP->p[i];
	}	
		
	t_uint mask = 1;
	mask = mask <<(RBIT % biL);
	mask = mask  - 1;
	ROP->p[LWE_NLIMB -1] &= mask ;


//	memset(ROP->p+ LWE_NLIMB, 0, (ROP->n-LWE_NLIMB)*ciL);

	for(i =LWE_NLIMB; i< ROP->n ; i++){
		ROP->p[i] = 0;
	}	

}


void mpi_mont_mul(mpi *ROP, mpi *X, mpi* Y){

	static mpi* np =NULL;
	static mpi* t = NULL;
	if(np == NULL){
		np= malloc (sizeof(mpi));
		t= malloc (sizeof(mpi));
		mpi_init(np);
		mpi_init(t);
		mpi_read_string( np , 10, NP_STRING); 
	}

	mpi_mul_mpi(t, X, Y);

	/*two ways to get right part of  a mpi in polarmpi: get the left half and sub them, or get and set bit by bit, trying the first one*/

	mpi_mul_mpi(ROP, t, np );
	mpi_get_right_Rbits(ROP, ROP);
	mpi_mul_mpi(ROP, ROP, Q );
	mpi_add_mpi(ROP, t, ROP);
	mpi_shift_r( ROP, RBIT);


	if(mpi_cmp_mpi(ROP, Q)>=0)
		mpi_sub_mpi(ROP, ROP,Q);

//	mpi_free(&t);
}

void mpi_mont_mulconst(mpi *ROP, mpi *X, int a){
	mpi_mul_int(ROP, X, a );
	while(mpi_cmp_mpi(ROP, Q)>=0){
		mpi_sub_mpi(ROP, ROP,Q);
	}
}


void mpi_mont_add(mpi *ROP, mpi *X, mpi* Y){
	mpi_add_mpi(ROP, X, Y);
	if(mpi_cmp_mpi(ROP, Q)>=0)
		mpi_sub_mpi(ROP, ROP,Q);

}


void mpi_mont_sub(mpi *ROP, mpi *X, mpi* Y){

	mpi_sub_mpi(ROP, X, Y);
	if(mpi_cmp_int(ROP, 0)<0)
		mpi_add_mpi(ROP, ROP,Q);

}

/*RR global var*/
void mpi_mont_trans( mpi *X ){
	static mpi* RR =NULL;
	if(RR== NULL){
		RR = malloc (sizeof(mpi));
		mpi_init(RR);
		mpi_read_string( RR, 10, RR_STRING); 
	}
	mpi_mont_mul(X, X, RR);
}

void mpi_mont_invtrans( mpi *X ){
	mpi t;
	mpi_init(&t);
	mpi_lset(&t, 1);
	mpi_mont_mul(X, X, &t);
}






