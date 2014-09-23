#include <gmp.h>
#include <gmpxx.h>
#include <iostream>
using namespace std;


int main(){
	mpz_class beta =1781006.336;
	
	mpz_class q = 16*37*beta*beta*2048;
	mpz_nextprime (q.get_mpz_t(),q.get_mpz_t());

	while (q%4096!=1)
		mpz_nextprime (q.get_mpz_t(),q.get_mpz_t());


	cout<<mpz_sizeinbase(q.get_mpz_t(), 2 )<<endl;
	cout<<q<<endl;
	
	

	
	
	







	return 0;
}


