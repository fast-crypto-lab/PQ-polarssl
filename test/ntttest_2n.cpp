#include <gmp.h>
#include <gmpxx.h>
#include <iostream>
#include <stdlib.h>
using namespace std;

#define NTTW_INVERSE 1
#define NTTW_FORWARD -1
#define n 2048


void ntt_norm(mpz_class* data,const size_t size, mpz_class invN , mpz_class q){

    for (int j = 0; j < size; j++)
        data[j] = (data[j] * invN)%q;
}


void rearrange(mpz_class* data, const size_t m) {
    size_t target = 0, position = 0, mask = m;
    mpz_class t;
    ///For all of input signal
    for (position = 0; position < m; ++position)
    {
        ///Ignore swapped entries
        if (target > position)
        {
            ///Swap
		t=data[target];	
		data[target]=data[position];
		data[position]=t;
        }

        ///Bit mask
        mask = m;
        ///While bit is set
        while (target & (mask >>= 1))
            ///Drop bit
            target &= ~mask;
        ///The current bit is 0 - set it
        target |= mask;
    }
}





void fntt(mpz_class *data, const size_t nn, const mpz_class pr, mpz_class q, const int isign)
{
    size_t m, i, j, istep, mmax;
    mpz_class w, wt, wr, wtemp;
    mpz_class t;
	
    if (isign > 0)
		t = q - 1 - (q - 1)/nn;
    else
		t= (q - 1)/nn;

	mpz_powm (w.get_mpz_t(), pr.get_mpz_t(), t.get_mpz_t() ,  q.get_mpz_t());

    rearrange(data, nn);

    mmax = 1;
    while (nn > mmax)
    {
		istep = mmax << 1;
		t= nn/istep;
		mpz_powm (wt .get_mpz_t(), w.get_mpz_t(), t.get_mpz_t() ,  q.get_mpz_t());
		wr=wt;
		
        // Optimize first step when wr = 1
        for (i = 0; i < nn; i += istep)
        {
            j = i + mmax;
            wtemp = data[j];
            data[j] = (data[i]-wtemp+q)%q;
            data[i] = (data[i]+wtemp)%q;
        }

        for (m = 1; m < mmax; m++)
        {
            for (i = m; i < nn; i += istep)
            {
                j = i + mmax;
                wtemp = (wr * data[j])%q;
                data[j] = (data[i] - wtemp+q)%q;
                data[i] = (data[i]+wtemp)%q;
            }
            wr = (wr *wt)%q;
        }
        mmax = istep;
    }
}








int main(){
	mpz_class beta =1781006.336;
	
	mpz_class q = 16*37*beta*beta*2048;
	mpz_nextprime (q.get_mpz_t(),q.get_mpz_t());

	while (q%(2*n)!=1)
		mpz_nextprime (q.get_mpz_t(),q.get_mpz_t());

	cout<<q<<endl;

	mpz_class w = 1;
	mpz_class t =1;
	mpz_class a;
	mpz_class qsize=q-1;
	mpz_class a0 =qsize/(2*n);

//find q-1th primitive root w

	//mpz_powm_ui (t.get_mpz_t(), t.get_mpz_t(), 4096,  q.get_mpz_t());

/*
	while(1){
		//w++;
		mpz_nextprime (w.get_mpz_t(),w.get_mpz_t());

		a=qsize/2;
		mpz_powm (t.get_mpz_t(), w.get_mpz_t(), a.get_mpz_t(),  q.get_mpz_t());
		if(t==1)
			continue;

		a= qsize/a1;
		mpz_powm (t.get_mpz_t(), w.get_mpz_t(), a.get_mpz_t(),  q.get_mpz_t());
		if(t==1)
			continue;

		mpz_powm (t.get_mpz_t(), w.get_mpz_t(), a0.get_mpz_t(),  q.get_mpz_t());
		break;

	}
*/
	
/*
	q=40961;
	t=3;
*/
	t=3;
	mpz_powm(w.get_mpz_t(), t.get_mpz_t(), a0.get_mpz_t(),  q.get_mpz_t());

	mpz_class data1[2*n];//2n
	mpz_class data2[2*n];//2n

	for(int i=0;i<2*n;i++)
		data1[i]=0;
	for(int i=0;i<n;i++)
		data1[i]=1;


/*
	srand(0);
	for(int i=0;i<n;i++)
		data1[i]=rand()%q;
*/

	for(int i=0;i<2*n;i++)
		data2[i]=data1[i];

//	data2[0]=1;

	fntt(data1, 2*n, t, q, NTTW_FORWARD);
	fntt(data2, 2*n, t, q, NTTW_FORWARD);

/*
for(int i=0;i<2*n;i++)
	cout<<(data1[i]+q)%q<<endl;
*/

for(int i=0;i<2*n;i+=1)
	data1[i]=(data1[i]*data2[i])%q;



	fntt(data1, 2*n,t, q, NTTW_INVERSE);

	mpz_class invN=2*n;
	mpz_invert(invN.get_mpz_t(),invN.get_mpz_t(),q.get_mpz_t());

	ntt_norm(data1, 2*n, invN,q );

for(int i=0;i<n;i+=1)
	data1[i]=data1[i]-data1[i+n];


	for(int i=0;i<10;i++)
		cout<<(data1[i]+q)%q<<endl;





	return 0;
}


