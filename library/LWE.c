#include "lattice/LWE.h"
#include "polarssl/sha256.h"
#include "stdlib.h"

#define polarssl_malloc malloc
#define polarssl_free free

void lwe_init( lwe_context  *ctx) {
    ctx->n = 2048;
    ctx->alpha = 3.397;
    ctx->beta = 1781006.336;
    ctx->gamma = 161.371;

    ctx->q = polarssl_malloc ( sizeof( mpi ) );
    mpi_init(ctx->q );
    mpi_read_string( ctx->q, 10, "3845762179574480897" );

    ctx->a  =polarssl_malloc ( sizeof( Poly_q) );
    ZeroPoly(ctx ->a,ctx ->n,ctx ->q);

    #include "lattice/polynomial_a.h"

    Poly_q* e = polarssl_malloc ( sizeof( Poly_q) );
    ctx->pk = polarssl_malloc ( sizeof( Poly_q) );
    ctx->sk = polarssl_malloc ( sizeof( Poly_q) );
    ZeroPoly(ctx ->pk,ctx ->n,ctx ->q);
    RandomPoly(ctx->sk, ctx->n, ctx->q, ctx->alpha, NULL);
    RandomPoly(e,   ctx->n, ctx->q, ctx->alpha, NULL);
    polyMul(ctx->pk ,ctx->sk, ctx->a);
    polyMulConst( e, 2, e);
    polyAdd(ctx->pk , ctx->pk , e  );
}




void *  lwe_alloc ( void ) {
    lwe_context *ctx = polarssl_malloc( sizeof( lwe_context ) );

    if( NULL ==  ctx ) {
        return NULL;
    }

    lwe_init(ctx);

    return ctx;

}

void  lwe_free ( lwe_context * ctx ) {
    //free all the poly
    freePoly(ctx->sk);
    freePoly(ctx->pk);
    freePoly(ctx->his_pk);
    freePoly(ctx->a);
    freePoly(ctx->x);
    freePoly(ctx->r);
    freePoly(ctx->y);
    freePoly2(ctx->w);

    polarssl_free( ctx );
}

int lwe_gen_public( lwe_context *ctx, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{//server and client must compute different things, how to implement.

    return 0;
}


int lwe_compute_shared ( lwe_context  *ctx, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng ){
    //maybe some assignment;

    return 0;
}
int lwe_set_params ( lwe_context  *ctx, const void *params ){

    return 0;
}



int lwe_read_ske( lwe_context  *ctx, int *rlen, const unsigned char *buf, size_t blen ){
/*disabled debug
    if (blen < 2 || blen > 2*ctx -> n * mpi_size( ctx ->q) ) {
        return POLARSSL_ERR_DHM_BAD_INPUT_DATA;
    }
*/
    //alloc x, his_pk
    ctx ->x = polarssl_malloc ( sizeof( Poly_q) );
    ctx ->his_pk = polarssl_malloc ( sizeof( Poly_q) );
    ZeroPoly(ctx ->x,ctx ->n,ctx ->q);
    ZeroPoly(ctx ->his_pk ,ctx ->n,ctx ->q);

    //x
    *rlen += polyReadBuffer(ctx ->x, buf);
    //his_pk
    *rlen += polyReadBuffer(ctx ->his_pk, buf + *rlen);






}


int lwe_read_response( lwe_context  *ctx, const unsigned char *buf, size_t blen ){
    //receive

    //no need for rlen?
    //alloc y,w,his_pk
    ctx ->his_pk = polarssl_malloc ( sizeof( Poly_q) );
    ctx ->y = polarssl_malloc ( sizeof( Poly_q) );
    ctx ->w = polarssl_malloc ( sizeof( Poly_2) );
    ZeroPoly(ctx ->y,ctx->n,ctx->q);
    ZeroPoly_2(ctx ->w,ctx->n);
    ZeroPoly(ctx ->his_pk, ctx->n,ctx->q);

    int IntPerElement = ctx -> n * mpi_size( ctx ->q);

    //probably will go wrong, since mpi doesn't properly cleanup.

    int rlen;
    //y
    rlen += polyReadBuffer(ctx ->y, buf);
    //pk
    rlen += polyReadBuffer(ctx ->his_pk, buf + rlen);
    //w(poly_2)
    rlen += poly2ReadBuffer(ctx ->w, buf + rlen);



//cheat


    Poly_q* g = polarssl_malloc ( sizeof( Poly_q) );
    RandomPoly(g,ctx->n, ctx->q, ctx->beta, NULL);



    Poly_q* c = polarssl_malloc ( sizeof( Poly_q) );
    Poly_q* d = polarssl_malloc ( sizeof( Poly_q) );

    int hash[8];
    int bufferlength =PolySize(ctx ->x);//i,j is ignored
    char* buffer = polarssl_malloc(bufferlength );
    polyWriteBuffer(ctx ->x, buffer);
    sha256(buffer ,bufferlength  ,hash ,0);
    RandomPoly(c, ctx->n, ctx->q, ctx->gamma,   hash[0]);
//  RandomPoly(c, ctx->n, ctx->q, ctx->gamma,  hash[0]); for debugging, 4 places
    polarssl_free(buffer);

    bufferlength = PolySize(ctx ->x)+PolySize(ctx ->y);
    buffer = polarssl_malloc(bufferlength );
    polyWriteBuffer(ctx ->y, buffer);
    polyWriteBuffer(ctx ->x, buffer + PolySize(ctx ->y));
    sha256(buffer ,bufferlength  ,hash ,0);
    RandomPoly(d, ctx->n, ctx->q, ctx->gamma,  hash[0]);
    polarssl_free(buffer);


    polyMul(d, ctx ->his_pk, d );
    polyMul(c, ctx ->sk, c );
    polyAdd(d, d, ctx ->y);
    polyAdd(c, c, ctx ->r );

    polyMul(d,c,d);
    polyMulConst( g, 2, g);
    polyAdd(d, d, g );

    invFFT(d);
//  Cha(ctx ->w ,d);
    Mod_2(ctx ->w, d ,ctx ->w);

    freePoly(g);

}



size_t  lwe_getsize_ske( const lwe_context *ctx ){
    //return size of message sent
    //poly_q*2
    return  PolySize(ctx ->x)+PolySize(ctx ->pk);
}

int lwe_write_ske( size_t *olen, unsigned char *buf, size_t blen, lwe_context  *ctx ){

    //cheat

    ctx ->r = polarssl_malloc ( sizeof( Poly_q) );
    ctx ->x = polarssl_malloc ( sizeof( Poly_q) );
    Poly_q* f = polarssl_malloc ( sizeof( Poly_q) );
    RandomPoly(ctx ->r, ctx->n, ctx->q, ctx->beta, NULL);
    RandomPoly(f,           ctx->n, ctx->q, ctx->beta, NULL);
    ZeroPoly(ctx ->x,ctx->n,ctx->q);

    polyMul(ctx->x ,ctx->r, ctx->a);
    polyMulConst( f, 2, f);
    polyAdd(ctx->x , ctx->x , f  );



    //pack and send (x and pk)

/*
    if( ctx == NULL || blen < wdhm_getsize_params(ctx) )
        return( POLARSSL_ERR_DHM_BAD_INPUT_DATA );
*/


    int IntPerElement = ctx -> n * mpi_size( ctx ->q);
    //x
    *olen += polyWriteBuffer(ctx ->x, buf);
    //pk
    *olen += polyWriteBuffer(ctx ->pk , buf+*olen );

/*
    for(i=0; i<2048; i++){
        mpi_write_file( NULL, (ctx->pk->a[i]) , 10, NULL );
    }
*/

    freePoly(f);
    return 0;

}

size_t lwe_getsize_response( const lwe_context  *ctx ){
    //poly_q*2+poly_2
    return  PolySize(ctx ->x)+PolySize(ctx ->pk)+(ctx->n)*4;
}

int lwe_write_response( size_t *olen, unsigned char *buf, size_t blen, lwe_context  *ctx ){
    //cheat

    ctx ->r = polarssl_malloc ( sizeof( Poly_q) );
    ctx ->y = polarssl_malloc ( sizeof( Poly_q) );
    Poly_q* f = polarssl_malloc ( sizeof( Poly_q) );
    RandomPoly(ctx ->r, ctx->n, ctx->q, ctx->beta, NULL);
    RandomPoly(f,           ctx->n, ctx->q, ctx->beta, NULL);
    ZeroPoly(ctx ->y,ctx->n,ctx->q);

    polyMul(ctx->y ,ctx->r, ctx->a);
    polyMulConst( f, 2, f);
    polyAdd(ctx->y , ctx->y , f  );

    Poly_q* c = polarssl_malloc ( sizeof( Poly_q) );
    Poly_q* d = polarssl_malloc ( sizeof( Poly_q) );
    Poly_q* g = polarssl_malloc ( sizeof( Poly_q) );
    RandomPoly(g,    ctx->n, ctx->q, ctx->beta, NULL);





    int hash[8];

    int bufferlength =PolySize(ctx ->x);//i,j is ignored
    char* buffer = polarssl_malloc(bufferlength );
    polyWriteBuffer(ctx ->x, buffer);
    sha256(buffer ,bufferlength  ,hash ,0);
    RandomPoly(c, ctx->n, ctx->q, ctx->gamma,   hash[0]);
    polarssl_free(buffer);

    bufferlength = PolySize(ctx ->x)+PolySize(ctx ->y);
    buffer = polarssl_malloc(bufferlength );
    polyWriteBuffer(ctx ->y, buffer);
    polyWriteBuffer(ctx ->x, buffer + PolySize(ctx ->y) );
    sha256(buffer ,bufferlength,hash ,0);
    RandomPoly(d, ctx->n, ctx->q, ctx->gamma,  hash[0]);
    polarssl_free(buffer);


    polyMul(c, c, ctx->his_pk);
    polyMul(d, d, ctx->sk);
    polyAdd(c,c,ctx->x);



    polyAdd(d,d,ctx ->r);
    polyMul(c, d, c);




    polyMulConst(g, 2, g);



    polyAdd(g ,c, g);

    ctx ->w = polarssl_malloc ( sizeof( Poly_2) );
    ZeroPoly_2(ctx ->w,ctx->n);


    invFFT(g);



    Cha(ctx ->w ,g);




/*
    for(i=0; i<2048; i++){
        printf("%d ", ctx ->w->a[i]);
    }
*/




    //write y,w,pk

//  if( ctx == NULL || blen < wdhm_getsize_response(ctx) )
//      return( POLARSSL_ERR_DHM_BAD_INPUT_DATA );




    //probably will go wrong, since mpi doesn't properly cleanup.
    //x
    *olen += polyWriteBuffer(ctx ->y, buf);
    //pk
    *olen += polyWriteBuffer(ctx ->pk , buf+*olen );
    //w
    *olen += poly2WriteBuffer(ctx ->w , buf+*olen );

//compute the rest

    Mod_2(ctx ->w, g ,ctx ->w);


    freePoly(c);
    freePoly(d);
    freePoly(g);
    freePoly(f);


}

size_t lwe_getsize_premaster( const lwe_context  *ctx ){
    return ctx->n;
}

int lwe_write_premaster( size_t *olen, unsigned char *buf, size_t blen, const lwe_context  *ctx ){
/*
    if( ctx == NULL || blen < ctx->n )
        return( POLARSSL_ERR_DHM_BAD_INPUT_DATA );
*/
    //write w
    *olen += poly2WriteBuffer(ctx ->w , buf );
    return 0;
}


const dh_info2_t lwe_info = {
    POLARSSL_DH_LWE, //not yet added to dh_type_t
    "M_LWE",
    lwe_alloc,
    lwe_free,
    lwe_gen_public,
    lwe_compute_shared,
    lwe_set_params,
    lwe_read_ske,
    lwe_read_response,
    NULL,
    NULL,
    lwe_getsize_ske,
    lwe_write_ske,
    lwe_getsize_response,
    lwe_write_response,
    lwe_getsize_premaster,
    lwe_write_premaster,
};

