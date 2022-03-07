#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int is_prime_naive(long p){
	for(int i=3;i<p;i+=2){
		if(p%i==0){
			return 0;
		}
	}
	return 1;
}

long mod_pow_naive(long a, long m, long n){
	long mod=1;
	for(int i=0;i<m;i++){
		mod*=a;
		mod=mod%n;
	}
	return mod;
}

long mod_pow(long a, long m, long n) {
	long p;
	for (p = 1; m > 0; m = m / 2) {
		if (m % 2 != 0){
			p = (p * a) % n;
		}
	a = (a * a) % n;
	}
	return p;
}

int witness ( long a , long b , long d , long p ) {
	long x = mod_pow (a ,d , p ) ;
	if ( x == 1) {
		return 0;
	}
	for ( long i = 0; i < b ; i ++) {
		if ( x == p -1) {
			return 0;
		}
		x = mod_pow (x ,2 , p ) ;
	}
	return 1;
}

long rand_long ( long low , long up ) {
	return rand () % ( up - low +1) + low ;
}

int is_prime_miller ( long p , int k ) {
	if ( p == 2) {
		return 1;
	}
	if (!( p & 1) || p <= 1) { //on verifie que p est impair et different de 1
		return 0;
	}
	//on determine b et d :
	long b = 0;
	long d = p - 1;
	while (!( d & 1) ) { //tant que d n’est pas impair
		d = d /2;
		b = b +1;
	}
	// On genere k valeurs pour a, et on teste si c’est un temoin :
	long a ;
	int i ;
	for ( i = 0; i < k ; i ++) {
		a = rand_long (2 , p -1) ;
		if ( witness (a ,b ,d , p ) ) {
			return 0;
		}
	}
	return 1;
}

long random_prime_number(int low_size, int up_size, int k){
	long min=1,max=1;
	long p;
	for(int i=0;i<low_size;i++){
		min*=2;
		max*=2;
	}
	max*=2;
	max-=1;
	do{
		p=rand_long(min,max);
	}
	while(is_prime_miller(p,k)==0);
	return p;
}

long extended_gcd ( long s , long t , long *u , long *v ) {
	if (s == 0) {
		*u = 0;
		*v = 1;
		return t;
	}
	long uPrim, vPrim;
	long gcd = extended_gcd (t%s, s, &uPrim, &vPrim);
	*u = vPrim-(t/s)*uPrim;;
	*v = uPrim;
	return gcd;
}

void generate_key_value(long p, long q, long *n, long *s, long *u){
	*n=p*q;
	long t=(p-1)*(q-1);
	long v;
	*s=rand_long(1,t);
	while(extended_gcd(*s,t,u,&v)!=1){
		*s=rand_long(1,t);
	}
}

long *encrypt(char *chaine, long s, long n){
	int taille=strlen(chaine);
	long *encrypt = (long *)(malloc((taille+1)*sizeof(long)));
	for(int i=0;i<taille+1;i++){
		encrypt[i]=mod_pow(chaine[i],s,n);
	}
	return encrypt;
}

char *decrypt(long *crypted, int size, long u, long n){
	char *decrypt = (char *)(malloc((size+1)*sizeof(char)));
	printf("taille: %d\n",size);
	for(int i=0;i<size;i++){
		/*printf("%ld et %ld\n",crypted[i],mod_pow(crypted[i],u,n));*/
		decrypt[i]=mod_pow(crypted[i],u,n);
	}
	decrypt[size]='\0';
	return decrypt;
}

void print_long_vector ( long * result , int size ) {
	printf ("Vector:[");
	for ( int i =0; i < size ; i ++) {
		printf ("%ld\t", result [ i ]);
	}
	printf ("]\n");
}

int main (){
	srand ( time ( NULL ) ) ;

	//Generation de cle :
	long p = random_prime_number (15 ,16 , 5000) ;
	long q = random_prime_number (15 ,16 , 5000) ;
	while ( p == q ) {
		q = random_prime_number (15 ,16 , 5000) ;
	}
	long n , s , u ;
	generate_key_value (p ,q ,& n ,& s ,& u ) ;
	//Pour avoir des cles positives :
	if (u <0) {
		long t = (p -1) *( q -1) ;
		u = u + t ; //on aura toujours s*u mod t = 1
	}

	//Afichage des cles en hexadecimal
	printf ("cle publique=(%ld, %ld)\n", s, n);
	printf ("cle privee=(%ld, %ld)\n", u, n);

	//Chiffrement:
	char mess [10] = "JHello.";
	int len = strlen ( mess ) ;
	long * crypted = encrypt ( mess , s , n ) ;

	printf ("Initial message:%s\n", mess);
	printf ("Encoded representation:\n");
	print_long_vector ( crypted , len ) ;

	//Dechiffrement
	char * decoded = decrypt ( crypted , len , u , n ) ;
	printf ("Decoded : %s \n" , decoded ) ;

	return 0;
}
