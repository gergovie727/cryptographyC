#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "main.h"

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
	}
	max=min;
	for(int i=low_size-1;i<up_size;i++){
		max*=2;
	}
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

void init_key(Key* key, long val, long n){
	key->val=val;
	key->n=n;
}

void init_pair_keys(Key* pKey, Key* sKey, long lowsize, long upsize){
	long p = random_prime_number (lowsize ,upsize , 5000) ;
	long q = random_prime_number (lowsize ,upsize , 5000) ;
	while ( p == q ) {
		q = random_prime_number (lowsize ,upsize , 5000) ;
	}
	long n , s , u ;
	generate_key_value (p ,q ,& n ,& s ,& u ) ;
	//Pour avoir des cles positives :
	if (u <0) {
		long t = (p -1) *( q -1) ;
		u = u + t ; //on aura toujours s*u mod t = 1
	}
	init_key(pKey,s,n);
	init_key(sKey,u,n);
}

char* key_to_str(Key* key){
	char *c1=malloc(20*sizeof(char));
	char *c2=malloc(20*sizeof(char));
	sprintf(c1,"(%lx,",key->val);
	sprintf(c2,"%lx)",key->n);
	
	int taille = strlen(c1);
	taille = strlen(c2);
	
	char *chaine = (char *)(malloc((taille+1)*sizeof(char)));
	strcat(chaine,c1);
	strcat(chaine,c2);
	
	free(c1);
	free(c2);
	
	return chaine;
}

Key* str_to_key(char *str){
	long val,n;
	sscanf(str,"(%lx,%lx)",&val,&n);
	Key *clef = (Key *)(malloc(sizeof(Key)));
	init_key(clef,val,n);
	return clef;
}

Signature* init_signature(long* content, int size){
	Signature *sign = (Signature *)(malloc(sizeof(Signature)));
	sign->taille=size;
	sign->tab=(long *)(malloc(size*sizeof(long)));
	for(int i=0;i<size;i++){
		sign->tab[i]=content[i];
	}
	return sign;
}

Signature* sign(char* mess, Key* sKey){
	int taille = strlen(mess);
	long *tab=encrypt(mess,sKey->val,sKey->n);
	Signature *sign=init_signature(tab,taille);
	return sign;
}

char * signature_to_str ( Signature * sgn ) {
	char * result = malloc (10*sgn->taille*sizeof(char));
	result [0]= '#' ;
	int pos = 1;
	char buffer [156];
	for ( int i =0; i < sgn->taille; i ++) {
		sprintf ( buffer , "%lx" , sgn->tab[i]) ;
		for ( int j =0; j < strlen ( buffer ) ; j ++) {
			result [ pos ] = buffer [ j ];
			pos = pos +1;
		}
		result [ pos ] = '#' ;
		pos = pos +1;
	}
	result [ pos ] = '\0' ;
	result = realloc ( result , ( pos +1) * sizeof ( char ) ) ;
	return result ;
}

Signature * str_to_signature ( char * str ) {
	int len = strlen ( str ) ;
	long *content = (long *)malloc(sizeof(long)*len ) ;
	int num = 0;
	char buffer [256];
	int pos = 0;
	for ( int i =0; i < len ; i ++) {
		if ( str [ i ] != '#' ) {
			buffer [ pos ] = str [ i ];
			pos = pos +1;
		} 
		else {
			if ( pos != 0) {
				buffer [ pos ] = '\0' ;
				sscanf ( buffer , "%lx" , &( content [ num ]) ) ;
				num = num + 1;
				pos = 0;
			}
		}
	}
	content = realloc ( content , num * sizeof ( long ) ) ;
	return init_signature ( content , num ) ;
}

Protected *init_protected(Key *pKey, char *mess, Signature *sgn){
	Protected *protec = (Protected *)(malloc(sizeof(Protected)));
	protec->clef_publique=pKey;
	protec->signature=sgn;
	protec->message=strdup(mess);
	return protec;
}

int verify(Protected* pr){
	char *messdec=decrypt(pr->signature->tab,strlen(pr->message),pr->clef_publique->val,pr->clef_publique->n);
	if(strcmp(messdec,pr->message)==0){
		return 1;
	}
	return 0;
}

char *protected_to_str(Protected* pr){
	char *c1=key_to_str(pr->clef_publique);
	char *c2=signature_to_str(pr->signature);
	int taille=strlen(c1);
	taille+=strlen(c2);
	taille+=strlen(pr->message);
	char *chaine = (char *)(malloc((taille+3)*sizeof(char)));
	strcat(chaine,c1);
	strcat(chaine," ");
	strcat(chaine,pr->message);
	strcat(chaine," ");
	strcat(chaine,c2);
	return chaine;
}

Protected *str_to_protected(char *chaine){
	int i=0;
	while(chaine[i]!=' '){
		i++;
	}
	char c1[i+1];
	for(int k=0;k<i;k++){
		c1[k]=chaine[k];
	}
	c1[i]='\0';
	
	int j=i+1;
	while(chaine[j]!=' '){
		j++;
	}
	char c2[j-i+1];
	for(int k=i+1;k<j;k++){
		c2[k]=chaine[k];
	}
	c2[j-i]='\0';
	
	i=j+1;
	while(chaine[i]!='\0'){
		i++;
	}
	char c3[i-j+1];
	for(int k=j+1;k<i;k++){
		c3[k]=chaine[3];
	}
	c3[i-j]='\0';
	
	Protected *pr = (Protected *)(malloc(sizeof(Protected)));
	pr->clef_publique=str_to_key(c1);
	pr->message=strdup(c2);
	pr->signature=str_to_signature(c3);
	return pr;
}

int main ( void ) {
	srand ( time ( NULL ) ) ;
	//Testing Init Keys
	Key * pKey = malloc ( sizeof ( Key ) ) ;
	Key * sKey = malloc ( sizeof ( Key ) ) ;
	init_pair_keys ( pKey , sKey ,3 ,7) ;
	printf ("pKey: %lx, %lx\n", pKey->val, pKey->n);
	printf ("sKey: %lx, %lx\n", sKey->val, sKey->n);
	//Testing Key Serialization
	char * chaine = key_to_str ( pKey ) ;
	printf ("key to str:%s\n", chaine);
	Key * k = str_to_key ( chaine ) ;
	printf ("str to key: %lx, %lx\n",k->val, k->n) ;

	//Testing signature
	//Candidate keys:
	Key * pKeyC = malloc ( sizeof ( Key ) ) ;
	Key * sKeyC = malloc ( sizeof ( Key ) ) ;
	init_pair_keys ( pKeyC , sKeyC ,3 ,7) ;
	//Declaration:
	char * mess = key_to_str ( pKeyC ) ;
	printf ("%s votepour %s\n" , key_to_str ( pKey ) , mess ) ;
	Signature *sgn = sign ( mess , sKey ) ;
	printf ("signature:") ;
	print_long_vector ( sgn->tab, sgn->taille) ;
	chaine = signature_to_str ( sgn ) ;
	printf ("signature to str:%s \n" , chaine ) ;
	sgn = str_to_signature ( chaine ) ;
	printf ("str to signature:") ;
	print_long_vector (sgn->tab, sgn->taille) ;
	//Testing protected:
	Protected * pr = init_protected ( pKey , mess , sgn ) ;
	//Verification:
	if (verify(pr)) {
		printf ("Signature valide\n");
	} 
	else {
		printf ("Signature non valide\n");
	}
	chaine = protected_to_str ( pr ) ;
	printf ("protected to str:%s\n",chaine);
	pr = str_to_protected ( chaine ) ;
	printf ( "str to protected: %s %s %s \n" , key_to_str(pr->clef_publique), pr->message ,signature_to_str (pr->signature));
	free ( pKey ) ;
	free ( sKey ) ;
	free ( pKeyC ) ;
	free ( sKeyC ) ;
	return 0;
}
