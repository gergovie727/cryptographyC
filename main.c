#include <stdio.h>
#include <stdlib.h>

#include "gagnant.h"
#include "protocole_rsa.h"
#include "primalite.h"
#include "keys.h"
#include "generate_data.h"
#include "rw_data.h"


void test_protocole_rsa () {
    srand(time(NULL));
    //Generation de cle :
    long p=random_prime_number(3, 7, 5000);
    long q=random_prime_number(3, 7, 5000);
    while(p==q) 
    {
        q=random_prime_number(3, 7, 5000);
    }
    long n, s, u;
    generate_keys_values(p,q,&n,&s,&u);
    //Pour avoir des cles positives :
    if (u<0)
    {
        long t=(p-1)*(q-1);
        u=u+t; //on aura toujours s*u mod t = 1
    }
    //Afichage des cles en hexadecimal
    printf("cle publique = (%lx , %lx ) \n",s,n);
    printf("cle privee = (%lx , %lx) \n",u,n);

    //Chiffrement:
    char mess[10] = "Hello";
    int len = strlen(mess);
    long* crypted = encrypt(mess, s, n); 

    printf ("Initial message : %s \n",mess);
    printf("Encoded representation : \n");
    print_long_vector(crypted, len);

    //Dechiffrement:

    char* decoded = decrypt(crypted,len, u, n);
    printf("Decoded : %s\n", decoded); 

	free(crypted);
	free(decoded);
}

void test_keys () {
    srand ( time ( NULL ) ) ;
	
    //Testing Init Keys
	Key *pKey=(Key *)(malloc(sizeof(Key)));
	Key *sKey=(Key *)(malloc(sizeof(Key)));
	init_pair_keys(pKey, sKey, 3, 7);
	printf("pKey: %lx, %lx\n", pKey->val, pKey->n);
	printf("sKey: %lx, %lx\n", sKey->val, sKey->n);
	
    //Testing Key Serialization
	char *chaine=key_to_str(pKey);
	printf("key to str:%s\n", chaine);
	Key *k=str_to_key(chaine);
	printf("str to key: %lx, %lx\n", k->val, k->n);
    free(k);

	//Testing signature

	//Candidate keys:
	Key *pKeyC=(Key *)malloc(sizeof(Key));
	Key *sKeyC=(Key *)malloc(sizeof(Key));
	init_pair_keys(pKeyC, sKeyC, 3, 7);
	
    //Declaration:
	char *mess=key_to_str(pKeyC);
	char *temp1=key_to_str(pKey);
	printf ("%s votepour %s\n" , temp1 , mess);
	free(temp1);
	Signature *sgn=sign(mess, sKey);
	printf("signature:");
	print_long_vector(sgn->tab, sgn->taille) ;
	free(chaine);
	chaine=signature_to_str(sgn);
	printf("signature to str:%s \n", chaine);
    free(sgn->tab);
	free(sgn);
	sgn=str_to_signature(chaine);
	printf("str to signature:");
	print_long_vector(sgn->tab, sgn->taille);
	
    //Testing protected:
	Protected *pr=init_protected(pKey, mess, sgn);
	
    //Verification:
	if(verify(pr)){
		printf("Signature valide\n");
	} 
	else{
		printf("Signature non valide\n");
	}
	free(chaine);
	chaine=protected_to_str(pr);
	printf("protected to str:%s\n",chaine);
    free(pr->message);
    free(pr->pKey);
    free(pr->signature->tab);
    free(pr->signature);
	free(pr);
	pr=str_to_protected(chaine);
	temp1=key_to_str(pr->pKey);
	char *temp2=signature_to_str(pr->signature);
	printf("str to protected: %s %s %s \n",temp1, pr->message, temp2);
	free(pKey);
	free(sKey);
	free(pKeyC);
	free(sKeyC);
	free(chaine);
	free(temp1);
	free(temp2);
	free(mess);
	free(sgn->tab);
	free(sgn);
    free(pr->message);
    free(pr->pKey);
    free(pr->signature->tab);
    free(pr->signature);
	free(pr);

}

void test_rw_data (void) {
    CellProtected *pro=read_protected();
	print_list_protec(pro);
	delete_list_protected(pro);

}

void test_winner(void){
	CellProtected *declarations=read_protected();
	char un[9]="keys.txt", deux[15]="candidates.txt";
	CellKey *votants=read_public_keys(un), *candidats=read_public_keys(deux);
	Key *clef_gagnant=compute_winner(declarations,candidats,votants,12,210);
	char *gagnant=key_to_str(clef_gagnant);
	fprintf(stderr,"et le gagnant est: %s\n",gagnant);
	delete_cell_protected(declarations);
	delete_cell_key(votants);
	delete_cell_key(candidats);
	free(clef_gagnant);
	free(gagnant);
}

int main(){
    /*test_protocole_rsa();
    test_keys();
    generate_random_data(200,10);*/
    //test_rw_data();
	test_winner();
    return 0;
}