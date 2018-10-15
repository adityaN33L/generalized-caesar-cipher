#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <time.h>
#define MAX_SIZE 1024
#define ll long long 

char alphabets[]=" ABCDEFGHIJKLMNOPQRSTUVWXYZ,.?0123456789abcdefghijklmnopqrstuvwxyz!";

char* encryption(char *Plallext,ll key,ll n){
    ll i=0;
    char *cipherText=malloc(n*sizeof(char));
    while(i<n){
        char* t=strchr(alphabets,Plallext[i]);
        if(t!=NULL){
            ll index=(ll)(t-alphabets);
            cipherText[i]=alphabets[(index+key)%67];
        }
        else
            cipherText[i]=Plallext[i];
        i++;
    }
    return cipherText;
}

ll power(ll num,ll exp,ll p){
    ll result = 1;      
    num=num%p;  
    while (exp>0){
        if (exp%2==1)
            result=(result%p*num%p)%p;
        exp=exp>>1;
        num=(num%p*num%p)%p;
    }
    return result;
}

ll MillerRabin(ll d,ll n){
    ll a=2+rand()%(n-4),x=power(a,d,n);
    if (x==1 || x==n-1)
       return 1;
    while (d!=n-1){
        x=(x*x)%n;
        d*=2;
        if(x==1)
            return 0;
        if(x==n-1)    
            return 1;
    }
    return 0;
}


ll isPrime(ll n){
	ll d=n-1,i;
    if (n<=3) 
        return 1;
    if(n<=1 || n==4)  
        return 0;
    while(d%2 == 0)
        d/=2;
    for (i=0;i<10;++i)
        if(MillerRabin(d,n)==0)
            return 0;
    return 1;
}

ll rand_num_generator(){
    while(1){
        ll number=0;
        while(number<99999)
        	number= rand() % 900000 + 100000;
        if(isPrime(number))
            return number;
    }
}

ll primitive_root(ll num){
    ll f=num-1,i,j,check[num],res;
    bool flag=true;
    for(i=2;i<num;++i){
        for(j=0;j<num;++j)
            check[j]=0;
        flag=false;
        for(j=0;j<f;++j){
            res=power(i,j,num);
            if(check[res]!=0){
                flag=true;
                break;
            }
            check[res]=1;
        }
        if(!flag)
            return i;
    }
    return -1;
}

void deliver_message(ll fd,char *msg,ll len) {
    ll dataSent = 0,temp;
    while (dataSent < len){
        if ((temp=send(fd,msg+dataSent,len-dataSent,0)) <= 0) {
            perror("Error");
            exit(-1);
        }
        dataSent+=temp;
    }
}

int main(int argc, char **argv){
    ll sockfd = 0;
    char message[MAX_SIZE],server_reply[MAX_SIZE];
    srand(time(0));
    struct sockaddr_in serv_addr;

    if((sockfd = socket(AF_INET, SOCK_STREAM, 0))< 0){
        printf("\n Error : Could not create socket \n");
        return 1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(5000);
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]);

    if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))<0){
        printf("\n Error : Connect Failed \n");
        return 1;
    }
    printf("Connection established with the server...\n");
    ll q=rand_num_generator();                     //Randomly generated prime number
    ll alpha=primitive_root(q);                    //alpha: primitive root of q
    ll Xa=rand()%q;                                //Xa: client's private key
    ll Ya=power(alpha,Xa,q);                       //Ya: client's public key
    sprintf(message, "%lld", Ya);
    char q1[6],alpha1[6];
    sprintf(q1,"%lld",q);
    sprintf(alpha1,"%lld",alpha);
    strcat(message," ");strcat(message,q1);strcat(message," ");strcat(message,alpha1);strcat(message,"\0");
    send(sockfd,message,strlen(message),0);
    read(sockfd,server_reply,MAX_SIZE);
    ll Yb=atoi(server_reply);                      //Yb: server's public key
    ll Kab=power(Yb,Xa,q);                         //Kab: client's shared key   
    ll key=Kab%67;                                 //key: caesar-key for encryption
    printf("Client's secret key (Kab): %lld \nCaesar-key for encryption: %lld",Kab,key); 

    FILE *file;
    char plainChunks[MAX_SIZE];
    file=fopen(argv[2],"r");
    ll n;
    if(file!=NULL){
        while((n=fread(plainChunks,sizeof(char),MAX_SIZE,file))>0){
            char *cipherText=encryption(plainChunks,key,n);
            deliver_message(sockfd,cipherText,n);       
        }
    }
    fclose(file);
    close(sockfd);
    printf("\nEncrypted message sent to the server....");
    return 0;
}