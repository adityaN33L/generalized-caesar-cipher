#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
# define MAX_SIZE 1024
#define ll long long

char *alphabets=" ABCDEFGHIJKLMNOPQRSTUVWXYZ,.?0123456789abcdefghijklmnopqrstuvwxyz!";
 
char *decryption(char *cipherText,ll key,ll n){
    ll i=0,index;
    char *Plallext=malloc(n*sizeof(char));
    while(i<n){
        char* t=strchr(alphabets,cipherText[i]);
        if(t!=NULL){
        	index=(ll)(t-alphabets);
	        index=(index-key)%67;
	        if(index<0){
	            index=-index;
	            index=(66*index)%67;
	        }
	        Plallext[i]=alphabets[index];
        }
        else
        	Plallext[i]=cipherText[i];
        i++;
    }
    return Plallext;
}

ll power(ll num,unsigned ll exp,ll p){
    ll result = 1;      
    num=num%p;  
    while (exp>0){
        if (exp&1)
            result=(result%p*num%p)%p;
        exp=exp>>1;
        num=(num%p*num%p)%p;
    }
    return result;
}


ll get_message(ll sockfd, char buffer[MAX_SIZE], ll recv_size) {
    ll dataRecv = 0,temp;
    while (dataRecv<recv_size) {
        if ((temp=recv(sockfd,buffer+dataRecv,MAX_SIZE-dataRecv,0))<=0) {
            if (temp == 0)
                break;
            perror("Error ");
            exit(-1);
        }
        dataRecv+=temp;
    }
    return dataRecv;
}

int main(int argc, char **argv){

    ll listenfd=0,connfd=0;
    struct sockaddr_in serv_addr;
    ll addrlen = sizeof(serv_addr);
    char recv_buff[1025],sendBuff[1025];  

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    printf("Socket established....\n");
      
    serv_addr.sin_family = AF_INET;    
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]); 
    serv_addr.sin_port = htons(5000);    

    bind(listenfd, (struct sockaddr*)&serv_addr,sizeof(serv_addr));

    if(listen(listenfd, 10) == -1){
        printf("Failed to listen\n");
        return -1;
    }     
    printf("Listening to clients...\n");
    if((connfd = accept(listenfd,(struct sockaddr *)&serv_addr,(socklen_t*)&addrlen)) <0){
        perror("Error in Accepting");
        exit(-1);
    }
    printf("Connection established with the client...\n");

    read(connfd,recv_buff,MAX_SIZE);
    char *token = strtok(recv_buff," ");
    ll YaQAlpha[3],i=0;      
    while(token!=NULL){
        YaQAlpha[i++]=atoi(token);
        token=strtok(NULL," ");
    }
    //YaQAlpha[0]: Ya from client
    //YaQAlpha[1]: q from client
    //YaQAlpha[2]: alpha from client
    ll Xb=rand()%YaQAlpha[1];                              //Xb: server's private key
    ll Yb=power(YaQAlpha[2],Xb,YaQAlpha[1]);               //Yb: server's public key
    ll Kba=power(YaQAlpha[0],Xb,YaQAlpha[1]);              //Kba: secret key by server
    sprintf(sendBuff, "%lld", Yb);
    strcat(sendBuff,"\0");
    send(connfd,sendBuff,strlen(sendBuff),0);
    ll key=Kba%67;                                         //key: caesar-key for decryption
    printf("\nServer's secret key (Kba): %lld \nCaesar-key for decryption: %lld\n",Kba,key);
    
    FILE *fp=NULL;
    char cryptChunks[MAX_SIZE];
    ll bytesRead;
    fp = fopen("output.txt","w");

    while ((bytesRead = get_message(connfd,cryptChunks,MAX_SIZE))>0) {
        char *plallext=decryption(cryptChunks,key,bytesRead);
        fwrite(plallext,sizeof(char), bytesRead,fp);
    }
    printf("Encrypted message recieved from the client...\n");
    fclose(fp);
    close(connfd);
    printf("Message decrypted and written out to the file...");
    return 0;
}