#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"
#include "parson.h"

#define HOST "34.241.4.235"
#define PORT 8080

int main(int argc, char *argv[])
{
    int sockfd;
    char *cmd = (char*)calloc(LINELEN, sizeof(char));
    char *token = (char*)calloc(LINELEN,sizeof(char));
    char *username = (char*)calloc(LINELEN, sizeof(char)); 
    char *password = (char*)calloc(LINELEN, sizeof(char));
    char *JWT = (char*)calloc(LINELEN,sizeof(char));
    char *url = (char*)calloc(LINELEN,sizeof(char));
    char *title = (char*)calloc(LINELEN,sizeof(char));
    char *author = (char*)calloc(LINELEN,sizeof(char));
    char *genre = (char*)calloc(LINELEN,sizeof(char));
    char *publisher = (char*)calloc(LINELEN,sizeof(char));
    char *page_count = (char*)calloc(LINELEN,sizeof(char));

    while(1){
        scanf("%s", cmd);
        sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);
        if(strcmp(cmd, "register") == 0){
            printf("username=");
            scanf("%s", username);
            printf("password=");
            scanf("%s", password);
            sign_up(sockfd, HOST, "/api/v1/tema/auth/register", username, password);
        }else if(strcmp(cmd, "login") == 0){
            printf("username=");
            scanf("%s", username);
            printf("password=");
            scanf("%s", password);
            login(sockfd, HOST, "/api/v1/tema/auth/login", username, password, token);
        }else if(strcmp(cmd, "enter_library") == 0){
            if(strcmp(token, "") != 0){
                getaccess(sockfd, HOST, "/api/v1/tema/library/access", token, JWT);
            }else{
                printf("You are not logged in!\n");
            }
        }else if(strcmp(cmd, "get_books") == 0){
            if(strcmp(JWT, "") != 0){
                view_info(sockfd, HOST, "/api/v1/tema/library/books", JWT);
            }else{
                printf("You do not have the access!\n");
            }
        }else if(strcmp(cmd, "get_book") == 0){
            if(strcmp(JWT, "") != 0){
                int id;
                printf("id=");
                scanf("%d", &id);
                memset(url, 0, LINELEN);
                sprintf(url, "%s%d", "/api/v1/tema/library/books/", id);
                check_book(sockfd, HOST, url, JWT);
            }else{
                printf("You do not have the access!\n");
            }
        }else if(strcmp(cmd, "add_book") == 0){
            if(strcmp(JWT, "") != 0){
                printf("title=");
                scanf("%s", title);
                printf("author=");
                scanf("%s", author);
                printf("genre=");
                scanf("%s", genre);
                printf("publisher=");
                scanf("%s", publisher);
                printf("page_count=");
                scanf("%s", page_count);

                if(strtol(page_count, NULL, 10) == 0){
                    printf("Invalid format!\n");
                }else{
                    //Create json
                    JSON_Value *root_value = json_value_init_object();
                    JSON_Object *root_object = json_value_get_object(root_value);
                    json_object_set_string(root_object, "title", title);
                    json_object_set_string(root_object, "author", author);
                    json_object_set_string(root_object, "genre", genre);
                    json_object_set_number(root_object, "page_count", atol(page_count));
                    json_object_set_string(root_object, "publisher", publisher);
                    char *json2string = json_serialize_to_string(root_value);
                    add_book(sockfd, HOST, "/api/v1/tema/library/books", json2string, JWT);
                    json_free_serialized_string(json2string);
                }
            }else{
                printf("You do not have the access!\n");
            }
        }else if(strcmp(cmd, "delete_book") == 0){
            if(strcmp(JWT, "") != 0){
                int id;
                printf("id=");
                scanf("%d", &id);
                memset(url, 0, LINELEN);
                sprintf(url, "%s%d", "/api/v1/tema/library/books/", id);
                delete_book(sockfd, HOST, url, JWT);
            }else{
                printf("You do not have the access!\n");
            }
        }else if(strcmp(cmd, "logout") == 0){
            if(strcmp(token, "") != 0){
                logout(sockfd, HOST, "/api/v1/tema/auth/logout", token);
                free(token);
                free(JWT);
                token = (char*)calloc(LINELEN,sizeof(char));
                JWT = (char*)calloc(LINELEN,sizeof(char));
            }else{
                printf("You are not logged in!\n");
            }
        }else if(strcmp(cmd, "exit") == 0){
            free(cmd);
            free(token);
            free(username); 
            free(password);
            free(JWT);
            free(url);
            free(title);
            free(author);
            free(genre);
            free(publisher);
            free(page_count);
            break;
        }
    }
}
