#ifndef _REQUESTS_
#define _REQUESTS_

int sign_up(int sockfd, char* host, char *url, char *username, char *password);

int login(int sockfd, char* host, char *url, char *username, char *password, char *token);

int getaccess(int sockfd, char* host, char *url, char *token, char *JWT);

int view_info(int sockfd, char* host, char *url, char *JWT);

int check_book(int sockfd, char* host, char *url, char *JWT);

int add_book(int sockfd, char* host, char *url, char *json, char *JWT);

int delete_book(int sockfd, char* host, char *url, char *JWT);

int logout(int sockfd, char* host, char *url, char *token);

#endif
