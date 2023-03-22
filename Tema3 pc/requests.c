#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <stdio.h>
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"
#include "parson.h"

int sign_up(int sockfd, char* host, char *url, char *username, char *password){
    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));
    char *response = calloc(LINELEN, sizeof(char));

    //Add type/url/protocol
    sprintf(line, "POST %s HTTP/1.1", url);
    compute_message(message, line);

    //Add host
    memset(line, 0, LINELEN);
    sprintf(line, "Host: %s", host);
    compute_message(message, line);

    //Add content type
    memset(line, 0, LINELEN);
    sprintf(line, "Content-Type: application/json");
    compute_message(message, line);

    //Create a json containing username/password
    memset(line, 0, LINELEN);
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_string(root_object, "username", username);
    json_object_set_string(root_object, "password", password);
    char *data = json_serialize_to_string_pretty(root_value);

    //Add content length
    sprintf(line, "Content-Length: %ld", strlen(data));
    compute_message(message, line);

    //Add mandatory newspace
    compute_message(message, "");

    //Add the json
    strcat(message, data);
    json_free_serialized_string(data);
    free(line);
    json_value_free(root_value);

    //Send the message
    send_to_server(sockfd, message);
    //Receive the answer
    response = receive_from_server(sockfd);

    //Check the answer
    if(strncmp(response, "HTTP/1.1 201", 12) == 0){
        printf("Successfully signed up!\n");
        return 201;
    }else{
        if(strncmp(response, "HTTP/1.1 429", 12) == 0){
            printf("Too many requests! Try again later!\n");
            return 429;
        }else if(strstr(response, "\"error\":\"The username") != NULL){
            printf("The username %s is already taken!\n", username);
            return 400;
        }else{
            printf("An unexpected error has occurred. Please try again!\n");
            puts(response);
            return 420;
        }
    }
}

int login(int sockfd, char* host, char *url, char *username, char *password, char *token){
    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));
    char *response = calloc(LINELEN, sizeof(char));

    //Add type/url/protocol
    sprintf(line, "POST %s HTTP/1.1", url);
    compute_message(message, line);

    //Add host
    memset(line, 0, LINELEN);
    sprintf(line, "Host: %s", host);
    compute_message(message, line);

    //Add content type
    memset(line, 0, LINELEN);
    sprintf(line, "Content-Type: application/json");
    compute_message(message, line);

    //Create the json using username / password
    memset(line, 0, LINELEN);
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_string(root_object, "username", username);
    json_object_set_string(root_object, "password", password);
    char *data = json_serialize_to_string(root_value);

    //Add content length
    sprintf(line, "Content-Length: %ld", strlen(data));
    compute_message(message, line);

    //Add mandatory new line
    compute_message(message, "");

    //Add json
    strcat(message, data);
    json_free_serialized_string(data);
    free(line);
    json_value_free(root_value);

    //Send request
    send_to_server(sockfd, message);

    //Receive answer
    response = receive_from_server(sockfd);

    //Check response
    if(strncmp(response, "HTTP/1.1 200", 12) == 0){
        printf("Successfully logged in!\n");
        //Get login token
        char *get_token = strstr(response, "connect.sid=");
        memset(token, 0, LINELEN);
        char *token_string = strtok(get_token, ";");
        strcpy(token, token_string);
        return 200;
    }else{
        if(strncmp(response, "HTTP/1.1 429", 12) == 0){
            printf("Too many requests! Try again later!\n");
            return 429;
        }else if(strstr(response, "\"error\":\"Credentials are not good!\"") != NULL){
            printf("Wrong password!\n");
            return 400;
        }else if (strstr(response, "\"error\":\"No account with this username!\"") != NULL){
            printf("Account with given username does not exist!\n");
            return 401;
        }else{
            printf("An unexpected error has occurred. Please try again!\n");
            puts(response);
            return 420;
        }
    }
} 

int getaccess(int sockfd, char* host, char *url, char *token, char *JWT){
    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));
    char *response = calloc(LINELEN, sizeof(char));

    //Add type/url/protocol
    sprintf(line, "GET %s HTTP/1.1", url);
    compute_message(message, line);

    //Add host
    memset(line, 0, LINELEN);
    sprintf(line, "Host: %s", host);
    compute_message(message, line);

    //Add cookie
    memset(line, 0, LINELEN);
    sprintf(line, "Cookie: %s", token);
    compute_message(message, line);

    //Add mandatory newline
    compute_message(message, "");

    //Send request
    send_to_server(sockfd, message);

    //Get response
    response = receive_from_server(sockfd);

    //Check response
    if(strncmp(response, "HTTP/1.1 200", 12) == 0){
        printf("Successfully accessed the library!\n");

        //Get access JWT
        char *JWT_line = strstr(response, "\"token\":\"");
        char *JWT_field = strstr(JWT_line, ":\"");
        char *JWT_data = strtok(JWT_field, ":\"");
        memset(JWT, 0, LINELEN);
        strcpy(JWT, JWT_data);
        return 200;
    }else{
        if(strncmp(response, "HTTP/1.1 429", 12) == 0){
            printf("Too many requests! Try again later!\n");
            return 429;
        }else if(strstr(response, "\"error\":\"You are not logged in!\"") != NULL){
            printf("You are not logged in!\n");
            return 400;
        }else{
            printf("An unexpected error has occurred. Please try again!\n");
            puts(response);
            return 420;
        }
    }
    return 0;
}

int view_info(int sockfd, char* host, char *url, char *JWT){
    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));
    char *response = calloc(LINELEN, sizeof(char));

    //Add type/url/protocol
    sprintf(line, "GET %s HTTP/1.1", url);

    compute_message(message, line);

    //Add host
    memset(line, 0, LINELEN);
    sprintf(line, "Host: %s", host);
    compute_message(message, line);

    //Add authorization JWT
    memset(line, 0, LINELEN);
    sprintf(line, "Authorization: Bearer %s", JWT);
    compute_message(message, line);

    //Add mandatory newline
    compute_message(message, "");

    //Send request
    send_to_server(sockfd, message);

    //Get response
    response = receive_from_server(sockfd);

    //Check response
    if(strncmp(response, "HTTP/1.1 200", 12) == 0){
        printf("The books are: \n");
        //Parse and print json
        char *data = strstr(response, "\r\n\r\n");
        char *json_only = strtok(data, "\r\n");
        JSON_Value *root_value = json_parse_string(json_only);
        char *pretty_text = json_serialize_to_string_pretty(root_value);
        puts(pretty_text);
        return 200;
    }else{
        if(strncmp(response, "HTTP/1.1 429", 12) == 0){
            printf("Too many requests! Try again later!\n");
            return 429;
        }else if(strstr(response, "\"error\":\"You are not logged in!\"") != NULL || strncmp(response, "HTTP/1.1 500", 12) == 0){
            printf("You do not have the access!\n");
            return 400;
        }else{
            printf("An unexpected error has occurred. Please try again!\n");
            puts(response);
            return 420;
        }
    }
    return 0;
}

int check_book(int sockfd, char* host, char *url, char *JWT){
    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));
    char *response = calloc(LINELEN, sizeof(char));

    //Add type/url/protocol
    sprintf(line, "GET %s HTTP/1.1", url);

    compute_message(message, line);

    //Add host
    memset(line, 0, LINELEN);
    sprintf(line, "Host: %s", host);
    compute_message(message, line);

    //Add authorization JWT
    memset(line, 0, LINELEN);
    sprintf(line, "Authorization: Bearer %s", JWT);
    compute_message(message, line);

    //Add mandatory newline
    compute_message(message, "");

    //Send request
    send_to_server(sockfd, message);

    //Get response
    response = receive_from_server(sockfd);

    //Check response
    if(strncmp(response, "HTTP/1.1 200", 12) == 0){
        printf("The book is: \n");
        //Parse and print json
        char *data = strstr(response, "\r\n\r\n");
        char *json_only = strtok(data, "\r\n");
        JSON_Value *root_value = json_parse_string(json_only);
        char *pretty_text = json_serialize_to_string_pretty(root_value);
        puts(pretty_text);
        json_free_serialized_string(pretty_text);
        return 200;
    }else{
        if(strncmp(response, "HTTP/1.1 429", 12) == 0){
            printf("Too many requests! Try again later!\n");
            return 429;
        }else if(strstr(response, "\"error\":\"No book was found!\"") != NULL || strncmp(response, "HTTP/1.1 404", 12) == 0){
            printf("Could not find the book!\n");
            return 400;
        }else{
            printf("An unexpected error has occurred. Please try again!\n");
            puts(response);
            return 420;
        }
    }
    
    return 0;
}

int add_book(int sockfd, char* host, char *url, char *json, char *JWT){
    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));
    char *response = calloc(LINELEN, sizeof(char));

    //Add type/url/protocol
    sprintf(line, "POST %s HTTP/1.1", url);

    compute_message(message, line);

    //Add host
    memset(line, 0, LINELEN);
    sprintf(line, "Host: %s", host);
    compute_message(message, line);

    //Add authorization JWT
    memset(line, 0, LINELEN);
    sprintf(line, "Authorization: Bearer %s", JWT);
    compute_message(message, line);

    //Add content type
    memset(line, 0, LINELEN);
    sprintf(line, "Content-Type: application/json");
    compute_message(message, line);

    //Add content length
    sprintf(line, "Content-Length: %ld", strlen(json));
    compute_message(message, line);

    //Add mandatory newline
    compute_message(message, "");

    //Add json
    strcat(message, json);

    //Send request
    send_to_server(sockfd, message);

    //Get response
    response = receive_from_server(sockfd);

    //Check response
    if(strncmp(response, "HTTP/1.1 200", 12) == 0){
        printf("Book added successfully!\n");
        return 200;
    }else{
        if(strncmp(response, "HTTP/1.1 429", 12) == 0){
            printf("Too many requests! Try again later!\n");
            return 429;
        }else if(strstr(response, "\"error\":\"No book was found!\"") != NULL){
            printf("Could not find the book!\n");
            return 400;
        }else{
            printf("An unexpected error has occurred. Please try again!\n");
            puts(response);
            return 420;
        }
    }
    
    return 0;
}

int delete_book(int sockfd, char* host, char *url, char *JWT){
    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));
    char *response = calloc(LINELEN, sizeof(char));

    //Add type/url/protocol
    sprintf(line, "DELETE %s HTTP/1.1", url);

    compute_message(message, line);

    //Add host
    memset(line, 0, LINELEN);
    sprintf(line, "Host: %s", host);
    compute_message(message, line);

    //Add authorization JWT
    memset(line, 0, LINELEN);
    sprintf(line, "Authorization: Bearer %s", JWT);
    compute_message(message, line);

    //Add mandatory newline
    compute_message(message, "");

    //Send request
    send_to_server(sockfd, message);

    //Get response
    response = receive_from_server(sockfd);

    //Check response
    if(strncmp(response, "HTTP/1.1 200", 12) == 0){
        printf("Book deleted successfully!\n");
        return 200;
    }else{
        if(strncmp(response, "HTTP/1.1 429", 12) == 0){
            printf("Too many requests! Try again later!\n");
            return 429;
        }else if(strstr(response, "\"error\":\"No book was found!\"") != NULL || strncmp(response, "HTTP/1.1 404", 12) == 0){
            printf("Could not find the book!\n");
            return 400;
        }else{
            printf("An unexpected error has occurred. Please try again!\n");
            return 420;
        }
    }
    
    return 0;
}

int logout(int sockfd, char* host, char *url, char *token){
    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));
    char *response = calloc(LINELEN, sizeof(char));

    //Add type/url/protocol
    sprintf(line, "GET %s HTTP/1.1", url);

    compute_message(message, line);

    //Add host
    memset(line, 0, LINELEN);
    sprintf(line, "Host: %s", host);
    compute_message(message, line);

    //Add login token
    memset(line, 0, LINELEN);
    sprintf(line, "Cookie: %s", token);
    compute_message(message, line);

    //Add mandatory newline
    compute_message(message, "");

    //Send request
    send_to_server(sockfd, message);

    //Get response
    response = receive_from_server(sockfd);

    //Check response
    if(strncmp(response, "HTTP/1.1 200", 12) == 0){
        printf("Disconnected successfully!\n");
        return 200;
    }else{
        if(strncmp(response, "HTTP/1.1 429", 12) == 0){
            printf("Too many requests! Try again later!\n");
            return 429;
        }else if(strstr(response, "\"error\":\"") != NULL){
            printf("User not logged in!\n");
            return 400;
        }else{
            printf("An unexpected error has occurred. Please try again!\n");
            puts(response);
            return 420;
        }
    }
    
    return 0;
}
