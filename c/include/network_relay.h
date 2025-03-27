/*
Copyright 2025 Viking Electronics

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef __NETWORK_RELAY_DISCOVERY_H__
#define __NETWORK_RELAY_DISCOVERY_H__

typedef struct s_network_relay
{
    char *name;
    char *username;
    char *password;
    int *http_port;
    char *mac_addr;
    char *model;
    char *ip_addr;
    struct s_network_relay *next;
} network_relay_t;

typedef enum e_network_relay_commands
{
    RELAY_RESET,
    RELAY_SET,
    __RELAY_FLASH,
    RELAY_TIMED,
    RELAY_TOGGLE
} network_relay_commands_t;

typedef enum
{
    E_NR_SUCCESS,
    E_NR_INVALID_RELAY_DETAILS,
    E_NR_INVALID_LOGIN,
    E_NR_INVALID_IP,
    E_NR_INVALID_COMMAND,
    E_NR_DIGEST_GENERATION_FAILURE,
    E_NR_ENCODING_FAILURE,
    E_NR_AUTH_GENERATION_FAILURE,
    E_NR_NETWORK_FAILURE,
    E_NR_NETWORK_TIMEOUT,
    E_NR_NETWORK_OUT_OF_ORDER,
    E_NR_NOMEM
} network_relay_command_errors_t;

typedef struct 
{
    network_relay_commands_t command;
    int index;
    int duration_s;
} network_relay_command_args_t;

/**
 * @brief Send a command to an RC-4A and return the response
 * 
 * @param relay             relay to send a command to, must update the username/password if not default 
 * @param command           command to send to the relay, must set the command, index, and time (if timed closure)
 * @return error code       error code, 0 is success, non zero is failure
 */
network_relay_command_errors_t
network_relay_command(network_relay_t *relay, network_relay_command_args_t command);

/**
 * @brief Discover RC-4A's on the local network
 * 
 * @param discovery_timeout     Max time for RC-4A to respond (ms)
 * @param mac_addr              Mac address of device to search for (optional, null to return a linked list of devices)
 * @return list of RC-4A's that responded before the timeout. Null if none         
 */
network_relay_t *
network_relay_discovery(int discovery_timeout, char *mac_addr);

/**
 * @brief deallocate memory for network relay structure
 * 
 * @param relay                 pointer to network relay object
 */
void network_relay_destroy(network_relay_t *relay);

/**
 * @brief deallocate memory for network relays
 * 
 * @param relay                 pointer to network relay array
 */
int network_relays_destroy(network_relay_t *head);

#endif