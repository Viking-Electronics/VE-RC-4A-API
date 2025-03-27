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

#include <stdio.h>
#include <string.h>
#include "network_relay.h"

int main(int argc, char **argv)
{
    network_relay_t *devices = NULL;
    network_relay_t *ptr = NULL;

    // Create a command to send to the relay, this will activate relay 1 for 5 seconds
    network_relay_command_args_t command = {.command=RELAY_TIMED, .index=1, .duration_s=5 };

    // Discover devices on the network for 500 ms
    devices = network_relay_discovery(500, NULL); //devices must be freed when done to avoid memory leak
    
    ptr = devices; // Save the head of the list
    int i = 0;

    if (NULL == ptr)
    {
        printf("No devices detected on network\n");
        return -1;
    }

    printf("Devices found on network\n\n");

    //iterate through the list of devices, sending a timed relay command to each
    while (NULL != ptr)
    {
        printf("device[%d]\n%s\n%s\n%s\n\n", i++, ptr->name, ptr->ip_addr, ptr->mac_addr);

        // Set the password for the device (default is viking)
        ptr->password = strdup("viking");

        // Send a command to the device
        int error = network_relay_command(devices, command);

        if (E_NR_SUCCESS == error)
        {
            printf("Command sent successfully to %s at %s\n", ptr->name, ptr->ip_addr);
        }
        else
        {
            printf("Error %d sending command to %s at %s\n", error, ptr->name, ptr->ip_addr);
        }
        
        // Move to the next device in the list
        ptr = ptr->next;
    }

    network_relays_destroy(devices); // Free the memory allocated for the devices

    return 0;
}
