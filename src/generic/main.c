/**
 * @author Flavien Lallemant
 * @file main.c
 * @brief Main function definition
 * 
 * This file contains the definition of the main function and the packet analyzer with some other useful function.
 * 
 * @see search_devs
 * @see dlt_format
 * @see packet_analyzer
 * @see main
 */

// General libraries
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Local header files
#include "ethernet.h"
#include "parser.h"
#include "types.h"

#define PCAP_SNAPLEN 65535 /**< Maximum number of bytes to capture per packet */


/**
 * @brief Search for devices and ask the user to choose one
 * 
 * This function searches for devices and asks the user to choose one.
 * 
 * @param errbuf The buffer to store the error message
 * @param alldevs The list of devices
 * @param dest The destination device
 * @param name The name of the device
 * 
 * @return 0 if the function succeeded, -1 otherwise
 */
int search_devs(char *errbuf, pcap_if_t **alldevs, pcap_if_t **dest, char *name)
{
    if (dest == NULL)
        printf("dest est null\n");
    if (pcap_findalldevs(alldevs, errbuf) == -1) {
        fprintf(stderr, "Couldn't find any devices: %s\n", errbuf);
        return (-1);
    }

    int i = 0;
    int valid_name = 0;
    for (pcap_if_t *dev = *alldevs; dev != NULL; dev = dev->next) {
        if (name[0] == '\0') {
            printf("%d.\t%s\n", i++, dev->name);
        } else if (strcmp(name, dev->name) == 0) {
            *dest = dev;
            valid_name = 1;
        }
    }

    if (name[0] == '\0' || valid_name == 0) {
        printf("Choose a valid interface (e.g.[eth0]): ");
        fflush(stdout);
        scanf("%s", name);
        fgetc(stdin);
        search_devs(errbuf, alldevs, dest, name);
    } else if (*dest == NULL) {
        fprintf(stderr, "No device found\n");
        return (-1);
    }
    return (0);
}


/**
 * @brief Format the DLT
 * 
 * This function formats the DLT.
 * 
 * @param dlt The DLT to format
 * 
 * @return The formatted DLT
 */
char *dlt_format(int dlt)
{
    char *res = malloc(8 * sizeof(char));
    if (res == NULL)
        return NULL;

    switch (dlt) {
    case DLT_NULL:
        sprintf(res, "NULL");
        break;
    case DLT_EN10MB:
        sprintf(res, "EN10MB");
        break;
    case DLT_EN3MB:
        sprintf(res, "EN3MB");
        break;
    case DLT_AX25:
        sprintf(res, "AX25");
        break;
    case DLT_PRONET:
        sprintf(res, "PRONET");
        break;
    case DLT_CHAOS:
        sprintf(res, "CHAOS");
        break;
    case DLT_IEEE802:
        sprintf(res, "IEEE802");
        break;
    case DLT_ARCNET:
        sprintf(res, "ARCNET");
        break;
    case DLT_SLIP:
        sprintf(res, "SLIP");
        break;
    case DLT_PPP:
        sprintf(res, "PPP");
        break;
    case DLT_FDDI:
        sprintf(res, "FDDI");
        break;
    }
    return res;
}


#define NB_COLORS 6
static long unsigned int compteur = 0;
static char *colors[NB_COLORS] = {"\033[1;31m", "\033[1;32m", "\033[1;33m", "\033[1;34m", "\033[1;35m", "\033[1;36m"};

/**
 * @brief Analyze a packet
 * 
 * This function analyzes a packet.
 * 
 * @param args The arguments
 * @param header The packet header
 * @param packet The packet
 * 
 * @see cast_ethernet
 */
void packet_analyzer(u_char *args, const struct pcap_pkthdr *header,
                     const u_char *packet)
{
    if (args) {
        ;
    }
    printf("%s", colors[++compteur % NB_COLORS]);

    printf("┌───────────────────────────────────────────────┐\n");
    printf("│\t\tPacket n°%ld\t\t\t│\n", compteur);
    printf("└───────────────────────────────────────────────┘\n");
    struct timeval tv = header->ts;
    time_t sec = tv.tv_sec;
    suseconds_t usec = tv.tv_usec;

    struct tm *timeinfo = localtime(&sec);
    if (timeinfo == NULL) {
        perror("localtime");
        return;
    }

    char time_str[64];
    if (strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeinfo) ==
        0) {
        fprintf(stderr, "strftime failed\n");
        return;
    }

    printf("%s.%06ld\n", time_str, (long)usec);
    cast_ethernet(packet);
    printf("\033[0m\n");
}


/**
 * @brief Main function
 * 
 * This function is the main function of the program.
 * It parses the arguments, opens the handle, sets the filter, and starts the loop.
 * 
 * @param argc The number of arguments
 * @param argv The arguments
 * 
 * @return 0 if the function succeeded, 1 otherwise
 * 
 * @see parse_args
 * @see search_devs
 * @see dlt_format
 * @see packet_analyzer
 */
int main(int argc, char **argv)
{
    struct arguments *args = calloc(1, sizeof(struct arguments));

    switch (parse_args(argc, argv, args)) {
    case -1:
        fprintf(stderr, "Error parsing arguments\n");
        free(args);
        return (1);
    case 1:
        free(args);
        return 0;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    pcap_dumper_t *dumper;
    if (args->fileInput) { // Open the file in offline mode
        handle = pcap_open_offline(args->fileInput, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Error opening input file: %s\n", errbuf);
            return (1);
        }
    } else { // First search for the device. Then open the device in live mode.
        if (args->interface[0] == '\0') { // If no interface is provided by user, ask for one
            pcap_if_t *alldevs = NULL;
            pcap_if_t *dev = NULL;
            if (search_devs(errbuf, &alldevs, &dev, args->interface) < 0) {
                fprintf(stderr, "Error searching devs\n");
                free(args);
                return (2);
            }
            // Free the list of devices
            pcap_freealldevs(alldevs);
            handle =
                pcap_open_live(args->interface, PCAP_SNAPLEN, 1, 1000, errbuf);
            if (handle == NULL) {
                fprintf(stderr, "Couldn't open device %s: %s\n",
                        args->interface, errbuf);
                free(args);
                return (2);
            }
        } else { // If an interface is provided by user, open it in live mode
            handle =
                pcap_open_live(args->interface, PCAP_SNAPLEN, 1, 1000, errbuf);
            if (handle == NULL) {
                fprintf(stderr, "Couldn't open device %s: %s\n",
                        args->interface, errbuf);
                free(args);
                return (2);
            }
        }
    }

    // Check if the device provides Ethernet headers
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr,
                "Device %s doesn't provide Ethernet headers - not supported\n",
                args->interface);
        free(args);
        return (2);
    }

    // Print the device information if one have been opened in live mode
    if (!args->fileInput) {
        char *dlt = dlt_format(pcap_datalink(handle));
        printf("Listening on %s, link-type %s, snapshot length %d bytes\n",
               args->interface, dlt, PCAP_SNAPLEN);
    }

    struct bpf_program filter;
    bpf_u_int32 subnet_mask, ip = 0;

    // Get the subnet mask and IP of the device if one have been opened in live mode
    if (!args->fileInput &&
        pcap_lookupnet(args->interface, &ip, &subnet_mask, errbuf)) {
        fprintf(stderr, "Could not get information for device: %s\n",
                args->interface);
        ip = 0;
        subnet_mask = 0;
    }

    // Compile the filter
    if (pcap_compile(handle, &filter, args->filter, 0, ip) == -1) {
        fprintf(stderr, "Bad filter - %s\n", pcap_geterr(handle));
        return (2);
    }

    // Set the filter
    if (pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr, "Error setting filter - %s\n", pcap_geterr(handle));
        return (2);
    }

    if (args->fileOutput) { // If an output file is provided, open it in write mode. Then start the loop
        dumper = pcap_dump_open(handle, args->fileOutput);
        if (dumper == NULL) {
            fprintf(stderr, "Error opening output file: %s\n",
                    pcap_geterr(handle));
            return (1);
        }
        pcap_loop(handle, args->count, pcap_dump, (u_char *)dumper);
        pcap_dump_close(dumper);
    } else { // If no output file is provided, start the loop
        pcap_loop(handle, args->count, packet_analyzer, NULL);
    }

    // Close the handle
    pcap_close(handle);

    // Free args
    free(args);

    return 0;
}
