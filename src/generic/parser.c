/**
 * @file parser.c
 * @brief Parser function definition
 * 
 * This file contains the definition of the parser function.
 * 
 * @see parser
 */

#include "parser.h"
#include "helper.h"
#include "stdio.h"

/**
 * @brief Parser function
 * 
 * This function parses the arguments passed to the program.
 * 
 * @param argc Number of arguments
 * @param argv Array of arguments
 * @param args Arguments structure
 * @return int 0 on success, -1 on error, 1 on help
 * 
 * @see helper_function
 */
int parse_args(int argc, char **argv, struct arguments* args)
{
    int opt;
    while ((opt = getopt(argc, argv, "i:w:r:v::c:h")) != -1) {
        switch (opt) {
        case 'i':           // Interface
            snprintf(args->interface, 16, "%s", optarg);
            break;
        case 'w':           // Output file
            args->fileOutput = optarg;
            break;
        case 'r':           // Input file
            args->fileInput = optarg;
            break;
        case 'v':           // Verbose level
            if (optarg)
                args->verbose = atoi(optarg);
            else
                args->verbose = 1;
            break;
        case 'c':           // Number of packets to capture
            args->count = atoi(optarg);
            break;
        case 'h':           // Help
            helper_function();
            return 1;
        default:
            helper_function();
            return -1;
        }
    }

    if (optind < argc) {    // Filter
        args->filter = argv[optind];
    }

    return 0;
}