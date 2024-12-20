/**
 * @author Flavien Lallemant
 * @file parser.h
 * @brief Parser function declaration
 * 
 * This file contains the declaration of the parser function.
 */

#ifndef PARSER_H
#define PARSER_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
// #include "lists.h"

/**
 * @brief Arguments structure
 * 
 * This structure contains the arguments passed to the program.
 */
struct arguments {
    char interface[16];
    char *fileInput;
    char *fileOutput;
    char *filter;
    int verbose;
    int count;
};

/**
 * @brief Parser function
 * 
 * This function parses the arguments passed to the program.
 * 
 * @param argc Number of arguments
 * @param argv Array of arguments
 * @param args Arguments structure
 * @return int 0 on success, -1 on error, 1 on help
 */
int parse_args(int argc, char **argv, struct arguments* args);

#endif // PARSER_H