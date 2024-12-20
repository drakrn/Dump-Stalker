/**
 * @file helper.c
 * @brief Helper function definition
 * 
 * This file contains the definition of the helper function.
 * 
 * @see helper_function
 */

// General libraries
#include <stdio.h>

// Local header files
#include "helper.h"

/**
 * @brief Helper function
 * 
 * This function displays the usage of the program.
 * 
 * @return int 0
 */
int helper_function(void)
{
    printf("Usage: dumpstalker [ -i interface ] [ -o output ] [ -v verbose ] expression\n");
    return 0;
}