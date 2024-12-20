/**
 * @author Flavien Lallemant
 * @file ftp.c
 * @brief FTP Protocol Header File
 * 
 * This file contains the definition of the FTP layer.
 * It provides functions to check if a packet is an FTP packet.
 * 
 * @see ftp.h
 * @see is_ftp
 */

#include "ftp.h"
#include <stdlib.h>
#include <string.h>

const char *ftp_command[] = {
    "ABOR", "ACCT", "ADAT", "ALLO", "APPE", "AUTH", "AVBL", "CCC",  "CDUP",
    "CONF", "CSID", "CWD",  "DELE", "DSIZ", "ENC",  "EPRT", "EPSV", "FEAT",
    "HELP", "HOST", "LANG", "LIST", "LPRT", "LPSV", "MDTM", "MFCT", "MFF",
    "MFMT", "MIC",  "MKD",  "MLSD", "MLST", "MODE", "NLST", "NOOP", "OPTS",
    "PASS", "PASV", "PBSZ", "PORT", "PROT", "PWD",  "QUIT", "REIN", "REST",
    "RETR", "RMD",  "RMDA", "RNFR", "RNTO", "SITE", "SIZE", "SMNT", "SPSV",
    "STAT", "STOR", "STOU", "STRU", "SYST", "THMB", "TYPE", "USER", "XCUP",
    "XMKD", "XPWD", "XRCP", "XRMD", "XRSQ", "XSEM", "XSEN"}; /**< List of FTP commands */


/**
 * @brief Check if the packet is an FTP command
 * 
 * @param packet The packet
 * @return int 1 if the packet is an FTP command, 0 otherwise
 */
static int is_command(const u_char *packet)
{
    for (int i = 0; i < 70; i++) {
        if (strncmp((char *)packet, ftp_command[i], strlen(ftp_command[i])) ==
            0) {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Check if the packet is an FTP return code
 * 
 * @param packet The packet
 * @return int 1 if the packet is an FTP return code, 0 otherwise
 * 
 * @note FTP return codes are in the form of 3 digits. The first two digits are between 1 and 5. The last digit is between 0 and 9.
 */
static int is_return_code(const u_char *packet)
{
    char buf[4];
    strncpy(buf, (char *)packet, 3);
    int code = atoi(buf);
    if ((code >= 100 && code <= 159) || (code >= 200 && code <= 259) ||
        (code >= 300 && code <= 359) || (code >= 400 && code <= 459) ||
        (code >= 500 && code <= 559)) {
        return 1;
    }
    return 0;
}


/**
 * @brief Check if the packet is an FTP packet
 * 
 * @param packet The packet
 * @return int 1 if the packet is an FTP packet, 0 otherwise
 */
int is_ftp(const u_char *packet)
{
    if (is_command(packet)) {
        return 1;
    } else if (is_return_code(packet)) {
        return 1;
    } else {
        return 0;
    }
}