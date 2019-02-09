#include "nmap.h"
#include "colors.h"

char	*error_str[] = {
	[THREAD_ZERO] = RED_TEXT("%s: '%d' thread is useless kill yourself\n"),
	[TOO_MANY_THREAD] = RED_TEXT("%s: '%d' too many thread -- speedup max == %d\n"),
	[THREAD_MIN_NOT_GREATER] = RED_TEXT("%s: port_min must be lesser than port_max or equal\n"),
	[INVALID_PORT_SYNTAX] = RED_TEXT("%s: --ports must be 'targeted_port' or 'port_min-port_max'\n"),
	[UNKNOWN_TYPE] = RED_TEXT("%s: '%s' is an unknown type\n"),
	[REQUIRED_ARG] = RED_TEXT("%s: option requires an argument -- '%c'\n"),
	[INVALID_OPT] = RED_TEXT("%s: invalid option -- '%c'\n"),
};

void	handle_error(uint32_t line, char *file, t_bool fatal, uint32_t error_code, ...)
{
	va_list ap;

	va_start(ap, error_str[error_code]);
	vfprintf(stderr, error_str[error_code], ap);
	va_end(ap);
	if (DEBUG)
		fprintf(stderr, RED_TEXT("Line : %u, File %s\n"), line, file);
	if (fatal == TRUE)
		exit(EXIT_FAILURE);
}


