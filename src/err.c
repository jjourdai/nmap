#include "nmap.h"
#include "colors.h"

char	*error_str[] = {
	[THREAD_ZERO] = RED_TEXT("%s: '%d' thread is useless kill yourself\n"),
	[TOO_MANY_THREAD] = RED_TEXT("%s: '%d' too many thread -- speedup max == %d\n"),
	[THREAD_MIN_NOT_GREATER] = RED_TEXT("%s: port_min must be lesser than port_max or equal\n"),
	[INVALID_PORT_SYNTAX] = RED_TEXT("%s: --ports must be 'targeted_port' or 'port_min-port_max'\n"),
	[UNKNOWN_TYPE] = RED_TEXT("%s: '%s' is an unknown type\n"),
	[REQUIRED_ARG] = RED_TEXT("%s: '%s' option requires an argument --\n"),
	[INVALID_OPT] = RED_TEXT("%s: invalid option -- '%s'\n"),
	[INVALID_SHORT_OPT] = RED_TEXT("%s: invalid option -- '%c'\n"),
	[UNDEFINED_PARAMETER] = RED_TEXT("%s: Undefined parameters -- '%s'\n"),
	[NO_DEST_GIVEN] = RED_TEXT("%s: at least one destination must be given see --help\n"),
	[RANGE_MAX_EXCEEDED] = RED_TEXT("%s: '%d' Port range must be >= at '%d'\n"),
	[IP_AND_FILE_GIVEN] = RED_TEXT("%s: ip and file has been given...\n"),
	[NOT_IP_FOUND] = RED_TEXT("%s: getifaddr don't found our ip...\n"),
	[NOT_ONLY_DIGIT] = RED_TEXT("%s: source_port must be only digit -- %s\n"),
	[PORT_NOT_EXIST] = RED_TEXT("%s: source_port must be contains between 0 >= 65535 -- %s\n"),
	[UNKNOWN_HOST] = RED_TEXT("%s: Unknown host -- %s\n"),
	[FILE_IS_EMPTY] = RED_TEXT("%s: file is empty -- %s\n"),
};

void	handle_error(uint32_t line, char *file, t_bool fatal, enum error code, ...)
{
	va_list ap;

	va_start(ap, error_str[code]);
	vfprintf(stderr, error_str[code], ap);
	va_end(ap);
	if (DEBUG)
		fprintf(stderr, RED_TEXT("Line : %u, File %s\n"), line, file);
	if (fatal == TRUE)
		exit(EXIT_FAILURE);
}

int		x_int(int err, int res, char *str, char *file, int line)
{
	if (res == err)
	{
		fprintf(stderr, "%s error (%s, %d): %s\n",\
			str, file, line, strerror(errno));
		exit(EXIT_FAILURE);
	}
	return (res);
}

void	*x_roid(void *err, void *res, char *str, char *file, int line)
{
	if (res == err)
	{
		fprintf(stderr, "%s error (%s, %d): %s\n",
				str, file, line, strerror(errno));
		exit(EXIT_FAILURE);
	}
	return (res);
}
