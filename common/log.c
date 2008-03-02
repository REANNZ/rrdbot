
#include "log.h"

#include <errno.h>
#include <syslog.h>

void
log_error (const char *msg, ...)
{
	va_list va;
	va_start (va, msg);
	log_vmessage (LOG_ERR, errno, msg, va);
	va_end (va);
}

void
log_errorx (const char *msg, ...)
{
	va_list va;
	va_start (va, msg);
	log_vmessage (LOG_ERR, 0, msg, va);
	va_end (va);
}

void
log_warn (const char *msg, ...)
{
	va_list va;
	va_start (va, msg);
	log_vmessage (LOG_WARNING, errno, msg, va);
	va_end (va);
}

void
log_warnx (const char *msg, ...)
{
	va_list va;
	va_start (va, msg);
	log_vmessage (LOG_WARNING, 0, msg, va);
	va_end (va);
}

void
log_debug (const char *msg, ...)
{
	va_list va;
	va_start (va, msg);
	log_vmessage (LOG_DEBUG, 0, msg, va);
	va_end (va);
}

void
log_info (const char *msg, ...)
{
	va_list va;
	va_start (va, msg);
	log_vmessage (LOG_INFO, 0, msg, va);
	va_end (va);
}
