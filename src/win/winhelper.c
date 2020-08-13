/*
 * Copyright (c) 2020 Elastos Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <ctype.h>
#include <locale.h>
#include <time.h>

#include "winhelper.h"
/*
 * We do not implement alternate representations. However, we always
 * check whether a given modifier is allowed for a certain conversion.
 */
#if defined(_WIN32) || defined(_WIN64)
#define ALT_E               0x01
#define ALT_O               0x02


#define S_YEAR              (1 << 0)
#define S_MON               (1 << 1)
#define S_YDAY              (1 << 2)
#define S_MDAY              (1 << 3)
#define S_WDAY              (1 << 4)
#define S_HOUR              (1 << 5)

#define HAVE_MDAY(s)        (s & S_MDAY)
#define HAVE_MON(s)         (s & S_MON)
#define HAVE_WDAY(s)        (s & S_WDAY)
#define HAVE_YDAY(s)        (s & S_YDAY)
#define HAVE_YEAR(s)        (s & S_YEAR)
#define HAVE_HOUR(s)        (s & S_HOUR)
#define TM_YEAR_BASE        1900

typedef unsigned char       u_char;
typedef unsigned int        u_int;

/*
 * Table to determine the ordinal date for the start of a month.
 * Ref: http://en.wikipedia.org/wiki/ISO_week_date
 */
static const int start_of_month[2][13] = {
    /* non-leap year */
    { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365 },
    /* leap year */
    { 0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366 }
};

/*
 * Calculate the week day of the first day of a year. Valid for
 * the Gregorian calendar, which began Sept 14, 1752 in the UK
 * and its colonies. Ref:
 * http://en.wikipedia.org/wiki/Determination_of_the_day_of_the_week
 */
#define LEGAL_ALT(x)        { if (alt_format & ~(x)) return NULL; }
#define delim(p) ((p) == '\0' || isspace((unsigned char)(p)))
#define isleap(y) (((y) % 4) == 0 && (((y) % 100) != 0 || ((y) % 400) == 0))
/*
** Since everything in isleap is modulo 400 (or a factor of 400), we know that
**  isleap(y) == isleap(y % 400)
** and so
**  isleap(a + b) == isleap((a + b) % 400)
** or
**  isleap(a + b) == isleap(a % 400 + b % 400)
** This is true even if % means modulo rather than Fortran remainder
** (which is allowed by C89 but not C99).
** We use this to avoid addition overflow problems.
*/
#define isleap_sum(a, b)    isleap((a) % 400 + (b) % 400)

static const u_char *conv_num(const unsigned char *, int *, u_int, u_int);
static const u_char *find_string(const u_char *, int *, const char * const *,
    const char * const *, int);

static int first_wday_of(int year)
{
    return ((2 * (3 - (year / 100) % 4)) + (year % 100) + ((year % 100) /  4) +
        (isleap(year) ? 6 : 0) + 1) % 7;
}

char *_strptime(const char *buf, const char *fmt, struct tm *tm)
{
    unsigned char c;
    const unsigned char *bp;
    int alt_format, i, split_year = 0, neg = 0, state = 0,
        day_offset = -1, week_offset = 0;

    bp = (const u_char *)buf;

    while (bp != NULL && (c = *fmt++) != '\0') {
        /* Clear `alternate' modifier prior to new conversion. */
        alt_format = 0;
        i = 0;

        /* Eat up white-space. */
        if (isspace(c)) {
            while (isspace(*bp))
                bp++;
            continue;
        }

        if (c != '%')
            goto literal;

again:      switch (c = *fmt++) {
        case '%':   /* "%%" is converted to "%". */
literal:
            if (c != *bp++)
                return NULL;
            LEGAL_ALT(0);
            continue;

        /*
         * "Alternative" modifiers. Just set the appropriate flag
         * and start over again.
         */
        case 'E':   /* "%E?" alternative conversion modifier. */
            LEGAL_ALT(0);
            alt_format |= ALT_E;
            goto again;

        case 'O':   /* "%O?" alternative conversion modifier. */
            LEGAL_ALT(0);
            alt_format |= ALT_O;
            goto again;

        case 'C':   /* The century number. */
            i = 20;
            bp = conv_num(bp, &i, 0, 99);

            i = i * 100 - TM_YEAR_BASE;
            if (split_year)
                i += tm->tm_year % 100;
            split_year = 1;
            tm->tm_year = i;
            LEGAL_ALT(ALT_E);
            state |= S_YEAR;
            continue;

        case 'd':   /* The day of month. */
        case 'e':
            bp = conv_num(bp, &tm->tm_mday, 1, 31);
            LEGAL_ALT(ALT_O);
            state |= S_MDAY;
            continue;

        case 'k':   /* The hour (24-hour clock representation). */
            LEGAL_ALT(0);
            /* FALLTHROUGH */
        case 'H':
            bp = conv_num(bp, &tm->tm_hour, 0, 23);
            LEGAL_ALT(ALT_O);
            state |= S_HOUR;
            continue;

        case 'l':   /* The hour (12-hour clock representation). */
            LEGAL_ALT(0);
            /* FALLTHROUGH */
        case 'I':
            bp = conv_num(bp, &tm->tm_hour, 1, 12);
            if (tm->tm_hour == 12)
                tm->tm_hour = 0;
            LEGAL_ALT(ALT_O);
            state |= S_HOUR;
            continue;

        case 'j':   /* The day of year. */
            i = 1;
            bp = conv_num(bp, &i, 1, 366);
            tm->tm_yday = i - 1;
            LEGAL_ALT(0);
            state |= S_YDAY;
            continue;

        case 'M':   /* The minute. */
            bp = conv_num(bp, &tm->tm_min, 0, 59);
            LEGAL_ALT(ALT_O);
            continue;

        case 'm':   /* The month. */
            i = 1;
            bp = conv_num(bp, &i, 1, 12);
            tm->tm_mon = i - 1;
            LEGAL_ALT(ALT_O);
            state |= S_MON;
            continue;

        case 'S':   /* The seconds. */
            bp = conv_num(bp, &tm->tm_sec, 0, 61);
            LEGAL_ALT(ALT_O);
            continue;

        case 'w':   /* The day of week, beginning on sunday. */
            bp = conv_num(bp, &tm->tm_wday, 0, 6);
            LEGAL_ALT(ALT_O);
            state |= S_WDAY;
            continue;

        case 'u':   /* The day of week, monday = 1. */
            bp = conv_num(bp, &i, 1, 7);
            tm->tm_wday = i % 7;
            LEGAL_ALT(ALT_O);
            state |= S_WDAY;
            continue;

        case 'g':   /* The year corresponding to the ISO week
                 * number but without the century.
                 */
            bp = conv_num(bp, &i, 0, 99);
            continue;

        case 'G':   /* The year corresponding to the ISO week
                 * number with century.
                 */
            do
                bp++;
            while (isdigit(*bp));
            continue;

        case 'V':   /* The ISO 8601:1988 week number as decimal */
            bp = conv_num(bp, &i, 0, 53);
            continue;

        case 'Y':   /* The year. */
            i = TM_YEAR_BASE;   /* just for data sanity... */
            bp = conv_num(bp, &i, 0, 9999);
            tm->tm_year = i - TM_YEAR_BASE;
            LEGAL_ALT(ALT_E);
            state |= S_YEAR;
            continue;

        case 'y':   /* The year within 100 years of the epoch. */
            /* LEGAL_ALT(ALT_E | ALT_O); */
            bp = conv_num(bp, &i, 0, 99);

            if (split_year)
                /* preserve century */
                i += (tm->tm_year / 100) * 100;
            else {
                split_year = 1;
                if (i <= 68)
                    i = i + 2000 - TM_YEAR_BASE;
                else
                    i = i + 1900 - TM_YEAR_BASE;
            }
            tm->tm_year = i;
            state |= S_YEAR;
            continue;

        /*
         * Miscellaneous conversions.
         */
        case 'n':   /* Any kind of white-space. */
        case 't':
            while (isspace(*bp))
                bp++;
            LEGAL_ALT(0);
            continue;

        default:    /* Unknown/unsupported conversion. */
            return NULL;
        }
    }

    if (!HAVE_YDAY(state) && HAVE_YEAR(state)) {
        if (HAVE_MON(state) && HAVE_MDAY(state)) {
            /* calculate day of year (ordinal date) */
            tm->tm_yday =  start_of_month[isleap_sum(tm->tm_year,
                TM_YEAR_BASE)][tm->tm_mon] + (tm->tm_mday - 1);
            state |= S_YDAY;
        } else if (day_offset != -1) {
            /*
             * Set the date to the first Sunday (or Monday)
             * of the specified week of the year.
             */
            if (!HAVE_WDAY(state)) {
                tm->tm_wday = day_offset;
                state |= S_WDAY;
            }
            tm->tm_yday = (7 -
                first_wday_of(tm->tm_year + TM_YEAR_BASE) +
                day_offset) % 7 + (week_offset - 1) * 7 +
                tm->tm_wday  - day_offset;
            state |= S_YDAY;
        }
    }

    if (HAVE_YDAY(state) && HAVE_YEAR(state)) {
        int isleap;

        if (!HAVE_MON(state)) {
            /* calculate month of day of year */
            i = 0;
            isleap = isleap_sum(tm->tm_year, TM_YEAR_BASE);
            while (tm->tm_yday >= start_of_month[isleap][i])
                i++;
            if (i > 12) {
                i = 1;
                tm->tm_yday -= start_of_month[isleap][12];
                tm->tm_year++;
            }
            tm->tm_mon = i - 1;
            state |= S_MON;
        }

        if (!HAVE_MDAY(state)) {
            /* calculate day of month */
            isleap = isleap_sum(tm->tm_year, TM_YEAR_BASE);
            tm->tm_mday = tm->tm_yday -
                start_of_month[isleap][tm->tm_mon] + 1;
            state |= S_MDAY;
        }

        if (!HAVE_WDAY(state)) {
            /* calculate day of week */
            i = 0;
            week_offset = first_wday_of(tm->tm_year);
            while (i++ <= tm->tm_yday) {
                if (week_offset++ >= 6)
                    week_offset = 0;
            }
            tm->tm_wday = week_offset;
            state |= S_WDAY;
        }
    }

    return (char*)bp;
}

static const u_char *
conv_num(const unsigned char *buf, int *dest, u_int llim, u_int ulim)
{
    u_int result = 0;
    unsigned char ch;

    /* The limit also determines the number of valid digits. */
    u_int rulim = ulim;

    ch = *buf;
    if (ch < '0' || ch > '9')
        return NULL;

    do {
        result *= 10;
        result += ch - '0';
        rulim /= 10;
        ch = *++buf;
    } while ((result * 10 <= ulim) && rulim && ch >= '0' && ch <= '9');

    if (result < llim || result > ulim)
        return NULL;

    *dest = result;
    return (char*)buf;
}

static const u_char *
find_string(const u_char *bp, int *tgt, const char * const *n1,
        const char * const *n2, int c)
{
    int i;
    size_t len;

    /* check full name - then abbreviated ones */
    for (; n1 != NULL; n1 = n2, n2 = NULL) {
        for (i = 0; i < c; i++, n1++) {
            len = strlen(*n1);
            if (stricmp(*n1, (const char *)bp) == 0) {
                *tgt = i;
                return bp + len;
            }
        }
    }

    /* Nothing matched */
    return NULL;
}
#endif
