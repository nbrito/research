/*
 * This program is copyright Alec Muffett 1991 except for some portions of
 * code in "crack-fcrypt.c" which are copyright Robert Baldwin, Icarus
 * Sparry and Alec Muffett.  The author(s) disclaims all responsibility or
 * liability with respect to it's usage or its effect upon hardware or
 * computer systems, and maintain copyright as set out in the "LICENCE"
 * document which accompanies distributions of Crack v4.0 and upwards. 
 */

#include "crack.h"

#define RULE_NOOP	':'
#define RULE_PREPEND	'^'
#define RULE_APPEND	'$'
#define RULE_REVERSE	'r'
#define RULE_UPPERCASE	'u'
#define RULE_LOWERCASE	'l'
#define RULE_PLURALISE	'p'
#define RULE_CAPITALISE	'c'
#define RULE_DUPLICATE	'd'
#define RULE_REFLECT	'f'
#define RULE_SUBSTITUTE	's'
#define RULE_MATCH	'/'
#define RULE_NOT	'!'
#define RULE_LT		'<'
#define RULE_GT		'>'
#define RULE_EXTRACT	'x'

void
Trim (string)			/* remove trailing whitespace from a string */
    register char *string;
{
    register char *ptr;

    for (ptr = string; *ptr; ptr++);
    while ((--ptr >= string) && isspace (*ptr));
    *(++ptr) = '\0';
}

char *
Clone (string, maxsize)
    char *string;
    int maxsize;
{
    register int len;
    register char *retval;

    len = strlen (string);
    if (maxsize && len > maxsize)
    {
	len = maxsize;
    }
    retval = (char *) malloc (len + 1);
    strncpy (retval, string, len);
    retval[len] = '\0';
    return (retval);
}

int
Suffix (word, suffix)
    char *word;
    char *suffix;
{
    register int i;
    register int j;

    i = strlen (word);
    j = strlen (suffix);

    if (i > j)
    {
	return (STRCMP ((word + i - j), suffix));
    } else
    {
	return (-1);
    }
}

char *
Reverse (str)			/* return a pointer to a reversal */
    register char *str;
{
    register int i;
    register int j;
    register char *ptr;
    static char area[STRINGSIZE];

    j = i = strlen (str);
    while (*str)
    {
	area[--i] = *str++;
    }
    area[j] = '\0';
    return (area);
}

char *
Uppercase (str)			/* return a pointer to an uppercase */
    register char *str;
{
    register char *ptr;
    static char area[STRINGSIZE];

    ptr = area;
    while (*str)
    {
	*(ptr++) = islower (*str) ? toupper (*str) : *str;
	str++;
    }
    *ptr = '\0';

    return (area);
}

char *
Lowercase (str)			/* return a pointer to an lowercase */
    register char *str;
{
    register char *ptr;
    static char area[STRINGSIZE];

    ptr = area;
    while (*str)
    {
	*(ptr++) = isupper (*str) ? tolower (*str) : *str;
	str++;
    }
    *ptr = '\0';

    return (area);
}

char *
Capitalise (str)		/* return a pointer to an capitalised */
    register char *str;
{
    register char *ptr;
    static char area[STRINGSIZE];

    ptr = area;

    while (*str)
    {
	*(ptr++) = isupper (*str) ? tolower (*str) : *str;
	str++;
    }

    *ptr = '\0';

    if (islower (area[0]))
    {
	area[0] = toupper (area[0]);
    }
    return (area);
}

char *
Pluralise (string)		/* returns a pointer to a plural */
    register char *string;
{
    register int length;
    static char area[STRINGSIZE];

    length = strlen (string);
    strcpy (area, string);

    if (!Suffix (string, "ch") ||
	!Suffix (string, "ex") ||
	!Suffix (string, "ix") ||
	!Suffix (string, "sh") ||
	!Suffix (string, "ss"))
    {
	/* bench -> benches */
	strcat (area, "es");
    } else if (length > 2 && string[length - 1] == 'y')
    {
	if (strchr ("aeiou", string[length - 2]))
	{
	    /* alloy -> alloys */
	    strcat (area, "s");
	} else
	{
	    /* gully -> gullies */
	    strcpy (area + length - 1, "ies");
	}
    } else if (string[length - 1] == 's')
    {
	/* bias -> biases */
	strcat (area, "es");
    } else
    {
	/* catchall */
	strcat (area, "s");
    }

    return (area);
}

char *
Substitute (string, old, new)	/* returns pointer to a swapped about copy */
    register char *string;
    register char old;
    register char new;
{
    register char *ptr;
    static char area[STRINGSIZE];

    ptr = area;
    while (*string)
    {
	*(ptr++) = *string == old ? new : *string;
	string++;
    }
    *ptr = '\0';
    return (area);
}

int
Char2Int (character)
    char character;
{
    if (character >= '0' && character <= '9')
    {
	return (character - '0');
    }
    if (character >= 'a' && character <= 'z')
    {
	return (character - 'a' + 10);
    }
    if (character >= 'A' && character <= 'Z')
    {
	return (character - 'A' + 10);
    }
    return (-1);
}

char *
Mangle (input, control)		/* returns a pointer to a controlled Mangle */
    char *input;
    char *control;
{
    int limit;
    register char *ptr;
    static char area[STRINGSIZE];
    char area2[STRINGSIZE];

    area[0] = '\0';
    strcpy (area, input);

    for (ptr = control; *ptr; ptr++)
    {
	switch (*ptr)
	{
	case RULE_NOOP:
	    break;
	case RULE_REVERSE:
	    strcpy (area, Reverse (area));
	    break;
	case RULE_UPPERCASE:
	    strcpy (area, Uppercase (area));
	    break;
	case RULE_LOWERCASE:
	    strcpy (area, Lowercase (area));
	    break;
	case RULE_CAPITALISE:
	    strcpy (area, Capitalise (area));
	    break;
	case RULE_PLURALISE:
	    strcpy (area, Pluralise (area));
	    break;
	case RULE_REFLECT:
	    strcat (area, Reverse (area));
	    break;
	case RULE_DUPLICATE:
	    strcpy (area2, area);
	    strcat (area, area2);
	    break;
	case RULE_GT:
	    if (!ptr[1])
	    {
		Log ("Mangle: '>' missing argument in '%s'\n",
		     control);
	    } else
	    {
		limit = Char2Int (*(++ptr));
		if (limit < 0)
		{
		    Log ("Mangle: '>' weird argument in '%s'\n",
			 control);
		    return ((char *) 0);
		}
		if (strlen (area) <= limit)
		{
		    return ((char *) 0);
		}
	    }
	    break;
	case RULE_LT:
	    if (!ptr[1])
	    {
		Log ("Mangle: '<' missing argument in '%s'\n",
		     control);
	    } else
	    {
		limit = Char2Int (*(++ptr));
		if (limit < 0)
		{
		    Log ("Mangle: '<' weird argument in '%s'\n",
			 control);
		    return ((char *) 0);
		}
		if (strlen (area) >= limit)
		{
		    return ((char *) 0);
		}
	    }
	    break;
	case RULE_PREPEND:
	    if (!ptr[1])
	    {
		Log ("Mangle: prepend missing argument in '%s'\n",
		     control);
	    } else
	    {
		area2[0] = *(++ptr);
		strcpy (area2 + 1, area);
		strcpy (area, area2);
	    }
	    break;
	case RULE_APPEND:
	    if (!ptr[1])
	    {
		Log ("Mangle: append missing argument in '%s'\n",
		     control);
	    } else
	    {
		register char *string;

		string = area;
		while (*(string++));
		string[-1] = *(++ptr);
		*string = '\0';
	    }
	    break;
	case RULE_SUBSTITUTE:
	    if (!ptr[1] || !ptr[2])
	    {
		Log ("Mangle: substitute missing argument in '%s'\n",
		     control);
	    } else
	    {
		strcpy (area, Substitute (area, ptr[1], ptr[2]));
		ptr += 2;
	    }
	    break;
	case RULE_EXTRACT:
	    if (!ptr[1] || !ptr[2])
	    {
		Log ("Mangle: extract missing argument in '%s'\n",
		     control);
	    } else
	    {
		int i;
		int start;
		int length;

		start = Char2Int (*(++ptr));
		length = Char2Int (*(++ptr));
		if (start < 0 || length < 0)
		{
		    Log ("Mangle: extract: weird argument in '%s'\n",
			 control);
		    return ((char *) 0);
		}
		strcpy (area2, area);
		for (i = 0; length-- && area2[start + i]; i++)
		{
		    area[i] = area2[start + i];
		}
		/* cant use strncpy() - no trailing NUL */
		area[i] = '\0';
	    }
	    break;
	case RULE_MATCH:
	    if (!ptr[1])
	    {
		Log ("Mangle: '/' missing argument in '%s'\n",
		     control);
	    } else
	    {
		register char *string;
		register char c;

		c = *(++ptr);
		for (string = area; *string; string++)
		{
		    if (*string == c)
		    {
			break;
		    }
		}
		if (!*string)
		{
		    return ((char *) 0);
		}
	    }
	    break;
	case RULE_NOT:
	    if (!ptr[1])
	    {
		Log ("Mangle: '!' missing argument in '%s'\n",
		     control);
	    } else
	    {
		register char *string;
		register char c;

		c = *(++ptr);
		for (string = area; *string; string++)
		{
		    if (*string == c)
		    {
			return ((char *) 0);
		    }
		}
	    }
	    break;
	default:
	    Log ("Mangle: unknown command %c in %s\n",
		 *ptr,
		 control);
	    break;
	}
    }
    return (area);
}
