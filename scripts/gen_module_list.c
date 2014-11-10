#include <stdio.h>
#include <string.h>

const char *header = 
  "#if !defined (_MODULES_H_)\n"
  "#define _MODULES_H_\n"
  "\n"
  "const char *modules_list_name[] = {\n";

const char *footer =
  "};\n"
  "const int modules_list_num = %d;\n"
  "#endif /* _MODULES_H_ */\n";

int
main (int argc, char **argv)
{
  int i, c = 0;
  char *result = NULL;
  char buf[256];

  memset (buf, 0, sizeof (buf));

  fprintf (stdout, "%s", header);

  while (!feof (stdin))
    {
      result = fgets (buf, sizeof (buf), stdin);

      for (i = 0; i < strlen (buf); i++)
        if (buf[i] == '\n')
          buf[i] = '\0';

      if (!result || ferror (stdin))
        break;

      fprintf (stdout, "  \"%s\",\n", buf);

      c++;
    }

  fprintf (stdout, footer, c);

  return 0;
}     
