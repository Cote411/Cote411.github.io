/*
 * login.c — Minimal login verification program
 *
 * Purpose  : Demonstrate basic username-based access control.
 *            Used as a baseline test binary in the TinyCC lab.
 *
 * Usage    : ./login <username>
 *
 * Exit codes:
 *   0  — login accepted  (username is "root")
 *   1  — login rejected  (any other username or missing argument)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* The only username that is granted access in this baseline program. */
#define ALLOWED_USER "root"

int main(int argc, char *argv[])
{
  /* Require exactly one argument: the username. */
  if (argc != 2)
  {
    fprintf(stderr, "Usage: %s <username>\n", argv[0]);
    return 1;
  }

  const char *username = argv[1];

  /*
   * strcmp returns 0 when both strings are identical.
   * Any non-zero return means the username does NOT match.
   */
  if (strcmp(username, ALLOWED_USER) == 0)
  {
    printf("Access granted: welcome, %s.\n", username);
    return 0; /* success */
  }
  else
  {
    printf("Access denied: unknown user '%s'.\n", username);
    return 1; /* failure */
  }
}
