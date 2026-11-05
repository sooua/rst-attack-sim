# Security policy

## Scope

rst-attack-sim only emits UDP syslog to a host and port you choose. It does not
scan, exploit, or connect to any other system. A vulnerability report is in
scope if it concerns the script itself — for example, it sends data somewhere
you did not point it, or it can be made to do something other than emit syslog.

## Reporting a vulnerability

Report privately through GitHub: open the repository's **Security** tab and
click **Report a vulnerability**. Please do not open a public issue for a
security problem.

## Misuse

Reports that someone pointed the tool at a third party are out of scope for the
tool itself. The tool is for authorized lab use only; misuse is the
responsibility of whoever ran it.
