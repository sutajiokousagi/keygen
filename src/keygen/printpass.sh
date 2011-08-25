#!/bin/sh


# Remove ourselves.
rm -f /psp/rfs1/userhook2
rm -rf /psp/rfs1
sync

# Notify the worker that the script passed.
while true
do
    /usr/chumby/scripts/printpass.pl
    sleep 1
done   # Loop indefinitely because the pass message can scroll off the screen.
