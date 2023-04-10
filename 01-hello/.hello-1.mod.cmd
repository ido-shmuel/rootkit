cmd_/home/johnny/rootkit/hello/hello-1.mod := printf '%s\n'   hello-1.o | awk '!x[$$0]++ { print("/home/johnny/rootkit/hello/"$$0) }' > /home/johnny/rootkit/hello/hello-1.mod
