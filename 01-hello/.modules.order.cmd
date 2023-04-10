cmd_/home/johnny/rootkit/hello/modules.order := {   echo /home/johnny/rootkit/hello/hello-1.ko; :; } | awk '!x[$$0]++' - > /home/johnny/rootkit/hello/modules.order
