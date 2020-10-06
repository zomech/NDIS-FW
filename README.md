# NDIS-FW

THIS TOOL IS STILL UNDER DEVELOPMENT, USE ONLY FOR RESEARCH PURPOSES.


\
A Simple NDIS Firewall - NDIS filter driver For network and packet filtering.

The Driver can filter and drop incoming and outgoing packets accourding to filtering rules (that can be defined using the IO exe) for a specific policy (incoming\outgoing).


## ndislwf1
The filter driver itself, deployment process (install through Manual deployment):\
https://docs.microsoft.com/en-us/samples/microsoft/windows-driver-samples/ndis-60-filter-driver/


## FWControl
An exe to preform IO operation on the filter driver.\
it can add or delete rules from a policy, and get a list of all the rules.\
Execution options:
```
>FWControl.exe

Options:
        add             Add a rule to a specific fw policy, use with all mandatory prarameters
        remove          Removes a rule to a specific fw policy, use with all mandatory prarameters
        show            Shows a list of all the rules of a specified fw policy


Parameters:
        Mandatory for all options:
        -policy         The Firewall Policy to update\view
                        options: <incoming> <outgoing> <both>(only for showing firewall rules - not updating)

        Mandatory for add and remove options:
        -ip             The ip address, can be used with wildcards characters (?, *)
        -port           The source or destination port of the packet
        -action         What to do with the packet - options are <drop> <allow> <modify>(in development)
```

Execution examples:\
```FWControl.exe add -policy incoming -ip * -port 445 -action drop```\
```FWControl.exe show -policy both```

\
References:

https://docs.microsoft.com/en-us/windows-hardware/drivers/network/roadmap-for-developing-ndis-filter-drivers
