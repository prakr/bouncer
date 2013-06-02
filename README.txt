1. Source files 
   - bouncer.c -> Main file of the project.
   - process_pkt.c -> Implements the functionalities of the bouncer applicatio and it contains the definition of the callback function required by the PCAP library to capture packets.
   - bouncer.h -> contains all the header inclusions and declaration of user defined data type.
   - bouncer.sh -> A script file acting as a wrapper to the executable.
   - build.sh -> wraper to the Makefile to build the application.
   - Makefile -> Make file used to build the application.

2. Compiling and building 
   - run the build.sh script to invole the make file that builds the application. ==> ./build.sh

3. Running the Bouncer:
   - run the bouncer.sh script with appropriate arguments to run the application, the usage of the application is given below:

     ./bouncer.sh <Bouncer IP Address> <Bouncer Port> <Server IP Address> <Server port>

