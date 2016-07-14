#########################################################################
#                                                                       #
#                                                                       #
#  Projectname          :       STAPAC                                  #
#                                                                       #
#  Date                 :       November 1991                           #
#                                                                       #
#  Author               :       L. Eckstein                             #
#                                                                       #
#  Filename             :       makefile                                #
#                                                                       #
#  Description          :       this makefile generates the install-    #
#                               program                                 #
#  Important            :                                               #
#  Set Environment Variable STAMOD:                                     #
#  under DOS     : set STAMOD=filename                                  #
#  under C-SHELL : setenv STAMOD filename                               #
#  Length of Filename : max 40 characters.                              #
#########################################################################
OBJS  =         install.o
#INCL   =        ../../include/

#IFLAGS =        -I$(INCL)
CFLAGS =        $(IFLAGS)

CKLINCL =       $(INCL)install.h

install:        $(OBJS)
		cc -o install $(OBJS)

install.o:      $(CKLINCL)




