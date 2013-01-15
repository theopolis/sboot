# Copyright 2012 Teddy Reed

include $(TOPDIR)/config.mk

LIB	= $(obj)libsboot.o

SOBJS	=

CFLAGS += -I$(VBOOT_SOURCE)/firmware/include -I$(VBOOT_SOURCE)/firmware/arch/$(ARCH)/include

ifdef CONFIG_SPL_BUILD
COBJS-$(CONFIG_SPL_SBOOT_SUPPORT) += spl_sboot.o
endif

COBJS-$(CONFIG_SBOOT) += sboot.o

COBJS	= $(COBJS-y)
SRCS 	:= $(SOBJS:.o=.S) $(COBJS:.o=.c)
OBJS	:= $(addprefix $(obj),$(SOBJS) $(COBJS))

$(LIB):	$(obj).depend $(OBJS)
	$(call cmd_link_o_target, $(OBJS))

#########################################################################

# defines $(obj).depend target
include $(SRCTREE)/rules.mk

sinclude $(obj).depend

#########################################################################
