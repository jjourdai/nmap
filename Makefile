# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: polooo <polooo@student.42.fr>              +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2017/01/17 13:28:01 by jjourdai          #+#    #+#              #
#    Updated: 2019/04/21 18:54:06 by polooo           ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

SRC_PATH = ./src/

INC_PATH =	./include/

SRC_NAME =	main.c \
			param.c \
			init.c \
			err.c \
			result.c \
			send.c \
			receive.c \
			threads.c \
			socket.c

INC_NAME =	nmap.h \
			colors.h

OBJ_PATH = ./.obj/

CPPFLAGS = -Iinclude -I ./libft/include

LDFLAGS = -Llibft

LDLIBS = -lft

NAME = ft_nmap
	
CC = gcc

#CFLAGS = -Wall -Wextra -fsanitize=address -g -fno-omit-frame-pointer -lpcap -lpthread
CFLAGS = -Wall -Wextra -lpcap -lpthread -g -Werror

OBJ_NAME = $(SRC_NAME:.c=.o)

SRC = $(addprefix $(SRC_PATH), $(SRC_NAME))

OBJ = $(addprefix $(OBJ_PATH), $(OBJ_NAME))

INC = $(addprefix $(INC_PATH), $(INC_NAME))

JOBS =	4

.PHONY: all, clean, fclean, re

all:
	make $(NAME) -j$(JOBS)

$(NAME): $(OBJ)
	make -C ./libft/ -j$(JOBS)
	$(CC) $^ -o $(NAME) $(CFLAGS) $(LDFLAGS) $(LDLIBS)
	sudo chown root:root $(NAME)
	sudo chmod 4755 $(NAME)

$(OBJ_PATH):
	mkdir -p $@

$(OBJ_PATH)%.o: $(SRC_PATH)%.c $(INC) Makefile | $(OBJ_PATH)
	$(CC) -o $@ $(CFLAGS) $(CPPFLAGS) -c $<

clean:
	rm -fv $(OBJ)
	make clean -C ./libft/
	@rmdir $(OBJ_PATH) 2> /dev/null || true

fclean: clean
	make fclean -C ./libft/
	rm -fv $(NAME)

re: fclean all
