/*
 *  WrapSix
 *  Copyright (C) 2008-2012  xHire <xhire@wrapsix.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LINKEDLIST_H
#define LINKEDLIST_H

#include <time.h>	/* time_t */

/* Linked list node structure */
typedef struct s_linkedlist_node {
	struct s_linkedlist_node	*prev;
	struct s_linkedlist_node	*next;
	void				*data;
	time_t				 time;
} linkedlist_node_t;

/* Linked list root structure */
typedef struct s_linkedlist {
	linkedlist_node_t	first;
	linkedlist_node_t	last;
} linkedlist_t;

linkedlist_t *linkedlist_create(void);
void linkedlist_destroy(linkedlist_t *root);
linkedlist_node_t *linkedlist_append(linkedlist_t *root, void *data);
void linkedlist_delete(linkedlist_t *root, linkedlist_node_t *node);
void linkedlist_move2end(linkedlist_t *root, linkedlist_node_t *node);

#endif /* LINKEDLIST_H */
