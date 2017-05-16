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

#include <stdlib.h>	/* free, malloc */
#include <time.h>	/* time, time_t */

#include "linkedlist.h"
#include "log.h"

/**
 * Creates root of a linked list.
 *
 * @return	Root of new linked list
 */
linkedlist_t *linkedlist_create(void)
{
	linkedlist_t *linkedlist;

	if ((linkedlist = (linkedlist_t *) malloc(sizeof(linkedlist_t))) ==
	    NULL) {
		log_error("Lack of free memory");
                return NULL;
        }
        linkedlist->first.prev = NULL;
        linkedlist->first.next = &linkedlist->last;
        linkedlist->last.prev  = &linkedlist->first;
	linkedlist->last.next  = NULL;

        return linkedlist;
}

/**
 * Destroys a linked list.
 *
 * @param	root	Root of the linked list to destroy
 */
void linkedlist_destroy(linkedlist_t *root)
{
	linkedlist_node_t *tmp;

	tmp = root->first.next;
	while (tmp->next != NULL) {
		tmp = tmp->next;
		free(tmp->prev);
	}
}

/**
 * Append new node at the end of the linked list.
 *
 * @param	root	Root of the linked list
 * @param	data	Data to append to the list
 *
 * @return	pointer to created node if succeeded
 * @return	NULL if failed
 */
linkedlist_node_t *linkedlist_append(linkedlist_t *root, void *data)
{
	linkedlist_node_t *node;

	if ((node = (linkedlist_node_t *) malloc(sizeof(linkedlist_node_t))) ==
	    NULL) {
		log_error("Lack of free memory");
                return NULL;
        }

	node->data = data;
	node->time = time(NULL);

	node->prev = root->last.prev;
	node->next = &root->last;
	root->last.prev->next = node;
	root->last.prev = node;

	return node;
}

/**
 * Delete node from beginning of linked list.
 *
 * @param	root	Root of the linked list
 * @param	node	Node to delete from the list
 */
void linkedlist_delete(linkedlist_t *root, linkedlist_node_t *node)
{
	root->first.next = node->next;
	node->next->prev = node->prev;

	free(node);
	node = NULL;
}

/**
 * Move a node to the end of linked list. It's possible to even move it to
 * another linked list.
 *
 * @param	root	Root of the linked list
 * @param	node	Node to move to the end
 */
void linkedlist_move2end(linkedlist_t *root, linkedlist_node_t *node)
{
	/* take the node out */
	node->next->prev = node->prev;
	node->prev->next = node->next;

	/* put it to the end */
	node->prev = root->last.prev;
	node->next = &root->last;
	root->last.prev->next = node;
	root->last.prev = node;

	node->time = time(NULL);
}
