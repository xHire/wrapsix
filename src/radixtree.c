/*
 *  WrapSix
 *  Copyright (C) 2008-2013  xHire <xhire@wrapsix.org>
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

#include <stdlib.h>		/* free, malloc */
#include <string.h>		/* memcpy */

#include "log.h"
#include "radixtree.h"

/**
 * Creates root of radix tree.
 *
 * @return	Root of new radix tree
 */
radixtree_t *radixtree_create(void)
{
	radixtree_t *radixtree;

	if ((radixtree = (radixtree_t *) malloc(sizeof(radixtree_t))) == NULL) {
		log_error("Lack of free memory");
		return NULL;
	}
	memset(radixtree, 0, sizeof(radixtree_t));
	radixtree->count = 0;

	return radixtree;
}

/**
 * Destroys a radix tree.
 *
 * @param	root	Root of the tree to destroy
 * @param	depth	Depth of the tree
 */
void radixtree_destroy(radixtree_t *root, unsigned char depth)
{
	unsigned char i;

	for (i = 0; i < ARRAY_SIZE; i++) {
		if (depth != 1 && root->array[i] != NULL) {
			radixtree_destroy(root->array[i], depth - 1);
		} else if (depth == 1) {
			free(root->array[i]);
		}
	}

	free(root);
}

/**
 * Inserts new data entry into the tree.
 *
 * @param	root		Root of the radix tree
 * @param	chunker		Function to use to get chunks for indexing
 * 				internal array
 * @param	search_data	Key used to search in the tree
 * @param	size		Length of the key
 * @param	data		Data to store in the tree
 */
void radixtree_insert(radixtree_t *root,
		      unsigned char *(chunker)(void *data, unsigned char size,
					       unsigned char *count),
		      void *search_data, unsigned char size, void *data)
{
	radixtree_t *tmp;
	unsigned char i, chunk_count;
	unsigned char *chunks;

	chunks = chunker(search_data, size, &chunk_count);

	tmp = root;

	for (i = 0; i < chunk_count; i++) {
		unsigned char id;

		id = chunks[i];

		if (i == chunk_count - 1) {
			tmp->array[id] = data;
			tmp->count++;
			free(chunks);
			return;
		}

		if (tmp->array[id] == NULL) {
			tmp->array[id] = radixtree_create();
			tmp->count++;
		}

		tmp = tmp->array[id];
	}

	free(chunks);
}

/**
 * Deletes an entry from the tree.
 *
 * @param	root		Root of the radix tree
 * @param	chunker		Function to use to get chunks for indexing
 * 				internal array
 * @param	data		Key used to search in the tree
 * @param	size		Length of the key
 */
void radixtree_delete(radixtree_t *root,
		      unsigned char *(chunker)(void *data, unsigned char size,
					       unsigned char *count),
		      void *data, unsigned char size)
{
	radixtree_t *tmp,
		    *next;
	unsigned char i, chunk_count;
	unsigned char *chunks;
	unsigned int flags = 0;

	chunks = chunker(data, size, &chunk_count);

	for (i = 0, tmp = root; i < chunk_count && tmp != NULL;
	     tmp = tmp->array[chunks[i++]]) {
		flags = tmp->count == 1 ? flags | (0x1 << i) : 0;

		if (i + 1 == chunk_count) {
			break;
		}
	}

	/* if was at leaf, decrement counter */
	if (i + 1 == chunk_count) {
		tmp->count--;
	}

	tmp = root;
	flags &= 0xfffffffe;	/* unflag root */

	for (i = 0; i < chunk_count; i++) {
		next = tmp->array[chunks[i]];
		if (flags & (0x1 << (i + 1))) {
			tmp->array[chunks[i]] = NULL;
			tmp->count--;
		}
		if (flags & (0x1 << i)) {
			free(tmp);
		}
		tmp = next;
	}

	free(chunks);
}

/**
 * Lookups an entry in the tree.
 *
 * @param	root		Root of the radix tree
 * @param	chunker		Function to use to get chunks for indexing
 * 				internal array
 * @param	data		Key used to search in the tree
 * @param	size		Length of the key
 */
void *radixtree_lookup(radixtree_t *root,
		       unsigned char *(chunker)(void *data, unsigned char size,
					       unsigned char *count),
		       void *data, unsigned char size)
{
	radixtree_t *tmp;
	unsigned char i, chunk_count, id;
	unsigned char *chunks;

	chunks = chunker(data, size, &chunk_count);

	tmp = root;

	for (i = 0;; i++) {
		id = chunks[i];

		/* leave the for cycle before tmp gets overwritten,
		 * if the final result was found */
		if (i == chunk_count - 1) {
			free(chunks);
			return tmp->array[id];
		}

		/* leave if there is no result */
		if (tmp->array[id] == NULL) {
			free(chunks);
			return NULL;
		}

		/* go deeper */
		tmp = tmp->array[id];
	}

	/* we never get here ;c) */
}

/**
 * Universal chunker.
 *
 * @param	data	Data to chunk
 * @param	size	Size of the data; must be divisible by 3
 * @param	count	Variable into which is put information about number of
 * 			chunks produced
 *
 * @return	Array of chunks
 */
unsigned char *radixtree_chunker(void *data, unsigned char size,
				 unsigned char *count)
{
	short i;
	unsigned char counter;
	unsigned char *chunks;
	unsigned char *cdata = (unsigned char *) data;

	counter = size * 8 / 6;
	memcpy(count, &counter, sizeof(unsigned char));

	if ((chunks = (unsigned char *) malloc(counter * sizeof(unsigned char)))
	    == NULL) {
		log_error("Lack of free memory");
		return NULL;
	}

	/*
	 *   3 == 0000 0011 == 0x03
	 *  15 == 0000 1111 == 0x0f
	 *  48 == 0011 0000 == 0x30
	 *  60 == 0011 1100 == 0x3c
	 *  63 == 0011 1111 == 0x3f
	 * 192 == 1100 0000 == 0xc0
	 * 240 == 1111 0000 == 0xf0
	 * 252 == 1111 1100 == 0xfc
	 */
	/* processes 3 bytes at a time */
	for (i = 0, counter = 0; counter < *count; i++) {
		chunks[counter++] = cdata[i] & 0x3f;
		chunks[counter++] = ((cdata[i] & 0xc0) >> 6) |
				    ((cdata[i + 1] & 0x0f) << 2);
		i++;
		chunks[counter++] = ((cdata[i] & 0xf0) >> 4) |
				    ((cdata[i + 1] & 0x03) << 4);
		i++;
		chunks[counter++] = ((cdata[i] & 0xfc) >> 2);
	}

	return chunks;
}
