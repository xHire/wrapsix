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

#ifndef RADIXTREE_H
#define RADIXTREE_H

#define CHUNK_SIZE	6
#define ARRAY_SIZE	64	/* 2 ^ CHUNK_SIZE */

typedef struct radixtree {
	void *array[ARRAY_SIZE];
	unsigned int count;
} radixtree_t;

radixtree_t *radixtree_create(void);
void radixtree_destroy(radixtree_t *root, unsigned char depth);
void radixtree_insert(radixtree_t *root,
		      unsigned char *(chunker)(void *data, unsigned char size,
					       unsigned char *count),
		      void *search_data, unsigned char size, void *data);
void radixtree_delete(radixtree_t *root,
		      unsigned char *(chunker)(void *data, unsigned char size,
					       unsigned char *count),
		      void *data, unsigned char size);
void *radixtree_lookup(radixtree_t *root,
		       unsigned char *(chunker)(void *data, unsigned char size,
					       unsigned char *count),
		       void *data, unsigned char size);
unsigned char *radixtree_chunker(void *data, unsigned char size,
				 unsigned char *count);

#endif /* RADIXTREE_H */
