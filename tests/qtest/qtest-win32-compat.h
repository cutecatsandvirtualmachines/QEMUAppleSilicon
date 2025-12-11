/*
 * Windows compatibility helpers for QEMU tests
 *
 * Copyright (c) 2025
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef QTEST_WIN32_COMPAT_H
#define QTEST_WIN32_COMPAT_H

#ifdef _WIN32
#include <stdio.h>

/*
 * Windows-compatible ftruncate implementation for tests
 * This avoids the need to link against block/file-win32.c
 */
static inline int qtest_ftruncate(int fd, off_t length)
{
    FILE *fp;
    int ret = -1;
    long pos;

    /* Get the file path from fd - we'll reopen it */
    fp = _fdopen(dup(fd), "r+b");
    if (!fp) {
        return -1;
    }

    /* Seek to length-1 and write a byte to set file size */
    if (length > 0) {
        if (fseek(fp, (long)length - 1, SEEK_SET) == 0) {
            if (fputc(0, fp) != EOF) {
                ret = 0;
            }
        }
    } else if (length == 0) {
        /* Truncate to zero by reopening in write mode */
        fclose(fp);
        fp = _fdopen(dup(fd), "wb");
        if (fp) {
            ret = 0;
        }
    }

    if (fp) {
        fclose(fp);
    }
    return ret;
}

#undef ftruncate
#define ftruncate qtest_ftruncate

#endif /* _WIN32 */

#endif /* QTEST_WIN32_COMPAT_H */
