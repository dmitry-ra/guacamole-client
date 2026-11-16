/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
#include "clipboard-image.h"

#include <limits.h>
#include <png.h>
#include <stdint.h>
#include <stdlib.h>

enum {
    DIB_HEADER_BYTES = 40,
    DIB_ALIGNMENT = 4,
    DIB_PIXEL_BYTES = 3,
    PNG_PIXEL_BYTES = 4,
    CHANNEL_MAX = 255
};

static void little_endian(unsigned char* output, uint32_t value, size_t count) {
    for (size_t i = 0; i < count; i++) {
        output[i] = value & 0xff;
        value >>= CHAR_BIT;
    }
}

int guac_rdp_clipboard_png_to_dib(const void* data, size_t length, size_t limit,
        unsigned char** result, size_t* result_length) {
    *result = NULL;
    *result_length = 0;
    png_image image = { .version = PNG_IMAGE_VERSION };
    if (!data || !length || length > limit || limit <= DIB_HEADER_BYTES)
        return 0;
    if (!png_image_begin_read_from_memory(&image, data, length)) {
        png_image_free(&image);
        return 0;
    }

    /* Check dimensions before libpng can allocate a decompressed bitmap. */
    if (!image.width || !image.height || image.width > INT32_MAX
            || image.height > INT32_MAX
            || image.width > limit / PNG_PIXEL_BYTES
            || image.height > limit / ((size_t) image.width * PNG_PIXEL_BYTES)) {
        png_image_free(&image);
        return 0;
    }
    size_t row_bytes = ((size_t) image.width * DIB_PIXEL_BYTES + DIB_ALIGNMENT - 1)
        & ~(size_t) (DIB_ALIGNMENT - 1);
    if (row_bytes > limit - DIB_HEADER_BYTES
            || image.height > (limit - DIB_HEADER_BYTES) / row_bytes) {
        png_image_free(&image);
        return 0;
    }
    size_t pixels = (size_t) image.width * image.height;
    size_t bytes = DIB_HEADER_BYTES + row_bytes * image.height;
    unsigned char* rgba = malloc(pixels * PNG_PIXEL_BYTES);
    unsigned char* dib = calloc(1, bytes);
    if (!rgba || !dib) {
        free(rgba);
        free(dib);
        png_image_free(&image);
        return 0;
    }
    image.format = PNG_FORMAT_RGBA;
    if (!png_image_finish_read(&image, NULL, rgba, 0, NULL)) {
        free(rgba);
        free(dib);
        png_image_free(&image);
        return 0;
    }

    little_endian(dib, DIB_HEADER_BYTES, 4);
    little_endian(dib + 4, image.width, 4);
    little_endian(dib + 8, (uint32_t) -(int32_t) image.height, 4);
    little_endian(dib + 12, 1, 2);
    little_endian(dib + 14, DIB_PIXEL_BYTES * CHAR_BIT, 2);
    little_endian(dib + 20, bytes - DIB_HEADER_BYTES, 4);
    for (size_t y = 0; y < image.height; y++) {
        for (size_t x = 0; x < image.width; x++) {
            const unsigned char* source = rgba + (y * image.width + x) * PNG_PIXEL_BYTES;
            unsigned char* target = dib + DIB_HEADER_BYTES + y * row_bytes + x * DIB_PIXEL_BYTES;
            unsigned int alpha = source[3];
            for (size_t channel = 0; channel < DIB_PIXEL_BYTES; channel++)
                target[channel] = (source[2 - channel] * alpha
                    + CHANNEL_MAX * (CHANNEL_MAX - alpha) + CHANNEL_MAX / 2) / CHANNEL_MAX;
        }
    }
    free(rgba);
    png_image_free(&image);
    *result = dib;
    *result_length = bytes;
    return 1;
}
