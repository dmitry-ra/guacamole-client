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
#include <assert.h>
#include <png.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

static void big_endian(unsigned char* output, uint32_t value) {
    output[0] = value >> 24;
    output[1] = value >> 16;
    output[2] = value >> 8;
    output[3] = value;
}

int main(void) {
    png_image image = { .version = PNG_IMAGE_VERSION,
        .width = 2, .height = 2, .format = PNG_FORMAT_RGBA };
    unsigned char pixels[] = {
        255, 0, 0, 255, 0, 255, 0, 255,
        0, 0, 255, 255, 0, 0, 0, 0
    };
    png_alloc_size_t length = 0;
    assert(png_image_write_to_memory(&image, NULL, &length, 0, pixels, 0, NULL));
    unsigned char* png = malloc(length);
    assert(png && png_image_write_to_memory(&image, png, &length, 0, pixels, 0, NULL));
    unsigned char* output;
    size_t size;
    assert(guac_rdp_clipboard_png_to_dib(png, length, 4096, &output, &size));
    assert(size == 56 && output[0] == 40 && output[4] == 2);
    assert(output[8] == 254 && output[9] == 255 && output[14] == 24);
    unsigned char expected[] = { 0, 0, 255, 0, 255, 0, 0, 0,
                               255, 0, 0, 255, 255, 255, 0, 0 };
    assert(!memcmp(output + 40, expected, sizeof(expected)));
    free(output);
    assert(!guac_rdp_clipboard_png_to_dib(png, length, 48, &output, &size));
    assert(!output && !size);
    assert(!guac_rdp_clipboard_png_to_dib(png, length / 2, 4096, &output, &size));
    assert(!guac_rdp_clipboard_png_to_dib("not a PNG", 9, 4096, &output, &size));
    /* A valid large IHDR must be rejected before any pixel decode/allocation. */
    big_endian(png + 16, 8192);
    big_endian(png + 20, 8192);
    big_endian(png + 29, crc32(0, png + 12, 17));
    png_image header = { .version = PNG_IMAGE_VERSION };
    assert(png_image_begin_read_from_memory(&header, png, length));
    assert(header.width == 8192 && header.height == 8192);
    png_image_free(&header);
    assert(!guac_rdp_clipboard_png_to_dib(png, length, 4096, &output, &size));
    assert(!output && !size);
    free(png);
    return 0;
}
