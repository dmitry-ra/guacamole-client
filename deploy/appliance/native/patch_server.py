#!/usr/bin/env python3
"""Apply the explicit downstream PNG clipboard patch to the locked server tree."""
from pathlib import Path
import shutil
import sys


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise RuntimeError('Locked native clipboard source context changed')
    return text.replace(before, after, 1)


def main():
    root = Path(sys.argv[1])
    here = Path(__file__).resolve().parent
    channels = root/'src/protocols/rdp/channels'
    source = channels/'cliprdr.c'
    text = source.read_text()
    text = replace_once(text, '#include "channels/cliprdr.h"',
                        '#include "channels/cliprdr.h"\n#include "channels/clipboard-image.h"')
    text = replace_once(text, '#include <guacamole/mem.h>',
                        '#include <guacamole/mem.h>\n#include <guacamole/protocol.h>\n#include <guacamole/socket.h>')
    text = replace_once(text, '    guac_client_log(client, GUAC_LOG_TRACE, "CLIPRDR: Sending format list");', '''    CLIPRDR_FORMAT image_formats[] = { { .formatId = CF_DIB } };
    if (!strcmp(clipboard->clipboard->mimetype, "image/png")) {
        format_list.formats = image_formats;
        format_list.numFormats = 1;
    }

    guac_client_log(client, GUAC_LOG_TRACE, "CLIPRDR: Sending format list");''')
    anchor = 'static UINT guac_rdp_cliprdr_format_data_request(CliprdrClientContext* cliprdr,'
    helper = '''static UINT guac_rdp_cliprdr_image_data_request(CliprdrClientContext* cliprdr,
        UINT requested_format) {
    guac_rdp_clipboard* clipboard = cliprdr->custom;
    guac_rdp_client* rdp_client = clipboard->client->data;
    unsigned char* dib = NULL;
    size_t length = 0;
    pthread_mutex_lock(&clipboard->clipboard->lock);
    int converted = requested_format == CF_DIB
        && guac_rdp_clipboard_png_to_dib(clipboard->clipboard->buffer,
                clipboard->clipboard->length, clipboard->clipboard->available,
                &dib, &length);
    pthread_mutex_unlock(&clipboard->clipboard->lock);
    guac_client_log(clipboard->client, GUAC_LOG_DEBUG,
            "PNG clipboard request format=%u input_bytes=%d limit_bytes=%d converted=%d output_bytes=%zu",
            requested_format, clipboard->clipboard->length,
            clipboard->clipboard->available, converted, length);
    CLIPRDR_FORMAT_DATA_RESPONSE response = {
        .requestedFormatData = dib,
#ifdef HAVE_CLIPRDR_HEADER
        .common = {
            .msgType = CB_FORMAT_DATA_RESPONSE,
            .msgFlags = converted ? CB_RESPONSE_OK : CB_RESPONSE_FAIL,
            .dataLen = length,
        }
#else
        .dataLen = length,
        .msgFlags = converted ? CB_RESPONSE_OK : CB_RESPONSE_FAIL
#endif
    };
    if (!converted)
        guac_client_log(clipboard->client, GUAC_LOG_WARNING,
                "PNG clipboard data is invalid, unsupported or exceeds the clipboard limit.");
    pthread_mutex_lock(&rdp_client->message_lock);
    UINT result = cliprdr->ClientFormatDataResponse(cliprdr, &response);
    pthread_mutex_unlock(&rdp_client->message_lock);
    free(dib);
    return result;
}

'''
    text = replace_once(text, anchor, helper + anchor)
    text = replace_once(text, '    guac_iconv_write* remote_writer;', '''    if (!strcmp(clipboard->clipboard->mimetype, "image/png"))
        return guac_rdp_cliprdr_image_data_request(cliprdr,
                format_data_request->requestedFormatId);

    guac_iconv_write* remote_writer;''')
    text = replace_once(text, '    guac_common_clipboard_append(clipboard->clipboard, "", 1);', '''    if (strcmp(clipboard->clipboard->mimetype, "image/png"))
        guac_common_clipboard_append(clipboard->clipboard, "", 1);''')
    text = replace_once(text, '    /* Append received data to current clipboard contents */', '''    /* PNG BlobWriter requires bounded per-chunk flow-control acknowledgements. */
    if (!strcmp(clipboard->clipboard->mimetype, "image/png")) {
        pthread_mutex_lock(&clipboard->clipboard->lock);
        int remaining = clipboard->clipboard->available - clipboard->clipboard->length;
        int accepted = length >= 0 && length <= remaining;
        if (accepted) {
            memcpy(clipboard->clipboard->buffer + clipboard->clipboard->length, data, length);
            clipboard->clipboard->length += length;
        }
        pthread_mutex_unlock(&clipboard->clipboard->lock);
        guac_protocol_send_ack(user->socket, stream,
                accepted ? "PNG clipboard chunk accepted" : "PNG clipboard limit exceeded",
                accepted ? GUAC_PROTOCOL_STATUS_SUCCESS : GUAC_PROTOCOL_STATUS_CLIENT_OVERRUN);
        guac_socket_flush(user->socket);
        return 0;
    }

    /* Append received data to current clipboard contents */''')
    source.write_text(text)
    make = root/'src/protocols/rdp/Makefile.am'
    text = make.read_text()
    continuation = ' ' + chr(92) + '\n'
    text = replace_once(text, '    channels/cliprdr.c',
                        '    channels/clipboard-image.c' + continuation + '    channels/cliprdr.c')
    text = replace_once(text, '    channels/cliprdr.h',
                        '    channels/clipboard-image.h' + continuation + '    channels/cliprdr.h')
    text = replace_once(text, '    @CAIRO_LIBS@',
                        '    @PNG_LIBS@' + continuation + '    @CAIRO_LIBS@')
    make.write_text(text)
    for name in ('clipboard-image.c', 'clipboard-image.h'):
        shutil.copyfile(here/name, channels/name)


if __name__ == '__main__':
    main()
