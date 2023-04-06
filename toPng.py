#!/bin/env python
# -*- coding: utf-8 -*-

import cv2
import numpy as np
import sys
import os
import hashlib



filename = sys.argv[1]

if os.path.exists(filename) and os.path.isfile(filename):
    with open(filename, "rb") as f:
        file_size = os.path.getsize(filename)
        if (file_size - 8)  % 256 != 0:
            raise ValueError(f'File size not a multiple of 256, actual size {file_size}')
        
        if (file_size - 8) > 256 * 256 * 3:
            raise ValueError(f'File size too large, actual size {file_size}, max: {256 * 256 * 3}')

        plaintext_size = int.from_bytes(f.read(8), byteorder='little')
        print(f"origin size: {plaintext_size}")

        img = np.zeros((256, 256, 3), np.uint8)

        img[:256, :256] = (255, 255, 255)

        chunk_size = 256
        idx = 0
        channel = 0

        alldata = bytearray()

        while True:
            chunk_data = f.read(chunk_size)
            if not chunk_data:
                break

            alldata.extend(chunk_data)

            
            for i in range(0, 256):
                img[idx, i, channel] = chunk_data[i]
            
            idx += 1
            if idx == 256:
                idx = 0
                channel += 1

        md5checksum = hashlib.md5(alldata).hexdigest()
        cv2.imwrite(f"img_{md5checksum}_{plaintext_size}.png", img)
else:
    raise ValueError('File not found')
            
        