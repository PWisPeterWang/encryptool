#!/bin/env python
# -*- coding: utf-8 -*-

import cv2
import sys
import os
import hashlib

filename = sys.argv[1]

if os.path.exists(filename) and os.path.isfile(filename):

    imginfo = filename.split('.')[0].split('_')
    md5sum = imginfo[1]
    print(f"md5sum {md5sum}")
    plaintext_size = imginfo[2]

    img = cv2.imread(filename, cv2.IMREAD_COLOR)

    height, width, channels = img.shape

    if height > 256 or width > 256 or channels > 3:
        raise ValueError(f'Image size too large, actual size {height}x{width}x{channels}, max: 256x256x3')
    
    print(f"image size: {height}x{width}x{channels}")
    
    chunk_size = 256
    idx = 0
    channel = 0

    alldata = bytearray()

    while True:
        chunk_data = img[idx, :, channel]

        sum = 0
        for i in range(0, len(chunk_data), 1):
            sum += int(chunk_data[i])
        if sum == 255 * 256:
            break
        
        alldata.extend(chunk_data.tobytes())

        idx += 1
        if idx == 256:
            idx = 0
            channel += 1
    
    md5check = hashlib.md5(alldata).hexdigest()
    if md5sum == md5check:
        print("md5sum match")
    else:
        raise ValueError(f"md5sum mismatch, expect: {md5sum}, actual: {md5check}")
    
    byte_value = int(plaintext_size).to_bytes(8, byteorder='little')
    with open("secret.enc", "wb") as f:
        f.write(byte_value)
        f.write(alldata)

else:
    raise ValueError('File not found')
            
        
