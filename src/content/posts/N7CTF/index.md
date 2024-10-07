---
title: N7CTF challenges
published: 2024-10-07
description: Solving N7CTF challenges
image: "./n7ctf.png"
tags: [N7CTF, CTF]
category: CTF
draft: false
---



first of all, i want to say thank you to the organizers and everyone who had a hand in organizing this event. thanks to the ctf developers for their effort, the challenges were fun to play.  
so, let's start with the network challenges.

## Network
### PORT FLOW

**link**: 

**problem**: 

the challenge was easy, just run the game and match the protocols with their ports.

| Protocol | Port Number |
|----------|-------------|
| FTP      | 21          |
| SSH      | 22          |
| TFTP     | 69          |
| HTTP     | 80          |
| NetBus   | 12345       |
| SMTP     | 25          |
| IMAP     | 993         |
| HTTPS    | 443         |
| MySQL    | 3306        |
| LDAP     | 389         |
| ncat     | 31337       |
| NTP      | 123         |

### PACKET LAB

**link**: 

**problem**: 

for this challenge, you first need to enable port Fa0 on the pc.  
change the ip for all servers to dhcp (except, of course, the dhcp server).  
in the dns server, go to the **Services** tab and select **DNS**.  


so, 192.168.1.3 is the ip of **CTF_SERVER**, but it doesn't give us anything.  
let's test 192.168.1.8; there is no server with this ip, but there is a strange server named **Server_MESG**. you can change the ip address to 192.168.1.8 and connect via the browser to this link—you will get that.  

or skip all that, go to **Server_MESG Services**, **HTTP**, and click **edit the image.html**. XD

## Binary
### BOMB GAME
**link**: 

**problem**: 

it's just a binary to hex problem.

### Key to the Vault
**link**: 

**problem**: 

use dogbolt.org and upload the vulnerable file, then look for this code `3N5ET_5UPR3MACY`.  
it's the secret key you should use to get the flag.

### PWN the Vault
**link**: 

**problem**: 

the challenge should not include canary but i think there is a problem

### EMAIL
**link**: 

**problem**:  
![img]

### IMAGE STEGANO

using chatgpt, it gave this code to extract it:

```python
from PIL import Image

def extract_lsb(image_path):
    # Open the image file
    img = Image.open(image_path)
    binary_data = ""
    
    # Get image size
    width, height = img.size
    
    # Loop through each pixel
    for y in range(height):
        for x in range(width):
            # Get the pixel value (RGB tuple)
            pixel = img.getpixel((x, y))
            
            # Extract the least significant bit from each RGB channel
            for color in pixel[:3]:  # Assuming RGB image, ignore alpha if exists
                binary_data += bin(color)[-1]  # Append the LSB of the color value
    
    # Split the binary string into chunks of 8 bits (1 byte)
    binary_chars = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    
    # Convert binary strings to characters
    message = ""
    for byte in binary_chars:
        char = chr(int(byte, 2))
        # Stop if we reach a null character (assuming message ends with a null)
        if char == "\x00":
            break
        message += char
    
    return message

# Use the function to extract the hidden message
image_path = "path_to_your_image.png"
hidden_message = extract_lsb(image_path)
print("Extracted message:", hidden_message)
```

### AUDIO STEGANO
**link**: 

**problem**: 

same as before:

```python
import wave

def extract_lsb_from_audio(audio_path):
    # Open the audio file
    audio = wave.open(audio_path, mode='rb')
    
    # Read frames and convert to byte array
    frame_bytes = bytearray(list(audio.readframes(audio.getnframes())))
    
    # Extract the LSB from each byte
    extracted_bits = ''.join([str(frame_bytes[i] & 1) for i in range(len(frame_bytes))])
    
    # Split the binary string into chunks of 8 bits (1 byte)
    binary_chars = [extracted_bits[i:i+8] for i in range(0, len(extracted_bits), 8)]
    
    # Convert binary strings to characters
    message = ""
    for byte in binary_chars:
        char = chr(int(byte, 2))
        # Stop if we reach a null character (assuming message ends with a null)
        if char == "\x00":
            break
        message += char
    
    # Close the audio file
    audio.close()
    
    return message

# Use the function to extract the hidden message
audio_path = "path_to_your_audio.wav"
hidden_message = extract_lsb_from_audio(audio_path)
print("Extracted message:", hidden_message)
```


## Forensics
### Fake TP

**link**: 

**problem**: 

open the file with wireshark in the line 20 i've seen (text/x-sh) it may be interested to look at it
click follow TCP stream you should see some functions just remove the bash in every function so it will not be executed and it should give u the flag

## Cryptography
### Duplicate Deception

**link**: 

**problem**: 

i found this in reddit https://www.reddit.com/r/DataHoarder/comments/gokrmx/these_different_2_images_has_the_same_md5_hash/ just upload the two files and u will get the flag


## Web
### Charikat Dajaj

**link**: 

**problem**: 

capture the first request with burpsuite change the user-agent to charikat dajaj it will redirect you to login page tab anything send and capture the request, change the user-agent to charikat dajaj again,
copie the request and make file .txt with it
in sqlmap run 

```bash
python3 sqlmap.py -r req.txt --dbms=MySQL --tables -T users
```

it should give u all the tables we can see the table users in database dbtry1
now run

```bash
sqlmap -r req.txt --dbms=MySQL -D dbtry1 -T users --dump
```
you will get the flag

## Misc
### Escape 3okacha

Blacklisted[27] i think
