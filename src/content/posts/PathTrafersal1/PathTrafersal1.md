---
title: Lab File path traversal simple case
published: 2024-10-01
description: Solving lab File path traversal
image: "../img/portswigger.png"
tags: [PortSwigger, "Path traversal", Lab]
category: PortSwigger
draft: false
---
![Cover Image](../img/portswigger.png)

# File path traversal, simple case


## Problem

This lab contains a path traversal vulnerability in the display of product images.
To solve the lab, retrieve the contents of the /etc/passwd file.


## Solution

look for any image, inspect it you should src like /imgae?filename=10.jpg thats mean the image is in /var/www/img/10.jpg we need just change 10.jpg with ../../../etc/passwd

![Screenshot1](https://github.com/user-attachments/assets/cc68f06b-1d6a-4b1f-b7b1-5a95c7270f24)

