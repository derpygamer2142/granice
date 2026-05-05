# Granice

Weird C web server, almost certainly super insecure so don't use this for anything important. Might become more user friendly eventually.

## Features
 - Dual http+https
 - Response deflation
 - Response caching
 - Loads in Internet Explorer 6

## Requirements
 - zlib
 - Linux based operating system because windows is for nerds. Windows support will come if I get paid to add it, which isn't happening.

```bash
sudo apt install zlib1g-dev openssl
```

## Building

Build normally:
```bash
make
```

Build in test mode with memory sanitization:
```bash
make test
```

## Usage

Where private_dir contains a cert.pem and a key.pem for TLS. Do not put those in the serve directory, if you do then whatever happens is your own fault. May need to be run as a superuser to access port 80.

```bash
genice private_dir/ serve_dir/
```

## The name

I was thinking about what to call this because I didn't want to be cringe and name it after an element on the periodic table or a Greek/Roman god or something (if you do any of those things you're a nerd), but then I thought about rocks and how rocks are super cool and my mind immediately went to granite (the coolest rock of all of the rocks) but granite is a generic name and tons of people probably use that and then I thought to change a letter and Granice seemed the most word-like and when I looked it up on Github there didn't seem to be anything in english that used that name but it seems to mean borders in Polish which is fine but I didn't know that when I named it so don't read too far into it, I would have called this project "Untitled C Web Server" if I could have but that's a dumb name and I can't get away with that more than once. Obligatory punctuation for you to use at your leisure:
../.,..,,.,(),,,;:,,&!!?—"".

## Licenses

This project is licensed under MPL-2.0. See LICENSE for more details.

This project includes code by Paul Hsieh from a blog post, available at https://www.azillionmonkeys.com/qed/hash.html and licensed under LGPL-2.1. See LICENSES/LGPL-2.1.txt for more details.